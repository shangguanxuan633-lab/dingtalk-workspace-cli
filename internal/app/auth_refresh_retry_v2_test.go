package app

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/audit"
	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/executor"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/transport"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/authretry"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

type rejectedTokenRefresherFunc func(context.Context, string, ...uint64) (string, error)

func (f rejectedTokenRefresherFunc) ForceRefreshRejectedToken(ctx context.Context, token string, generation ...uint64) (string, error) {
	return f(ctx, token, generation...)
}

func installAuthRetryUnitSeams(t *testing.T) (*int, *int) {
	t.Helper()
	previousHooks := edition.Get()
	previousRefresh := forceRefreshRejectedTokenFunc
	previousProfileRefresh := forceRefreshRejectedTokenForProfileFunc
	hookCalls, refreshCalls := new(int), new(int)
	edition.Override(&edition.Hooks{OnAuthError: func(string, error) error {
		(*hookCalls)++
		return &authretry.AuthRefreshRequired{Cause: apperrors.NewAuth("overlay rejected token", apperrors.WithReason("overlay_token_rejected"))}
	}})
	forceRefreshRejectedTokenFunc = func(context.Context, string, string, ...uint64) (string, error) {
		(*refreshCalls)++
		return "", context.DeadlineExceeded
	}
	forceRefreshRejectedTokenForProfileFunc = func(context.Context, string, string, string, ...uint64) (string, error) {
		(*refreshCalls)++
		return "", context.DeadlineExceeded
	}
	t.Cleanup(func() {
		edition.Override(previousHooks)
		forceRefreshRejectedTokenFunc = previousRefresh
		forceRefreshRejectedTokenForProfileFunc = previousProfileRefresh
	})
	return hookCalls, refreshCalls
}

func retryUnitInvocation() executor.Invocation {
	return executor.Invocation{CanonicalProduct: "test", Tool: "call"}
}

func managedRetryUnitSnapshot(access string, generation uint64) AccessTokenSnapshot {
	return AccessTokenSnapshot{
		AccessToken:   access,
		Generation:    generation,
		Source:        "oauth",
		profile:       "corp-a:user-a",
		profilePinned: true,
	}
}

func TestRecoverAuthErrorDoesNotRefreshTimeoutOrHTTP500(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "timeout", err: context.DeadlineExceeded},
		{name: "http 500", err: &transport.CallError{Stage: transport.CallStageHTTP, HTTPStatus: http.StatusInternalServerError}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hookCalls, refreshCalls := installAuthRetryUnitSeams(t)
			attempted, _, err := (&runtimeRunner{}).recoverAuthError(
				context.Background(), "https://unused.invalid", retryUnitInvocation(),
				managedRetryUnitSnapshot("old", 1), false, tt.err,
			)
			if attempted || err != nil {
				t.Fatalf("recoverAuthError() = attempted %v, err %v", attempted, err)
			}
			if *hookCalls != 0 || *refreshCalls != 0 {
				t.Fatalf("timeout/500 invoked hook=%d refresh=%d", *hookCalls, *refreshCalls)
			}
		})
	}
}

func TestRecoverAuthErrorAcceptsExplicitEditionMarkerWithoutCoreCode(t *testing.T) {
	hookCalls, refreshCalls := installAuthRetryUnitSeams(t)
	cause := apperrors.NewAuth("edition-specific rejection", apperrors.WithReason("edition_token_rejected"))
	marker := &authretry.AuthRefreshRequired{Cause: cause}
	attempted, _, err := (&runtimeRunner{}).recoverAuthError(
		context.Background(), "https://unused.invalid", retryUnitInvocation(),
		managedRetryUnitSnapshot("old", 3), false, marker,
	)
	if !attempted {
		t.Fatal("explicit edition marker was not consumed")
	}
	var typed *apperrors.Error
	if !errors.As(err, &typed) || typed.Reason != "auth_refresh_transient" {
		t.Fatalf("recoverAuthError() error = %#v, want auth_refresh_transient", err)
	}
	if *hookCalls != 0 {
		t.Fatalf("explicit marker was sent through OnAuthError %d time(s)", *hookCalls)
	}
	if *refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", *refreshCalls)
	}
}

func TestRecoverAuthErrorDoesNotUpgradeOrdinaryCategoryAuth(t *testing.T) {
	hookCalls, refreshCalls := installAuthRetryUnitSeams(t)
	source := apperrors.NewAuth("ordinary auth failure", apperrors.WithReason("auth_load_failed"))
	attempted, _, err := (&runtimeRunner{}).recoverAuthError(
		context.Background(), "https://unused.invalid", retryUnitInvocation(),
		managedRetryUnitSnapshot("old", 2), false, source,
	)
	if attempted || err != nil {
		t.Fatalf("ordinary CategoryAuth was recovered: attempted=%v err=%v", attempted, err)
	}
	if *hookCalls != 0 || *refreshCalls != 0 {
		t.Fatalf("ordinary CategoryAuth invoked hook=%d refresh=%d", *hookCalls, *refreshCalls)
	}
}

func TestRecoverAuthErrorVetoesPermissionAndPATMarkers(t *testing.T) {
	tests := []struct {
		name  string
		cause error
	}{
		{name: "http 403", cause: apperrors.NewAuth("forbidden", apperrors.WithReason("http_403"))},
		{name: "permission reason", cause: apperrors.NewAuth("permission required", apperrors.WithReason("permission_denied"))},
		{name: "scope diagnostic", cause: apperrors.NewAuth("scope required", apperrors.WithServerDiag(apperrors.ServerDiagnostics{ServerErrorCode: "scope_required"}))},
		{name: "403 diagnostic", cause: apperrors.NewAuth("forbidden", apperrors.WithServerDiag(apperrors.ServerDiagnostics{ServerErrorCode: "http_403"}))},
		{name: "PAT scope", cause: &PatScopeError{ErrorType: "missing_scope", MissingScope: "mail:send"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, refreshCalls := installAuthRetryUnitSeams(t)
			marker := &authretry.AuthRefreshRequired{Cause: tt.cause}
			attempted, _, err := (&runtimeRunner{}).recoverAuthError(
				context.Background(), "https://unused.invalid", retryUnitInvocation(),
				managedRetryUnitSnapshot("old", 1), false, marker,
			)
			if attempted || err != nil || *refreshCalls != 0 {
				t.Fatalf("permission marker recovered: attempted=%v err=%v refreshes=%d", attempted, err, *refreshCalls)
			}
		})
	}
}

func TestRecoverAuthErrorRequiresManagedOAuthLease(t *testing.T) {
	for _, snapshot := range []AccessTokenSnapshot{
		{AccessToken: "legacy", Source: "file", profilePinned: true},
		{AccessToken: "edition", Source: "edition", profilePinned: true},
		{AccessToken: "explicit", Source: "explicit"},
		{AccessToken: "compat", Source: "oauth_compat"},
	} {
		t.Run(snapshot.Source, func(t *testing.T) {
			hookCalls, refreshCalls := installAuthRetryUnitSeams(t)
			marker := &authretry.AuthRefreshRequired{Cause: apperrors.NewAuth("rejected", apperrors.WithReason("access_token_rejected"))}
			attempted, _, err := (&runtimeRunner{}).recoverAuthError(
				context.Background(), "https://unused.invalid", retryUnitInvocation(), snapshot, false, marker,
			)
			if attempted || err != nil || *hookCalls != 0 || *refreshCalls != 0 {
				t.Fatalf("source %q recovered: attempted=%v err=%v hook=%d refresh=%d", snapshot.Source, attempted, err, *hookCalls, *refreshCalls)
			}
		})
	}
}

func TestCoreAuthRejectionAcceptsExact40014RepresentationsOnly(t *testing.T) {
	for _, content := range []map[string]any{
		{"code": 40014},
		{"code": "40014"},
		{"error": map[string]any{"errorCode": "TOKEN_VERIFIED_FAILED"}},
	} {
		if _, ok := coreAuthRejectionFromContent(content); !ok {
			t.Fatalf("exact rejection not recognized: %#v", content)
		}
	}
	for _, content := range []map[string]any{
		{"code": 40015},
		{"message": "40014 token expired"},
		{"code": "TOKEN_VERIFY_FAILED"},
	} {
		if _, ok := coreAuthRejectionFromContent(content); ok {
			t.Fatalf("non-allowlisted rejection recognized: %#v", content)
		}
	}
}

func TestCoreAuthRejectionMixedPermissionSignalVetoesRefresh(t *testing.T) {
	for _, content := range []map[string]any{
		{"code": 40014, "details": map[string]any{"errorCode": "PERMISSION_DENIED"}},
		{"code": 40014, "details": map[string]any{"errorCode": "FORBIDDEN"}},
		{"code": 40014, "details": map[string]any{"errorCode": "ORG_DOC_TOKEN_MISMATCH"}},
		{"code": 40014, "details": map[string]any{"code": 403}},
		{"errorCode": "TOKEN_VERIFIED_FAILED", "data": map[string]any{"httpStatus": 403}},
		{"code": 40014, "data": map[string]any{"missingScope": "mail:send"}},
		{"code": 40014, "data": map[string]any{"requiredScope": "mail:send"}},
		{"code": 40014, "data": map[string]any{"requiredScopes": []any{"mail:send"}}},
	} {
		if _, ok := coreAuthRejectionFromContent(content); ok {
			t.Fatalf("mixed permission payload triggered refresh: %#v", content)
		}
	}
	for _, content := range []map[string]any{
		{"code": 40014, "data": map[string]any{"missingScopes": []any{}}},
		{"code": 40014, "data": map[string]any{"requiredScopes": nil}},
	} {
		if _, ok := coreAuthRejectionFromContent(content); !ok {
			t.Fatalf("empty scope metadata incorrectly vetoed token rejection: %#v", content)
		}
	}
}

func TestCoreAuthRejectionExplicitSuccessEnvelopeNeverRefreshes(t *testing.T) {
	for _, content := range []map[string]any{
		{"success": true, "code": 40014},
		{"ok": true, "errorCode": "TOKEN_VERIFIED_FAILED"},
		{"success": true, "code": 40014, "data": map[string]any{"missingScope": "mail:send"}},
		{"ok": true, "data": map[string]any{"errorCode": "TOKEN_VERIFIED_FAILED", "requiredScope": "mail:send"}},
	} {
		if _, ok := coreAuthRejectionFromContent(content); ok {
			t.Fatalf("explicit success payload triggered refresh: %#v", content)
		}
	}
}

func TestCoreAuthRejectionDropsFreeTextAndCredentialURLs(t *testing.T) {
	const (
		secret = "access-token-secret"
		uid    = "4496576595"
	)
	marker, ok := coreAuthRejectionFromContent(map[string]any{
		"code":             40014,
		"trace_id":         "trace-safe-1",
		"technical_detail": "token=" + secret + " uid=" + uid,
		"friendly_hint":    "retry as uid " + uid,
		"action_url":       "https://example.invalid/retry?access_token=" + secret,
	})
	if !ok {
		t.Fatal("allowlisted rejection not recognized")
	}
	var typed *apperrors.Error
	if !errors.As(marker, &typed) {
		t.Fatalf("marker cause = %T", marker)
	}
	if typed.ServerDiag.TraceID != "trace-safe-1" || typed.ServerDiag.ServerErrorCode != "40014" {
		t.Fatalf("safe diagnostics = %#v", typed.ServerDiag)
	}
	if typed.ServerDiag.TechnicalDetail != "" || typed.ServerDiag.FriendlyHint != "" || typed.ServerDiag.ActionURL != "" {
		t.Fatalf("free-form diagnostics retained: %#v", typed.ServerDiag)
	}
	var out bytes.Buffer
	if err := apperrors.PrintJSON(&out, marker); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), secret) || strings.Contains(out.String(), uid) || strings.Contains(out.String(), "action_url") {
		t.Fatalf("credential diagnostics leaked: %s", out.String())
	}
}

func TestCoreAuthRejectionDropsCredentialLookingBodyTraceIDs(t *testing.T) {
	for _, traceID := range []string{
		"4496576595",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0NDk2NTc2NTk1In0.signature1",
		"access-token-secret",
		"opaque0123456789abcdef0123456789",
		"trace-4496576595",
	} {
		marker, ok := coreAuthRejectionFromContent(map[string]any{
			"code":     40014,
			"trace_id": traceID,
		})
		if !ok {
			t.Fatalf("allowlisted rejection with trace %q not recognized", traceID)
		}
		var typed *apperrors.Error
		if !errors.As(marker, &typed) || typed.ServerDiag.TraceID != "" {
			t.Fatalf("trace %q survived in diagnostics: %#v", traceID, typed)
		}
		var out bytes.Buffer
		if err := apperrors.PrintJSON(&out, marker); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), traceID) {
			t.Fatalf("trace %q leaked in output: %s", traceID, out.String())
		}
	}
}

func TestCoreAuthRejectionSanitizesTypedAndCallErrorTraceMetadata(t *testing.T) {
	const (
		uid          = "4496576595"
		jwt          = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0NDk2NTc2NTk1In0.signature1"
		opaqueSecret = "opaque0123456789abcdef0123456789"
	)

	tests := []struct {
		name       string
		typedTrace string
		callTrace  string
		requestID  string
		wantTrace  string
	}{
		{name: "typed uid and header jwt", typedTrace: uid, callTrace: jwt, requestID: opaqueSecret},
		{name: "typed opaque falls back to safe header", typedTrace: opaqueSecret, callTrace: "trace-safe-1", requestID: uid, wantTrace: "trace-safe-1"},
		{name: "safe typed trace wins", typedTrace: "trace-safe-1", callTrace: jwt, requestID: uid, wantTrace: "trace-safe-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callErr := &transport.CallError{
				Stage:      transport.CallStageHTTP,
				HTTPStatus: http.StatusUnauthorized,
				TraceID:    tt.callTrace,
				RequestID:  tt.requestID,
			}
			source := apperrors.NewAuth(
				"remote-controlled auth error "+uid,
				apperrors.WithReason("http_401"),
				apperrors.WithRPCData([]byte(`{"trace_id":"`+tt.typedTrace+`","token":"`+opaqueSecret+`"}`)),
				apperrors.WithServerDiag(apperrors.ServerDiagnostics{
					TraceID:         tt.typedTrace,
					TechnicalDetail: "token=" + opaqueSecret,
					ActionURL:       "https://example.invalid/?token=" + opaqueSecret,
				}),
				apperrors.WithCause(callErr),
			)
			marker, ok := coreAuthRejectionFromError(source)
			if !ok {
				t.Fatal("HTTP 401 rejection not recognized")
			}
			var typed *apperrors.Error
			if !errors.As(marker, &typed) || typed.ServerDiag.TraceID != tt.wantTrace {
				t.Fatalf("safe marker diagnostics = %#v, want trace %q", typed, tt.wantTrace)
			}
			var sourceTyped *apperrors.Error
			if !errors.As(source, &sourceTyped) || sourceTyped.ServerDiag.TraceID != transport.SanitizeTraceID(tt.typedTrace) {
				t.Fatalf("source trace was not sanitized: %#v", sourceTyped)
			}
			if sourceTyped.Message != "access token was rejected by the server" || len(sourceTyped.RPCData) != 0 ||
				sourceTyped.ServerDiag.TechnicalDetail != "" || sourceTyped.ServerDiag.ActionURL != "" {
				t.Fatalf("source auth error was not normalized for recovery capture: %#v", sourceTyped)
			}
			if callErr.TraceID != transport.SanitizeTraceID(tt.callTrace) || callErr.RequestID != transport.SanitizeTraceID(tt.requestID) {
				t.Fatalf("CallError correlation metadata was not sanitized: %#v", callErr)
			}
			var out bytes.Buffer
			if err := apperrors.PrintJSON(&out, marker); err != nil {
				t.Fatal(err)
			}
			printed := out.String()
			for _, forbidden := range []string{uid, jwt, opaqueSecret, "remote-controlled auth error"} {
				if strings.Contains(printed, forbidden) {
					t.Fatalf("HTTP auth error output leaked %q: %s", forbidden, printed)
				}
			}
			if tt.wantTrace != "" && !strings.Contains(printed, tt.wantTrace) {
				t.Fatalf("safe trace %q missing from output: %s", tt.wantTrace, printed)
			}
		})
	}
}

func TestAuthRetryExhaustionHasStableReasonAndDoesNotRefreshAgain(t *testing.T) {
	_, refreshCalls := installAuthRetryUnitSeams(t)
	original := apperrors.NewAuth("still rejected", apperrors.WithReason("access_token_rejected"))
	_, err := (&runtimeRunner{}).maybeAuthRefreshRetry(
		withAuthRetrying(context.Background()), "https://unused.invalid", retryUnitInvocation(),
		AccessTokenSnapshot{AccessToken: "new", Generation: 2}, original,
	)
	var typed *apperrors.Error
	if !errors.As(err, &typed) || typed.Reason != "auth_retry_exhausted" || !errors.Is(err, original) {
		t.Fatalf("retry exhaustion error = %#v", err)
	}
	if *refreshCalls != 0 {
		t.Fatalf("retry exhaustion refreshed %d time(s)", *refreshCalls)
	}
}

func TestAuthResolutionTerminalFailureRequiresLoginAndKeepsCause(t *testing.T) {
	cause := &authpkg.OAuthEndpointError{StatusCode: http.StatusBadRequest, Code: "invalid_grant", Message: "raw server detail"}
	err := authResolutionError(cause)
	var typed *apperrors.Error
	if !errors.As(err, &typed) || typed.Reason != "login_required" || !errors.Is(err, cause) {
		t.Fatalf("authResolutionError() = %#v", err)
	}
}

func TestAuthRetryReusesLogicalExecutionAndMessageID(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("DWS_CONFIG_DIR", configDir)
	writeTokenManagerMarker(t, configDir, 1)

	var providerCalls atomic.Int32
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			if providerCalls.Add(1) > 1 {
				return managerToken("token-b", time.Now().Add(time.Hour), 2), nil
			}
			return managerToken("token-a", time.Now().Add(time.Hour), 1), nil
		}}
	})

	previousRefresherFactory := newRejectedTokenRefresher
	previousCall := runnerCallTool
	var refreshCalls atomic.Int32
	newRejectedTokenRefresher = func(string, string) rejectedTokenRefresher {
		return rejectedTokenRefresherFunc(func(context.Context, string, ...uint64) (string, error) {
			refreshCalls.Add(1)
			writeTokenManagerMarker(t, configDir, 2)
			return "token-b", nil
		})
	}
	t.Cleanup(func() {
		newRejectedTokenRefresher = previousRefresherFactory
		runnerCallTool = previousCall
	})

	var messageIDs, executionIDs, tokens, businessUUIDs []string
	runnerCallTool = func(client *transport.Client, _ context.Context, _, _ string, params map[string]any) (transport.ToolCallResult, error) {
		messageIDs = append(messageIDs, client.ExtraHeaders["x-dingtalk-message-id"])
		executionIDs = append(executionIDs, client.ExecutionId)
		tokens = append(tokens, client.AuthToken)
		businessUUID, _ := params["uuid"].(string)
		businessUUIDs = append(businessUUIDs, businessUUID)
		if len(tokens) == 1 {
			return transport.ToolCallResult{Content: map[string]any{"code": 40014}}, nil
		}
		return transport.ToolCallResult{Content: map[string]any{"success": true}}, nil
	}

	runner := &runtimeRunner{
		transport:   transport.NewClient(&http.Client{}),
		globalFlags: &GlobalFlags{},
	}
	invocation := retryUnitInvocation()
	invocation.Tool = "send_personal_message"
	_, err := runner.executeInvocation(context.Background(), "https://example.invalid/mcp", invocation)
	if err != nil {
		t.Fatalf("executeInvocation() error = %v", err)
	}
	if refreshCalls.Load() != 1 || len(tokens) != 2 {
		t.Fatalf("refreshes=%d calls=%d tokens=%v", refreshCalls.Load(), len(tokens), tokens)
	}
	if tokens[0] != "token-a" || tokens[1] != "token-b" {
		t.Fatalf("auth tokens = %v, want token-a then token-b", tokens)
	}
	if messageIDs[0] == "" || messageIDs[0] != messageIDs[1] {
		t.Fatalf("message IDs = %v, want one stable non-empty ID", messageIDs)
	}
	if executionIDs[0] == "" || executionIDs[0] != executionIDs[1] || executionIDs[0] != messageIDs[0] {
		t.Fatalf("execution IDs=%v message IDs=%v", executionIDs, messageIDs)
	}
	if businessUUIDs[0] == "" || businessUUIDs[0] != businessUUIDs[1] {
		t.Fatalf("business UUIDs = %v, want one stable non-empty UUID", businessUUIDs)
	}
}

func TestAuthRetryKeepsExactDefaultProfileLeaseAcrossAtoBSwitch(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("DWS_CONFIG_DIR", configDir)
	t.Setenv("DWS_DISABLE_KEYCHAIN", "1")
	t.Setenv("DWS_KEYCHAIN_DIR", t.TempDir())
	previousHooks := edition.Get()
	previousProfile := authpkg.RuntimeProfile()
	edition.Override(&edition.Hooks{})
	authpkg.SetRuntimeProfile("")
	t.Cleanup(func() {
		edition.Override(previousHooks)
		authpkg.SetRuntimeProfile(previousProfile)
	})
	seed := func(corpID, userID, access string) *authpkg.TokenData {
		return &authpkg.TokenData{
			AccessToken:  access,
			RefreshToken: "refresh-" + access,
			ExpiresAt:    time.Now().Add(time.Hour),
			RefreshExpAt: time.Now().Add(24 * time.Hour),
			CorpID:       corpID,
			UserID:       userID,
			ClientID:     "client",
		}
	}
	if err := authpkg.SaveTokenData(configDir, seed("corp-a", "user-a", "stored-a")); err != nil {
		t.Fatal(err)
	}
	authpkg.SetRuntimeProfile("corp-b:user-b")
	if err := authpkg.SaveTokenData(configDir, seed("corp-b", "user-b", "stored-b")); err != nil {
		t.Fatal(err)
	}
	authpkg.SetRuntimeProfile("")
	if _, err := authpkg.SetCurrentProfile(configDir, "corp-a:user-a"); err != nil {
		t.Fatal(err)
	}

	var tokenMu sync.Mutex
	tokensByProfile := map[string]string{
		"corp-a:user-a": "token-a-old",
		"corp-b:user-b": "token-b",
	}
	installTokenManagerProvider(t, func(_ string, profile string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			tokenMu.Lock()
			token := tokensByProfile[profile]
			tokenMu.Unlock()
			return managerToken(token, time.Now().Add(time.Hour), 1), nil
		}}
	})

	previousFactory := newRejectedTokenRefresher
	previousCall := runnerCallTool
	defer func() {
		newRejectedTokenRefresher = previousFactory
		runnerCallTool = previousCall
	}()
	refreshedProfile := ""
	newRejectedTokenRefresher = func(_ string, profile string) rejectedTokenRefresher {
		refreshedProfile = profile
		return rejectedTokenRefresherFunc(func(context.Context, string, ...uint64) (string, error) {
			tokenMu.Lock()
			tokensByProfile[profile] = "token-a-new"
			tokenMu.Unlock()
			generation, _, err := authpkg.ReadTokenMarkerGeneration(configDir)
			if err != nil {
				return "", err
			}
			writeTokenManagerMarker(t, configDir, generation+1)
			return "token-a-new", nil
		})
	}

	var sentTokens []string
	runnerCallTool = func(client *transport.Client, _ context.Context, _, _ string, _ map[string]any) (transport.ToolCallResult, error) {
		sentTokens = append(sentTokens, client.AuthToken)
		if len(sentTokens) == 1 {
			if _, err := authpkg.SetCurrentProfile(configDir, "corp-b:user-b"); err != nil {
				t.Fatal(err)
			}
			return transport.ToolCallResult{Content: map[string]any{"code": 40014}}, nil
		}
		return transport.ToolCallResult{Content: map[string]any{"success": true}}, nil
	}

	runner := &runtimeRunner{transport: transport.NewClient(&http.Client{}), globalFlags: &GlobalFlags{}}
	if _, err := runner.executeInvocation(context.Background(), "https://example.invalid/mcp", retryUnitInvocation()); err != nil {
		t.Fatal(err)
	}
	if refreshedProfile != "corp-a:user-a" {
		t.Fatalf("refreshed profile = %q, want profile A", refreshedProfile)
	}
	if len(sentTokens) != 2 || sentTokens[0] != "token-a-old" || sentTokens[1] != "token-a-new" {
		t.Fatalf("sent tokens = %v, want A-old then A-new (never B)", sentTokens)
	}
}

func TestConcurrentInvocationsKeepExecutionAndMessageIDsIsolated(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("DWS_CONFIG_DIR", configDir)
	writeTokenManagerMarker(t, configDir, 1)
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			return managerToken("shared-token", time.Now().Add(time.Hour), 1), nil
		}}
	})

	previousCall := runnerCallTool
	t.Cleanup(func() { runnerCallTool = previousCall })
	type observed struct {
		executionID string
		messageID   string
	}
	var (
		observedMu sync.Mutex
		calls      []observed
	)
	runnerCallTool = func(client *transport.Client, _ context.Context, _, _ string, _ map[string]any) (transport.ToolCallResult, error) {
		observedMu.Lock()
		calls = append(calls, observed{
			executionID: client.ExecutionId,
			messageID:   client.ExtraHeaders["x-dingtalk-message-id"],
		})
		observedMu.Unlock()
		return transport.ToolCallResult{Content: map[string]any{"success": true}}, nil
	}

	runner := &runtimeRunner{
		transport:   transport.NewClient(&http.Client{}),
		globalFlags: &GlobalFlags{},
		auditSink:   audit.NopSink{},
	}
	const count = 32
	start := make(chan struct{})
	errCh := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := runner.executeInvocation(context.Background(), "https://example.invalid/mcp", retryUnitInvocation())
			errCh <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent executeInvocation() error = %v", err)
		}
	}

	observedMu.Lock()
	defer observedMu.Unlock()
	if len(calls) != count {
		t.Fatalf("calls = %d, want %d", len(calls), count)
	}
	seen := make(map[string]struct{}, count)
	for _, call := range calls {
		if call.executionID == "" || call.messageID != call.executionID {
			t.Fatalf("correlation pair = %#v", call)
		}
		if _, duplicate := seen[call.executionID]; duplicate {
			t.Fatalf("execution ID reused across logical invocations: %q", call.executionID)
		}
		seen[call.executionID] = struct{}{}
	}
	if runner.transport.ExecutionId != "" {
		t.Fatalf("shared transport was mutated: execution_id=%q", runner.transport.ExecutionId)
	}
}

package app

import (
	"context"
	"errors"
	"net/http"
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
	hookCalls, refreshCalls := new(int), new(int)
	edition.Override(&edition.Hooks{OnAuthError: func(string, error) error {
		(*hookCalls)++
		return &authretry.AuthRefreshRequired{Cause: apperrors.NewAuth("overlay rejected token", apperrors.WithReason("overlay_token_rejected"))}
	}})
	forceRefreshRejectedTokenFunc = func(context.Context, string, string, ...uint64) (string, error) {
		(*refreshCalls)++
		return "", context.DeadlineExceeded
	}
	t.Cleanup(func() {
		edition.Override(previousHooks)
		forceRefreshRejectedTokenFunc = previousRefresh
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

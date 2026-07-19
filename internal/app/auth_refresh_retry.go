// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/executor"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/transport"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/authretry"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

// authRetryingKey marks a context that has already attempted one
// AuthRefreshRequired-driven retry of the current invocation. The runner uses
// this to refuse a second refresh+retry pass and surface the original cause
// to the user instead.
type authRetryingKeyType struct{}

var authRetryingKey = authRetryingKeyType{}

// IsAuthRetrying reports whether the current context is already inside an
// AuthRefreshRequired retry. Mirrors IsPatRetrying.
func IsAuthRetrying(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(authRetryingKey).(bool)
	return v
}

func withAuthRetrying(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, authRetryingKey, true)
}

var forceRefreshRejectedTokenFunc = ForceRefreshRejectedToken
var forceRefreshRejectedTokenForProfileFunc = forceRefreshRejectedTokenForProfile

func (r *runtimeRunner) maybeAuthRefreshRetry(
	ctx context.Context,
	endpoint string,
	invocation executor.Invocation,
	rejected AccessTokenSnapshot,
	originalErr error,
) (executor.Result, error) {
	if IsAuthRetrying(ctx) {
		logAuthRefreshRecovery(ctx, "retry_exhausted", invocation, rejected, authpkg.RefreshFailureUnknown, originalErr, false, false)
		return executor.Result{}, apperrors.NewAuth(
			"access token was rejected after one refresh retry",
			apperrors.WithOperation("tools/call"),
			apperrors.WithReason("auth_retry_exhausted"),
			apperrors.WithHint("重新登录后重试；若持续失败，请携带 trace/exec ID 排查服务端认证"),
			apperrors.WithCause(originalErr),
		)
	}
	_, refreshErr := forceRefreshRejectedTokenForSnapshot(ctx, defaultConfigDir(), rejected)
	if refreshErr != nil {
		failureClass := authpkg.ClassifyRefreshFailure(refreshErr)
		deleted, cleanupFailed := false, false
		if failureClass == authpkg.RefreshFailureTerminal {
			var deleteErr error
			deleted, deleteErr = deleteRejectedTokenForSnapshot(ctx, defaultConfigDir(), rejected)
			cleanupFailed = deleteErr != nil
		}
		ResetRuntimeTokenCache()
		logAuthRefreshRecovery(ctx, "refresh_failed", invocation, rejected, failureClass, refreshErr, deleted, cleanupFailed)
		return executor.Result{}, authRefreshFailureError(originalErr, refreshErr, failureClass)
	}
	ResetRuntimeTokenCache()
	logAuthRefreshRecovery(ctx, "refresh_succeeded", invocation, rejected, authpkg.RefreshFailureUnknown, nil, false, false)
	retryCtx := withAuthRetrying(ctx)
	if rejected.profilePinned {
		retryCtx = withLogicalProfile(retryCtx, rejected.profile)
	}
	return r.executeInvocation(retryCtx, endpoint, invocation)
}

func forceRefreshRejectedTokenForSnapshot(ctx context.Context, configDir string, rejected AccessTokenSnapshot) (string, error) {
	// Keep the test seam and backwards-compatible public function for snapshots
	// synthesized by tests/hosts. Real TokenManager snapshots always carry the
	// pinned selector chosen with their cache key.
	if !rejected.profilePinned {
		return forceRefreshRejectedTokenFunc(ctx, configDir, rejected.AccessToken, rejected.Generation)
	}
	return forceRefreshRejectedTokenForProfileFunc(ctx, configDir, rejected.profile, rejected.AccessToken, rejected.Generation)
}

func deleteRejectedTokenForSnapshot(ctx context.Context, configDir string, rejected AccessTokenSnapshot) (bool, error) {
	if !rejected.profilePinned {
		return authpkg.DeleteTokenDataIfAccessTokenMatches(ctx, configDir, rejected.AccessToken, rejected.Generation)
	}
	return authpkg.DeleteTokenDataIfAccessTokenMatchesForProfile(ctx, configDir, rejected.profile, rejected.AccessToken, rejected.Generation)
}

func coreAuthRejectionFromError(err error) (*authretry.AuthRefreshRequired, bool) {
	if err == nil {
		return nil, false
	}
	var callErr *transport.CallError
	if errors.As(err, &callErr) && callErr.HTTPStatus == http.StatusUnauthorized {
		return &authretry.AuthRefreshRequired{Cause: err}, true
	}
	var typed *apperrors.Error
	if errors.As(err, &typed) && typed.Reason == "http_401" {
		return &authretry.AuthRefreshRequired{Cause: err}, true
	}
	return nil, false
}

func coreAuthRejectionFromContent(content map[string]any) (*authretry.AuthRefreshRequired, bool) {
	if hasAuthRefreshVeto(content, 0) {
		return nil, false
	}
	code := exactAuthRejectionCode(content, 0)
	if code == "" {
		return nil, false
	}
	rawDiag := transport.ExtractServerDiagnosticsFromMap(content)
	// Auth-recovery payloads are adversarial input. Preserve only correlation
	// metadata and the exact allowlisted code that triggered this branch; free
	// text and URLs may contain bearer tokens, user IDs, or signed credentials.
	diag := apperrors.ServerDiagnostics{
		TraceID:         safeAuthTraceID(rawDiag.TraceID),
		ServerErrorCode: code,
	}
	return &authretry.AuthRefreshRequired{Cause: apperrors.NewAuth(
		"access token was rejected by the server",
		apperrors.WithOperation("tools/call"),
		apperrors.WithReason("access_token_rejected"),
		apperrors.WithServerDiag(diag),
	)}, true
}

func safeAuthTraceID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == ':' || r == '.' {
			continue
		}
		return ""
	}
	return value
}

func hasAuthRefreshVeto(value any, depth int) bool {
	if depth > 8 {
		return false
	}
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			compactKey := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
			switch compactKey {
			case "httpstatus", "status", "statuscode", "rpcstatus":
				if isForbiddenCode(child) {
					return true
				}
			case "code", "errorcode", "errcode", "servererrorcode":
				if code, ok := child.(string); ok && isAuthRefreshVetoCode(code) {
					return true
				}
			case "missingscope", "missingscopes":
				if child != nil && strings.TrimSpace(fmt.Sprint(child)) != "" {
					return true
				}
			}
			if hasAuthRefreshVeto(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if hasAuthRefreshVeto(child, depth+1) {
				return true
			}
		}
	}
	return false
}

func isForbiddenCode(value any) bool {
	switch code := value.(type) {
	case int:
		return code == http.StatusForbidden
	case int64:
		return code == http.StatusForbidden
	case float64:
		return code == http.StatusForbidden
	case string:
		return strings.TrimSpace(code) == "403"
	default:
		return false
	}
}

func isAuthRefreshVetoCode(code string) bool {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "CLI_ORG_NOT_AUTHORIZED", "AUTH_PERMISSION_DENIED", "PERMISSION_DENIED",
		"PAT_NO_PERMISSION", "PAT_LOW_RISK_NO_PERMISSION", "PAT_MEDIUM_RISK_NO_PERMISSION",
		"PAT_HIGH_RISK_NO_PERMISSION", "PAT_ORG_POLICY_DENIED", "AGENT_CODE_NOT_EXISTS",
		"PAT_BATCH_AUTH_PENDING", "PAT_SCOPE_AUTH_REQUIRED":
		return true
	default:
		return false
	}
}

func exactAuthRejectionCode(value any, depth int) string {
	if depth > 6 {
		return ""
	}
	switch current := value.(type) {
	case map[string]any:
		for _, key := range []string{"errorCode", "error_code", "errCode", "errcode", "code", "serverErrorCode", "server_error_code"} {
			if code, ok := exactTokenRejectionValue(current[key]); ok {
				return code
			}
		}
		for _, key := range []string{"error", "data", "result", "details", "content"} {
			if nested, ok := current[key]; ok {
				if code := exactAuthRejectionCode(nested, depth+1); code != "" {
					return code
				}
			}
		}
	case []any:
		for _, item := range current {
			if code := exactAuthRejectionCode(item, depth+1); code != "" {
				return code
			}
		}
	}
	return ""
}

func exactTokenRejectionValue(value any) (string, bool) {
	switch code := value.(type) {
	case string:
		if exactTokenRejectionCode(code) {
			return strings.ToUpper(strings.TrimSpace(code)), true
		}
		if strings.TrimSpace(code) == "40014" {
			return "40014", true
		}
	case float64:
		if code == 40014 {
			return "40014", true
		}
	case int:
		if code == 40014 {
			return "40014", true
		}
	case int64:
		if code == 40014 {
			return "40014", true
		}
	}
	return "", false
}

func exactTokenRejectionCode(code string) bool {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "TOKEN_VERIFIED_FAILED", "USER_TOKEN_ILLEGAL", "ACCESS_TOKEN_EXPIRED", "DWS_SERVICE_UNAUTHORIZED":
		return true
	default:
		return false
	}
}

func authRefreshAllowed(sourceErr, originalErr error) bool {
	if apperrors.AsPatAuthCheckError(sourceErr) != nil || apperrors.AsPatAuthCheckError(originalErr) != nil {
		return false
	}
	var patScope *PatScopeError
	if errors.As(sourceErr, &patScope) || errors.As(originalErr, &patScope) || isPatScopeError(sourceErr) || isPatScopeError(originalErr) {
		return false
	}
	return authRefreshErrorAllowed(sourceErr) && authRefreshErrorAllowed(originalErr)
}

func authRefreshErrorAllowed(err error) bool {
	var typed *apperrors.Error
	if errors.As(err, &typed) {
		if typed.Reason == "http_403" || typed.RPCCode == http.StatusForbidden {
			return false
		}
		switch strings.ToUpper(strings.TrimSpace(typed.ServerDiag.ServerErrorCode)) {
		case "CLI_ORG_NOT_AUTHORIZED", "AUTH_PERMISSION_DENIED", "PERMISSION_DENIED":
			return false
		}
	}
	return true
}

func authRefreshFailureError(originalErr, refreshErr error, class authpkg.RefreshFailureClass) error {
	reason := "auth_refresh_failed"
	message := "登录态刷新失败"
	hint := "使用 --verbose 查看认证阶段日志后重试；原始凭证未被破坏性清理"
	actions := []string{"dws auth status --verbose", "dws doctor --verbose"}
	switch class {
	case authpkg.RefreshFailureTransient:
		reason = "auth_refresh_transient"
		message = "登录态刷新暂时失败"
		hint = "网络、限流或认证服务暂时不可用；稍后重试，原登录态已保留"
	case authpkg.RefreshFailureTerminal:
		reason = "login_required"
		message = "登录态已失效"
		hint = "运行 'dws auth login' 完成登录后重试"
		actions = []string{"dws auth login"}
	}
	return apperrors.NewAuth(
		message,
		apperrors.WithOperation("tools/call.auth_refresh"),
		apperrors.WithReason(reason),
		apperrors.WithHint(hint),
		apperrors.WithActions(actions...),
		apperrors.WithCause(errors.Join(originalErr, refreshErr)),
	)
}

func logAuthRefreshRecovery(ctx context.Context, outcome string, invocation executor.Invocation, rejected AccessTokenSnapshot, class authpkg.RefreshFailureClass, cause error, credentialDeleted, cleanupFailed bool) {
	reason, oauthCode, causeCategory := "", "", ""
	var typed *apperrors.Error
	if errors.As(cause, &typed) {
		reason = typed.Reason
		causeCategory = string(typed.Category)
	}
	var endpointErr *authpkg.OAuthEndpointError
	if errors.As(cause, &endpointErr) {
		oauthCode = authpkg.SafeOAuthDiagnosticCode(endpointErr.Code)
		causeCategory = "oauth_endpoint"
	}
	execID, _ := logicalExecutionID(ctx)
	slog.Warn("runtime.auth_refresh_recovery",
		"stage", "runtime_retry",
		"outcome", outcome,
		"failure_class", string(class),
		"cause_category", causeCategory,
		"reason", reason,
		"oauth_code", oauthCode,
		"error_type", fmtType(cause),
		"product", invocation.CanonicalProduct,
		"tool", invocation.Tool,
		"exec_id", execID,
		"profile_hash", rejected.ProfileFingerprint,
		"credential_generation", rejected.Generation,
		"observed_generation", rejected.ObservedGeneration,
		"credential_source", rejected.Source,
		"expires_bucket", tokenExpiryBucket(rejected.ExpiresAt, time.Now()),
		"retry_count", 1,
		"credential_deleted", credentialDeleted,
		"credential_cleanup_failed", cleanupFailed,
	)
}

func tokenExpiryBucket(expiresAt, now time.Time) string {
	if expiresAt.IsZero() {
		return "unknown"
	}
	remaining := expiresAt.Sub(now)
	switch {
	case remaining <= 0:
		return "expired"
	case remaining <= 5*time.Minute:
		return "le_5m"
	case remaining <= time.Hour:
		return "le_1h"
	default:
		return "gt_1h"
	}
}

func fmtType(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%T", err)
}

func (r *runtimeRunner) recoverAuthError(
	ctx context.Context,
	endpoint string,
	invocation executor.Invocation,
	rejected AccessTokenSnapshot,
	hasPluginAuth bool,
	sourceErr error,
) (bool, executor.Result, error) {
	if sourceErr == nil || !r.canAutoRefreshAuth(hasPluginAuth, rejected) || !authRefreshAllowed(sourceErr, sourceErr) {
		return false, executor.Result{}, nil
	}

	marker, marked := authretry.As(sourceErr)
	coreMarker, coreRejected := coreAuthRejectionFromError(sourceErr)
	if marked {
		// ClassifyToolResult/preflight already supplied the explicit contract.
		// Do not feed it through OnAuthError a second time.
		cause := marker.Cause
		if cause == nil {
			cause = sourceErr
		}
		if !authRefreshAllowed(sourceErr, cause) {
			return false, executor.Result{}, nil
		}
		result, err := r.maybeAuthRefreshRetry(ctx, endpoint, invocation, rejected, cause)
		return true, result, err
	}
	if !coreRejected {
		// Timeouts, 5xx responses, and arbitrary transport/business failures
		// are not proof that the access token was rejected. In particular, do
		// not let a broad edition OnAuthError hook upgrade them into a refresh.
		return false, executor.Result{}, nil
	}
	marker = coreMarker
	resolved, hookErr := invokeEditionOnAuthError(defaultConfigDir(), sourceErr, marker)
	if hookErr != nil {
		return true, executor.Result{}, hookErr
	}
	if resolved == nil {
		return false, executor.Result{}, nil
	}
	cause := resolved.Cause
	if cause == nil {
		cause = sourceErr
	}
	if !authRefreshAllowed(sourceErr, cause) {
		return false, executor.Result{}, nil
	}
	result, err := r.maybeAuthRefreshRetry(ctx, endpoint, invocation, rejected, cause)
	return true, result, err
}

func (r *runtimeRunner) canAutoRefreshAuth(hasPluginAuth bool, snapshot AccessTokenSnapshot) bool {
	if r == nil || hasPluginAuth {
		return false
	}
	if r.globalFlags != nil && strings.TrimSpace(r.globalFlags.Token) != "" {
		return false
	}
	// Only a TokenManager-owned OAuth snapshot has the refresh credential,
	// generation, and immutable profile lease required for safe CAS recovery.
	// Legacy file strings, explicit tokens, and arbitrary edition tokens must
	// preserve the original rejection without attempting OAuth.
	return snapshot.profilePinned && snapshot.Source == "oauth" && strings.TrimSpace(snapshot.AccessToken) != ""
}

func editionAuthRejection(err error, fallback *authretry.AuthRefreshRequired) (*authretry.AuthRefreshRequired, error) {
	if err == nil {
		return fallback, nil
	}
	if marker, ok := authretry.As(err); ok {
		return marker, nil
	}
	return nil, err
}

func invokeEditionOnAuthError(configDir string, sourceErr error, fallback *authretry.AuthRefreshRequired) (*authretry.AuthRefreshRequired, error) {
	if fn := edition.Get().OnAuthError; fn != nil {
		return editionAuthRejection(fn(configDir, sourceErr), fallback)
	}
	return fallback, nil
}

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

func (r *runtimeRunner) maybeAuthRefreshRetry(
	ctx context.Context,
	endpoint string,
	invocation executor.Invocation,
	rejected AccessTokenSnapshot,
	originalErr error,
) (executor.Result, error) {
	if IsAuthRetrying(ctx) {
		logAuthRefreshRecovery("retry_exhausted", invocation, authpkg.RefreshFailureUnknown, originalErr, false, false)
		return executor.Result{}, apperrors.NewAuth(
			"access token was rejected after one refresh retry",
			apperrors.WithOperation("tools/call"),
			apperrors.WithReason("auth_retry_exhausted"),
			apperrors.WithHint("重新登录后重试；若持续失败，请携带 trace/exec ID 排查服务端认证"),
			apperrors.WithCause(originalErr),
		)
	}
	_, refreshErr := forceRefreshRejectedTokenFunc(ctx, defaultConfigDir(), rejected.AccessToken, rejected.Generation)
	if refreshErr != nil {
		failureClass := authpkg.ClassifyRefreshFailure(refreshErr)
		deleted, cleanupFailed := false, false
		if failureClass == authpkg.RefreshFailureTerminal {
			var deleteErr error
			deleted, deleteErr = authpkg.DeleteTokenDataIfAccessTokenMatches(ctx, defaultConfigDir(), rejected.AccessToken, rejected.Generation)
			cleanupFailed = deleteErr != nil
		}
		ResetRuntimeTokenCache()
		logAuthRefreshRecovery("refresh_failed", invocation, failureClass, refreshErr, deleted, cleanupFailed)
		return executor.Result{}, authRefreshFailureError(originalErr, refreshErr, failureClass)
	}
	ResetRuntimeTokenCache()
	logAuthRefreshRecovery("refresh_succeeded", invocation, authpkg.RefreshFailureUnknown, nil, false, false)
	return r.executeInvocation(withAuthRetrying(ctx), endpoint, invocation)
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
	code := exactAuthRejectionCode(content, 0)
	if code == "" {
		return nil, false
	}
	diag := transport.ExtractServerDiagnosticsFromMap(content)
	return &authretry.AuthRefreshRequired{Cause: apperrors.NewAuth(
		"access token was rejected by the server",
		apperrors.WithOperation("tools/call"),
		apperrors.WithReason("access_token_rejected"),
		apperrors.WithServerDiag(diag),
	)}, true
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

func logAuthRefreshRecovery(outcome string, invocation executor.Invocation, class authpkg.RefreshFailureClass, cause error, credentialDeleted, cleanupFailed bool) {
	reason, oauthCode, causeCategory := "", "", ""
	var typed *apperrors.Error
	if errors.As(cause, &typed) {
		reason = typed.Reason
		causeCategory = string(typed.Category)
	}
	var endpointErr *authpkg.OAuthEndpointError
	if errors.As(cause, &endpointErr) {
		oauthCode = strings.TrimSpace(endpointErr.Code)
		causeCategory = "oauth_endpoint"
	}
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
		"profile_selected", strings.TrimSpace(authpkg.RuntimeProfile()) != "",
		"credential_deleted", credentialDeleted,
		"credential_cleanup_failed", cleanupFailed,
	)
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
	if sourceErr == nil || !r.canAutoRefreshAuth(hasPluginAuth) || !authRefreshAllowed(sourceErr, sourceErr) {
		return false, executor.Result{}, nil
	}

	marker, marked := authretry.As(sourceErr)
	coreMarker, coreRejected := coreAuthRejectionFromError(sourceErr)
	trustedAuthError := isAuthError(sourceErr)
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
	if !coreRejected && !trustedAuthError {
		// Timeouts, 5xx responses, and arbitrary transport/business failures
		// are not proof that the access token was rejected. In particular, do
		// not let a broad edition OnAuthError hook upgrade them into a refresh.
		return false, executor.Result{}, nil
	}
	marker = coreMarker
	resolved, hookErr := invokeEditionOnAuthError(defaultConfigDir(), sourceErr, marker)
	if hookErr != nil {
		// Preserve the pre-V2 hook contract for errors already categorized as
		// authentication failures. A hook cannot replace an unrelated transport
		// error unless it returns the explicit AuthRefreshRequired marker.
		if coreRejected || isAuthError(sourceErr) {
			return true, executor.Result{}, hookErr
		}
		return false, executor.Result{}, nil
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

func (r *runtimeRunner) canAutoRefreshAuth(hasPluginAuth bool) bool {
	if r == nil || hasPluginAuth {
		return false
	}
	return r.globalFlags == nil || strings.TrimSpace(r.globalFlags.Token) == ""
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

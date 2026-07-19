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
		logAuthRefreshRecovery("retry_exhausted", invocation, authpkg.RefreshFailureUnknown, false, false)
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
		logAuthRefreshRecovery("refresh_failed", invocation, failureClass, deleted, cleanupFailed)
		return executor.Result{}, errors.Join(
			originalErr,
			fmt.Errorf("access token refresh failed (%s): %w", failureClass, refreshErr),
		)
	}
	ResetRuntimeTokenCache()
	logAuthRefreshRecovery("refresh_succeeded", invocation, authpkg.RefreshFailureUnknown, false, false)
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
	var typed *apperrors.Error
	if errors.As(originalErr, &typed) {
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

func logAuthRefreshRecovery(outcome string, invocation executor.Invocation, class authpkg.RefreshFailureClass, credentialDeleted, cleanupFailed bool) {
	slog.Warn("runtime.auth_refresh_recovery",
		"outcome", outcome,
		"failure_class", string(class),
		"product", invocation.CanonicalProduct,
		"tool", invocation.Tool,
		"profile_selected", strings.TrimSpace(authpkg.RuntimeProfile()) != "",
		"credential_deleted", credentialDeleted,
		"credential_cleanup_failed", cleanupFailed,
	)
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

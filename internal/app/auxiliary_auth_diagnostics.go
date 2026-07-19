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
	"net"
	"os"
	"strings"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
)

// auxiliaryAuthDiagnosticAttrs returns only bounded, machine-readable auth
// diagnostics. It deliberately excludes err.Error(), profile selectors,
// identities, token material, and endpoint response bodies.
func auxiliaryAuthDiagnosticAttrs(stage string, err error) []any {
	attrs := []any{
		"stage", stage,
		"error_type", classifyAuxiliaryAuthError(err),
		"cause_type", fmt.Sprintf("%T", err),
	}
	if err == nil {
		return attrs
	}
	class := authpkg.ClassifyRefreshFailure(err)
	attrs = append(attrs, "refresh_failure_class", string(class))

	var structured *apperrors.Error
	if errors.As(err, &structured) {
		attrs = append(attrs,
			"category", string(structured.Category),
			"reason", strings.TrimSpace(structured.Reason),
			"retryable", structured.Retryable,
		)
	}
	var endpointErr *authpkg.OAuthEndpointError
	if errors.As(err, &endpointErr) {
		attrs = append(attrs,
			"http_status", endpointErr.StatusCode,
			"oauth_code", strings.TrimSpace(endpointErr.Code),
		)
	}
	return attrs
}

func classifyAuxiliaryAuthError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, authpkg.ErrTokenDataNotFound) || errors.Is(err, os.ErrNotExist) {
		return "no_credentials"
	}
	if errors.Is(err, authpkg.ErrRefreshTokenExpired) {
		return "credentials_expired"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, os.ErrPermission) {
		return "permission_denied"
	}
	var endpointErr *authpkg.OAuthEndpointError
	if errors.As(err, &endpointErr) {
		return "oauth_endpoint"
	}
	var structured *apperrors.Error
	if errors.As(err, &structured) {
		if reason := strings.TrimSpace(structured.Reason); reason != "" {
			return reason
		}
		if structured.Category != "" {
			return string(structured.Category)
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return "network"
	}
	return "unknown"
}

func isTrueMissingCredential(err error) bool {
	return errors.Is(err, authpkg.ErrTokenDataNotFound) || errors.Is(err, os.ErrNotExist)
}

func logPATAuthFailure(level slog.Level, message, stage string, err error, extra ...any) {
	attrs := auxiliaryAuthDiagnosticAttrs(stage, err)
	attrs = append(attrs, extra...)
	slog.Log(context.Background(), level, message, attrs...)
}

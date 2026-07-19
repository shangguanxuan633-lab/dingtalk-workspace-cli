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

package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
)

// RefreshFailureClass controls whether rejected credentials may be removed.
// Unknown is deliberately non-destructive: only an explicit terminal signal
// is strong enough to authorize compare-and-delete cleanup.
type RefreshFailureClass string

const (
	RefreshFailureUnknown   RefreshFailureClass = "unknown"
	RefreshFailureTransient RefreshFailureClass = "transient"
	RefreshFailureTerminal  RefreshFailureClass = "terminal"
)

// ErrRefreshTokenExpired is retained in the error chain when local metadata
// proves that the refresh credential can no longer be used.
var ErrRefreshTokenExpired = errors.New("refresh token expired")

// OAuthEndpointError is a redacted OAuth failure. It intentionally carries
// only status/code and a bounded server message, never the response body or
// submitted access/refresh token.
type OAuthEndpointError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *OAuthEndpointError) Error() string {
	if e == nil {
		return "OAuth endpoint error"
	}
	parts := make([]string, 0, 3)
	if e.StatusCode != 0 {
		parts = append(parts, http.StatusText(e.StatusCode))
	}
	if code := SafeOAuthDiagnosticCode(e.Code); code != "" {
		parts = append(parts, code)
	}
	if len(parts) == 0 {
		return "OAuth endpoint error"
	}
	return "OAuth endpoint error: " + strings.Join(parts, ": ")
}

// SafeOAuthDiagnosticCode returns a bounded code suitable for logs and user
// diagnostics. OAuth servers and gateways are not trusted to keep their code
// field machine-only; an unknown value may contain echoed identity or token
// material, so it is collapsed to "other". Classification continues to use
// the raw in-memory code.
func SafeOAuthDiagnosticCode(code string) string {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "invalid_grant":
		return "invalid_grant"
	case "invalid_refresh_token":
		return "invalid_refresh_token"
	case "refresh_token_expired":
		return "refresh_token_expired"
	case "refresh_token_revoked":
		return "refresh_token_revoked"
	case "invalidparameter.authcode.notfound":
		return "invalidParameter.authCode.notFound"
	case "":
		return ""
	default:
		return "other"
	}
}

// ClassifyRefreshFailure separates retryable infrastructure failures from
// explicit refresh-credential revocation/expiry. Unknown failures (including
// local persistence and keychain errors) are never destructive.
func ClassifyRefreshFailure(err error) RefreshFailureClass {
	if err == nil {
		return RefreshFailureUnknown
	}
	if errors.Is(err, ErrRefreshTokenExpired) {
		return RefreshFailureTerminal
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return RefreshFailureTransient
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return RefreshFailureTransient
	}
	var endpointErr *OAuthEndpointError
	if errors.As(err, &endpointErr) {
		if endpointErr.StatusCode == http.StatusRequestTimeout ||
			endpointErr.StatusCode == http.StatusTooManyRequests ||
			endpointErr.StatusCode >= http.StatusInternalServerError {
			return RefreshFailureTransient
		}
		if terminalOAuthCode(endpointErr.Code) {
			return RefreshFailureTerminal
		}
		return RefreshFailureUnknown
	}

	return RefreshFailureUnknown
}

func terminalOAuthCode(code string) bool {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "invalid_grant", "invalid_refresh_token", "refresh_token_expired", "refresh_token_revoked", "invalidparameter.authcode.notfound":
		return true
	default:
		return false
	}
}

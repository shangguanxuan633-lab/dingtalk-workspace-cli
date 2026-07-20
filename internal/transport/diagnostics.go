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

package transport

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
)

// authPolicyEvidence is the deliberately narrow result of inspecting a
// remote HTTP/JSON-RPC error body. Raw payloads and free-form server text must
// never cross this boundary: callers only need to know whether the response
// is authentication-related, whether refresh is forbidden, and the exact
// allowlisted diagnostic code that established that decision.
type authPolicyEvidence struct {
	auth bool
	veto bool
	code string
}

func extractAuthPolicyEvidence(data []byte) authPolicyEvidence {
	if len(data) == 0 {
		return authPolicyEvidence{}
	}
	var content map[string]any
	if json.Unmarshal(data, &content) != nil || len(content) == 0 {
		return authPolicyEvidence{}
	}
	if apperrors.IsExplicitSuccessEnvelope(content) {
		return authPolicyEvidence{}
	}

	// HTTP status and JSON-RPC error envelopes are positive error context even
	// when their nested business payload omitted success:false/isError:true.
	// Explicit success still wins inside ClassifyToolResultContent.
	errorContent := make(map[string]any, len(content)+1)
	for key, value := range content {
		errorContent[key] = value
	}
	errorContent["isError"] = true

	classified := apperrors.ClassifyToolResultContent(errorContent)
	var patErr *apperrors.PATError
	if errors.As(classified, &patErr) {
		code := sanitizeAuthServerErrorCode(patErr.CanonicalCode())
		if code == "" {
			code = "PERMISSION_DENIED"
		}
		return authPolicyEvidence{auth: true, veto: true, code: code}
	}
	var typed *apperrors.Error
	if errors.As(classified, &typed) {
		code := sanitizeAuthServerErrorCode(typed.ServerDiag.ServerErrorCode)
		switch typed.Reason {
		case "permission_denied":
			if code == "" {
				code = "PERMISSION_DENIED"
			}
			return authPolicyEvidence{auth: true, veto: true, code: code}
		case "gateway_auth_expired":
			return authPolicyEvidence{auth: true, code: code}
		}
	}

	if code := exactRecoverableAuthCode(content, 0); code != "" {
		return authPolicyEvidence{auth: true, code: code}
	}
	return authPolicyEvidence{}
}

func exactRecoverableAuthCode(value any, depth int) string {
	if depth > 8 {
		return ""
	}
	switch current := value.(type) {
	case map[string]any:
		for _, key := range []string{"errorCode", "error_code", "errCode", "errcode", "code", "serverErrorCode", "server_error_code"} {
			if code := recoverableAuthCode(current[key]); code != "" {
				return code
			}
		}
		for _, key := range []string{"error", "data", "result", "details", "content"} {
			if nested, ok := current[key]; ok {
				if code := exactRecoverableAuthCode(nested, depth+1); code != "" {
					return code
				}
			}
		}
	case []any:
		for _, item := range current {
			if code := exactRecoverableAuthCode(item, depth+1); code != "" {
				return code
			}
		}
	}
	return ""
}

func recoverableAuthCode(value any) string {
	switch current := value.(type) {
	case string:
		code := strings.ToUpper(strings.TrimSpace(current))
		switch code {
		case "40014", "HTTP_401", "TOKEN_VERIFIED_FAILED", "USER_TOKEN_ILLEGAL", "ACCESS_TOKEN_EXPIRED", "DWS_SERVICE_UNAUTHORIZED":
			return code
		}
	case float64:
		if current == 40014 {
			return "40014"
		}
	case json.Number:
		if string(current) == "40014" {
			return "40014"
		}
	case int:
		if current == 40014 {
			return "40014"
		}
	case int64:
		if current == 40014 {
			return "40014"
		}
	}
	return ""
}

// ExtractServerDiagnostics parses server diagnostic fields from a JSON
// payload (typically from RPCError.Data). Returns an empty struct if
// the payload is empty or unparseable.
func ExtractServerDiagnostics(data json.RawMessage) apperrors.ServerDiagnostics {
	if len(data) == 0 {
		return apperrors.ServerDiagnostics{}
	}
	var content map[string]any
	if json.Unmarshal(data, &content) != nil {
		return apperrors.ServerDiagnostics{}
	}
	return ExtractServerDiagnosticsFromMap(content)
}

// ExtractServerDiagnosticsFromMap parses server diagnostic fields from a
// map[string]any (typically from ToolCallResult.Content for business errors).
func ExtractServerDiagnosticsFromMap(content map[string]any) apperrors.ServerDiagnostics {
	if len(content) == 0 {
		return apperrors.ServerDiagnostics{}
	}
	diag := apperrors.ServerDiagnostics{
		TraceID:         SanitizeTraceID(stringFromMap(content, "trace_id", "traceId")),
		ServerErrorCode: serverErrorCodeFromMap(content, 0),
		TechnicalDetail: stringFromMap(content, "technical_detail"),
		FriendlyHint:    stringFromMapRecursive(content, 0, "friendly_hint", "friendlyHint"),
		ActionURL:       stringFromMapRecursive(content, 0, "action_url", "actionUrl"),
	}
	if v, ok := content["retryable"].(bool); ok {
		diag.ServerRetryable = &v
	}
	return diag
}

func sanitizeAuthServerDiagnostics(diag apperrors.ServerDiagnostics) apperrors.ServerDiagnostics {
	return apperrors.ServerDiagnostics{
		TraceID:         SanitizeTraceID(diag.TraceID),
		ServerErrorCode: sanitizeAuthServerErrorCode(diag.ServerErrorCode),
	}
}

func sanitizeAuthServerErrorCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	switch code {
	case "40014", "UNAUTHORIZED", "AUTH_ERROR", "AUTHENTICATION_FAILED", "HTTP_401",
		"TOKEN_VERIFIED_FAILED", "USER_TOKEN_ILLEGAL", "ACCESS_TOKEN_EXPIRED", "DWS_SERVICE_UNAUTHORIZED",
		"FORBIDDEN", "HTTP_403", "PERMISSION_DENIED", "AUTH_PERMISSION_DENIED", "CLI_ORG_NOT_AUTHORIZED",
		"ORG_DOC_TOKEN_MISMATCH", "SCOPE_REQUIRED", "PAT_NO_PERMISSION", "PAT_LOW_RISK_NO_PERMISSION",
		"PAT_MEDIUM_RISK_NO_PERMISSION", "PAT_HIGH_RISK_NO_PERMISSION", "PAT_ORG_POLICY_DENIED",
		"PAT_SCOPE_AUTH_REQUIRED", "PAT_BATCH_AUTH_PENDING", "AGENT_CODE_NOT_EXISTS":
		return code
	default:
		return ""
	}
}

func stringFromMapRecursive(content map[string]any, depth int, keys ...string) string {
	if content == nil || depth > 8 {
		return ""
	}
	if value := stringFromMap(content, keys...); value != "" {
		return value
	}
	for _, key := range []string{"content", "result", "data"} {
		switch child := content[key].(type) {
		case map[string]any:
			if value := stringFromMapRecursive(child, depth+1, keys...); value != "" {
				return value
			}
		case []any:
			for _, item := range child {
				childMap, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if value := stringFromMapRecursive(childMap, depth+1, keys...); value != "" {
					return value
				}
			}
		}
	}
	return ""
}

// ExtractTraceIDFromHeaders reads a trace ID from standard HTTP response
// headers. Returns empty string if none found.
func ExtractTraceIDFromHeaders(headers http.Header) string {
	for _, key := range []string{
		"X-Trace-Id",
		"X-Request-Id",
		"x-dingtalk-trace-id",
	} {
		if v := SanitizeTraceID(headers.Get(key)); v != "" {
			return v
		}
	}
	return ""
}

// SanitizeTraceID returns a bounded correlation identifier that is safe to
// copy into user-visible errors, recovery snapshots, and diagnostic logs.
//
// Trace metadata is controlled by the remote server. Treating every
// whitespace-free value as harmless lets an upstream accidentally (or
// maliciously) reflect a UID, JWT, access token, or other opaque credential
// through a field named trace_id. Keep only short human-readable identifiers,
// explicit correlation-shaped identifiers, and canonical UUIDs.
func SanitizeTraceID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return ""
	}

	hasDigit := false
	hasLetter := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '-', r == '_', r == ':', r == '.':
			// Correlation identifiers commonly use these separators.
		default:
			return ""
		}
	}
	if hasDigit && !hasLetter && !strings.ContainsAny(value, "-_.:") {
		// A bare decimal identifier is much more likely to be a UID than a
		// useful cross-system correlation identifier.
		return ""
	}

	lower := strings.ToLower(value)
	if containsSensitiveTraceMarker(lower) || looksLikeJWT(value) {
		return ""
	}
	if isCanonicalUUID(value) {
		return value
	}
	if digitsAndSeparatorsOnly(value) {
		return ""
	}

	payload, explicit := correlationPayload(value, lower)
	if !explicit {
		if len(value) <= 16 {
			// Preserve established compact trace IDs such as abc123 and req-1.
			return value
		}
		return ""
	}
	if payload == "" || len(payload) > 24 {
		return ""
	}
	payloadLower := strings.ToLower(payload)
	if containsSensitiveTraceMarker(payloadLower) || looksLikeJWT(payload) || (isDecimal(payload) && len(payload) > 6) {
		return ""
	}
	if isCanonicalUUID(payload) {
		return value
	}
	// A long, separator-free suffix is indistinguishable from an opaque
	// credential. Explicit, readable correlation IDs such as trace-safe-1
	// remain available.
	if len(payload) > 16 && !strings.ContainsAny(payload, "-_.:") {
		return ""
	}
	return value
}

func containsSensitiveTraceMarker(lower string) bool {
	for _, marker := range []string{
		"authorization", "bearer", "credential", "password", "passwd",
		"token", "refresh", "oauth",
		"access-token", "access_token", "accesstoken", "refresh-token",
		"refresh_token", "refreshtoken", "client-secret", "client_secret",
		"clientsecret", "private-key", "private_key", "privatekey",
		"api-key", "api_key", "apikey", "secret", "session", "cookie",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, prefix := range []string{
		"pat-", "pat_", "sk-", "sk_", "ak-", "ak_", "dapi", "ding-", "ding_", "dingtalk-", "dingtalk_", "dt-", "dt_",
		"uid-", "uid_", "userid-", "userid_",
	} {
		if strings.HasPrefix(lower, prefix) || strings.Contains(lower, "-"+prefix) || strings.Contains(lower, "_"+prefix) {
			return true
		}
	}
	return false
}

func correlationPayload(value, lower string) (string, bool) {
	for _, prefix := range []string{
		"correlation-id-", "correlation_id_", "correlation-", "correlation_",
		"request-id-", "request_id_", "request-", "request_",
		"execution-id-", "execution_id_", "execution-", "execution_",
		"message-id-", "message_id_", "message-", "message_",
		"trace-id-", "trace_id_", "trace-", "trace_", "trace:", "trace.",
		"span-id-", "span_id_", "span-", "span_", "corr-", "corr_",
		"exec-", "exec_", "req-", "req_", "msg-", "msg_",
	} {
		if strings.HasPrefix(lower, prefix) {
			return value[len(prefix):], true
		}
	}
	return "", false
}

func looksLikeJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || len(parts[0]) < 8 || len(parts[1]) < 8 || len(parts[2]) < 8 {
		return false
	}
	for _, part := range parts {
		for _, r := range part {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func digitsAndSeparatorsOnly(value string) bool {
	hasDigit := false
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '-', r == '_', r == ':', r == '.':
		default:
			return false
		}
	}
	return hasDigit
}

func isCanonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, r := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

// coalesceStr returns the first non-empty string.
func coalesceStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// stringFromMap returns the first non-empty string value found for any of
// the given keys in the map.
func stringFromMap(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func serverErrorCodeFromMap(content map[string]any, depth int) string {
	if content == nil || depth > 8 {
		return ""
	}
	direct := stringFromMap(content, "errorCode", "error_code", "errCode", "errcode", "code", "serverErrorCode", "server_error_code")
	if isWrapperServerCode(direct) {
		if nested := nestedServerErrorCode(content, depth); nested != "" {
			return nested
		}
	}
	if direct != "" {
		return direct
	}
	return nestedServerErrorCode(content, depth)
}

func nestedServerErrorCode(content map[string]any, depth int) string {
	for _, key := range []string{"content", "result", "data"} {
		switch child := content[key].(type) {
		case map[string]any:
			if code := serverErrorCodeFromMap(child, depth+1); code != "" {
				return code
			}
		case []any:
			for _, item := range child {
				childMap, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if code := serverErrorCodeFromMap(childMap, depth+1); code != "" {
					return code
				}
			}
		}
	}
	return ""
}

func isWrapperServerCode(code string) bool {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "ERROR", "BUSINESS_ERROR", "-1":
		return true
	default:
		return false
	}
}

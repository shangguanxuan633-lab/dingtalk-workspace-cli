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

package logging

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"
)

// sensitiveKeys are header/field names whose values must be redacted in logs.
var sensitiveKeys = map[string]bool{
	"authorization":       true,
	"x-user-access-token": true,
	"client_secret":       true,
	"client-secret":       true,
	"token":               true,
	"secret":              true,
	"password":            true,
	"cookie":              true,
	"api_key":             true,
	"api-key":             true,
	"access_token":        true,
	"credential":          true,
}

// sensitiveSubstrings are substrings that mark a key as sensitive.
var sensitiveSubstrings = []string{
	"password", "secret", "token", "credential",
}

// identityKeys are identifiers that must not be copied verbatim into local
// diagnostic logs.  They are intentionally kept separate from credentials:
// callers may still log that a field was present, but never its value.
// compactLogKey makes this list cover snake_case, kebab-case, and camelCase.
var identityKeys = map[string]bool{
	"uid":                true,
	"userid":             true,
	"username":           true,
	"staffid":            true,
	"employeeid":         true,
	"unionid":            true,
	"openid":             true,
	"opendingtalkid":     true,
	"corpid":             true,
	"corpname":           true,
	"tenantid":           true,
	"profile":            true,
	"profilename":        true,
	"profileselector":    true,
	"runtimeprofile":     true,
	"identityselector":   true,
	"groupid":            true,
	"conversationid":     true,
	"openconversationid": true,
}

// IsSensitiveKey returns true if the key (case-insensitive) refers to a
// credential or secret that must not appear in log files.
func IsSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	if sensitiveKeys[lower] {
		return true
	}
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// IsIdentityKey reports whether a structured field carries a user,
// organization, profile, or conversation identifier that must be redacted in
// diagnostic output.
func IsIdentityKey(key string) bool {
	return identityKeys[compactLogKey(key)]
}

// RedactValue replaces a sensitive value with a safe placeholder. No prefix is
// retained: even a partial access/refresh token is credential material.
func RedactValue(value string) string {
	return "***"
}

// TruncateBody returns the body truncated to maxBytes with a UTF-8 safe
// boundary. If truncated, appends a marker showing the original size.
func TruncateBody(body []byte, maxBytes int) string {
	if len(body) <= maxBytes {
		return string(body)
	}
	safe := body[:maxBytes]
	// Walk back to a valid UTF-8 boundary.
	for len(safe) > 0 && !utf8.Valid(safe) {
		safe = safe[:len(safe)-1]
	}
	return fmt.Sprintf("%s...(truncated, total=%d bytes)", string(safe), len(body))
}

// SanitizeArguments returns a JSON string of the arguments map with
// sensitive-looking values replaced by "***". Truncates to maxBytes.
func SanitizeArguments(args map[string]any, maxBytes int) string {
	if len(args) == 0 {
		return "{}"
	}
	sanitized := make(map[string]any, len(args))
	for k, v := range args {
		sanitized[k] = v
	}
	redactMapValues(sanitized)
	data, err := json.Marshal(sanitized)
	if err != nil {
		return "{}"
	}
	return TruncateBody(data, maxBytes)
}

// redactMapValues replaces values of sensitive keys with "***" in-place.
func redactMapValues(m map[string]any) {
	for k, v := range m {
		if IsSensitiveKey(k) || IsIdentityKey(k) {
			m[k] = "***"
			continue
		}
		switch nested := v.(type) {
		case map[string]any:
			redactMapValues(nested)
		case []any:
			redactSliceValues(nested)
		}
	}
}

func redactSliceValues(values []any) {
	for _, value := range values {
		switch nested := value.(type) {
		case map[string]any:
			redactMapValues(nested)
		case []any:
			redactSliceValues(nested)
		}
	}
}

func compactLogKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	replacer := strings.NewReplacer("_", "", "-", "", ".", "", " ", "")
	return replacer.Replace(key)
}

// RedactHeaders returns slog attributes for HTTP headers with sensitive
// values redacted.
func RedactHeaders(headers http.Header) []slog.Attr {
	if len(headers) == 0 {
		return nil
	}
	attrs := make([]slog.Attr, 0, len(headers))
	for key := range headers {
		value := headers.Get(key)
		if IsSensitiveKey(key) || IsIdentityKey(key) {
			value = RedactValue(value)
		}
		attrs = append(attrs, slog.String("header."+strings.ToLower(key), value))
	}
	return attrs
}

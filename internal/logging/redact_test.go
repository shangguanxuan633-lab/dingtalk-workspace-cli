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
	"net/http"
	"strings"
	"testing"
)

func TestIsSensitiveKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key  string
		want bool
	}{
		{"Authorization", true},
		{"authorization", true},
		{"x-user-access-token", true},
		{"X-User-Access-Token", true},
		{"client_secret", true},
		{"client-secret", true},
		{"token", true},
		{"password", true},
		{"cookie", true},
		{"Content-Type", false},
		{"X-Cli-Source", false},
		{"method", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Parallel()
			if got := IsSensitiveKey(tt.key); got != tt.want {
				t.Errorf("IsSensitiveKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestRedactValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"short", "***"},
		{"12345678", "***"},
		{"123456789", "***"},
		{"a-very-long-token-value", "***"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			if got := RedactValue(tt.input); got != tt.want {
				t.Errorf("RedactValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTruncateBody(t *testing.T) {
	t.Parallel()
	short := []byte("hello")
	if got := TruncateBody(short, 100); got != "hello" {
		t.Fatalf("expected no truncation, got %q", got)
	}
	long := []byte(strings.Repeat("a", 200))
	got := TruncateBody(long, 50)
	if !strings.Contains(got, "truncated") {
		t.Fatalf("expected truncation marker, got %q", got)
	}
	if !strings.Contains(got, "total=200") {
		t.Fatalf("expected total size, got %q", got)
	}
}

func TestTruncateBody_Empty(t *testing.T) {
	t.Parallel()
	if got := TruncateBody(nil, 100); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestSanitizeArguments(t *testing.T) {
	t.Parallel()
	args := map[string]any{
		"name":     "test",
		"password": "secret123",
		"userId":   "user-4496576595",
		"nested": map[string]any{
			"api_key": "key-value",
			"safe":    "ok",
			"items": []any{
				map[string]any{"corpId": "corp-secret"},
			},
		},
	}
	got := SanitizeArguments(args, 4096)
	if strings.Contains(got, "secret123") {
		t.Fatalf("password should be redacted: %s", got)
	}
	if strings.Contains(got, "key-value") {
		t.Fatalf("api_key should be redacted: %s", got)
	}
	for _, identity := range []string{"user-4496576595", "corp-secret"} {
		if strings.Contains(got, identity) {
			t.Fatalf("identity %q should be redacted: %s", identity, got)
		}
	}
	if !strings.Contains(got, "test") {
		t.Fatalf("non-sensitive value should remain: %s", got)
	}
}

func TestSanitizeArguments_Empty(t *testing.T) {
	t.Parallel()
	if got := SanitizeArguments(nil, 100); got != "{}" {
		t.Fatalf("expected {}, got %q", got)
	}
}

func TestRedactHeaders(t *testing.T) {
	t.Parallel()
	headers := http.Header{
		"Authorization": {"Bearer token123456"},
		"Content-Type":  {"application/json"},
	}
	attrs := RedactHeaders(headers)
	if len(attrs) != 2 {
		t.Fatalf("expected 2 attrs, got %d", len(attrs))
	}
	for _, attr := range attrs {
		if attr.Key == "header.authorization" && !strings.Contains(attr.Value.String(), "***") {
			t.Fatalf("authorization should be redacted: %s", attr.Value.String())
		}
		if attr.Key == "header.content-type" && attr.Value.String() != "application/json" {
			t.Fatalf("content-type should not be redacted: %s", attr.Value.String())
		}
	}
}

func TestIsSensitiveKey_Substrings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		key  string
		want bool
	}{
		{"x-api-token", true},
		{"user_password_hash", true},
		{"my_secret_key", true},
		{"x-credential-id", true},
		{"safe-header", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Parallel()
			if got := IsSensitiveKey(tt.key); got != tt.want {
				t.Errorf("IsSensitiveKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

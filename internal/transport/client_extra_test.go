package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
)

func TestWithAuth_ClonesCorrectly(t *testing.T) {
	t.Parallel()
	original := NewClient(nil)
	original.AuthToken = "original-token"
	original.ExtraHeaders = map[string]string{"X-Old": "val"}
	original.TrustedDomains = []string{"*.example.com"}

	clone := original.WithAuth("new-token", map[string]string{"X-New": "val2"})

	if clone.AuthToken != "new-token" {
		t.Fatalf("clone token = %s, want new-token", clone.AuthToken)
	}
	if clone.ExtraHeaders["X-New"] != "val2" {
		t.Fatal("clone missing new header")
	}
	// Original unchanged
	if original.AuthToken != "original-token" {
		t.Fatal("original token was modified")
	}
	// Shared HTTP client
	if clone.HTTPClient != original.HTTPClient {
		t.Fatal("HTTP client should be shared")
	}
	// Trusted domains propagated
	if len(clone.TrustedDomains) != 1 || clone.TrustedDomains[0] != "*.example.com" {
		t.Fatal("trusted domains not propagated")
	}
}

func TestMatchDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		host, pattern string
		want          bool
	}{
		{"api.dingtalk.com", "*.dingtalk.com", true},
		{"dingtalk.com", "*.dingtalk.com", true},
		{"api.dingtalk.com", "api.dingtalk.com", true},
		{"evil.com", "*.dingtalk.com", false},
		{"api.dingtalk.com", "", false},
		{"API.DINGTALK.COM", "*.dingtalk.com", true},
		{"localhost", "localhost", true},
		{"localhost", "*.localhost", true}, // matches host == pattern[2:]
	}
	for _, tt := range tests {
		t.Run(tt.host+"_"+tt.pattern, func(t *testing.T) {
			if got := matchDomain(tt.host, tt.pattern); got != tt.want {
				t.Fatalf("matchDomain(%s, %s) = %v, want %v", tt.host, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestRedactURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"https://api.example.com/path", "https://api.example.com/path"},
		{"https://api.example.com/path?key=secret&token=abc", ""},
		{"not a url ://", "not a url ://"},
	}
	for _, tt := range tests {
		got := RedactURL(tt.input)
		if tt.want == "" {
			// Just check that secrets are redacted
			if strings.Contains(got, "secret") || strings.Contains(got, "abc") {
				t.Fatalf("RedactURL(%s) still contains secrets: %s", tt.input, got)
			}
		} else if got != tt.want {
			t.Fatalf("RedactURL(%s) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestDoWithRetryRedactsGatewayQueryInHeaderDebugLog(t *testing.T) {
	t.Parallel()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var requestedURL string
	client := NewClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requestedURL = req.URL.String()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{}}`)),
			Request:    req,
		}, nil
	})})
	client.FileLogger = logger

	resp, err := client.doWithRetry(context.Background(), "https://mcp-gw.dingtalk.com/server/demo?key=secret#frag", []byte(`{}`), "initialize")
	if err != nil {
		t.Fatalf("doWithRetry() error = %v", err)
	}
	defer resp.Body.Close()

	if !strings.Contains(requestedURL, "key=secret") {
		t.Fatalf("gateway request URL = %q, want preserved key query", requestedURL)
	}
	out := logBuf.String()
	if strings.Contains(out, "key=secret") || strings.Contains(out, "secret") {
		t.Fatalf("debug log leaked gateway key: %s", out)
	}
	if !strings.Contains(out, "key=REDACTED") {
		t.Fatalf("debug log did not include redacted endpoint, got: %s", out)
	}
}

func TestCallJSONRPCSanitizesHeaderTraceBeforeErrorAndLog(t *testing.T) {
	t.Parallel()

	const unsafeTrace = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0NDk2NTc2NTk1In0.signature1"
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	client := NewClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     http.Header{"X-Trace-Id": {unsafeTrace}},
			Body:       io.NopCloser(strings.NewReader(`{"error":"unauthorized"}`)),
			Request:    req,
		}, nil
	})})
	client.MaxRetries = 0
	client.FileLogger = logger

	err := client.callJSONRPC(context.Background(), "https://mcp-gw.dingtalk.com/server/demo", requestEnvelope{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
	}, true, &map[string]any{})
	if err == nil {
		t.Fatal("callJSONRPC() error = nil")
	}
	var typed *apperrors.Error
	if !errors.As(err, &typed) || typed.ServerDiag.TraceID != "" {
		t.Fatalf("typed error diagnostics = %#v", typed)
	}
	var callErr *CallError
	if !errors.As(err, &callErr) || callErr.TraceID != "" {
		t.Fatalf("call error = %#v", callErr)
	}
	if strings.Contains(logBuf.String(), unsafeTrace) || strings.Contains(logBuf.String(), "4496576595") {
		t.Fatalf("transport log leaked unsafe trace metadata: %s", logBuf.String())
	}
}

func TestJSONRPCAuthErrorDropsRawRemoteDiagnostics(t *testing.T) {
	t.Parallel()

	const (
		secret = "access-token-secret"
		uid    = "4496576595"
	)
	err := jsonrpcEnvelopeError("tools/call", &RPCError{
		Code:    http.StatusUnauthorized,
		Message: "token " + secret + " rejected for uid " + uid,
		Data: []byte(`{
			"trace_id":"4496576595",
			"errorCode":"TOKEN_VERIFIED_FAILED",
			"technical_detail":"access-token-secret",
			"friendly_hint":"retry for uid 4496576595",
			"action_url":"https://example.invalid/?token=access-token-secret"
		}`),
	}, "", "trace-safe-1")

	var typed *apperrors.Error
	if !errors.As(err, &typed) {
		t.Fatalf("jsonrpcEnvelopeError() = %T", err)
	}
	if typed.Category != apperrors.CategoryAuth || len(typed.RPCData) != 0 {
		t.Fatalf("auth error retained raw RPC data: %#v", typed)
	}
	if typed.ServerDiag.TraceID != "trace-safe-1" || typed.ServerDiag.ServerErrorCode != "TOKEN_VERIFIED_FAILED" {
		t.Fatalf("safe auth diagnostics = %#v", typed.ServerDiag)
	}
	if typed.ServerDiag.TechnicalDetail != "" || typed.ServerDiag.FriendlyHint != "" || typed.ServerDiag.ActionURL != "" {
		t.Fatalf("untrusted auth diagnostics retained: %#v", typed.ServerDiag)
	}

	var out bytes.Buffer
	if printErr := apperrors.PrintJSON(&out, err); printErr != nil {
		t.Fatal(printErr)
	}
	printed := out.String()
	for _, forbidden := range []string{secret, uid, "retry for uid", "example.invalid", "rpc_data"} {
		if strings.Contains(printed, forbidden) {
			t.Fatalf("auth error output leaked %q: %s", forbidden, printed)
		}
	}
	if !strings.Contains(printed, "trace-safe-1") || !strings.Contains(printed, "TOKEN_VERIFIED_FAILED") {
		t.Fatalf("safe correlation metadata missing: %s", printed)
	}
}

func TestSanitizeBearerToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"valid-token-123", "valid-token-123"},
		{" spaced ", "spaced"},
		{"", ""},
		{"has\x00null", ""},
		{"has\nnewline", ""},
		{"has\ttab", ""},
	}
	for _, tt := range tests {
		if got := sanitizeBearerToken(tt.input); got != tt.want {
			t.Fatalf("sanitizeBearerToken(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestWarnWildcardDomains_OnlyOnce(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	c := NewClient(nil)
	c.Stderr = &buf

	c.warnWildcardDomains()
	c.warnWildcardDomains()
	c.warnWildcardDomains()

	lines := strings.Count(buf.String(), "[WARN]")
	if lines != 1 {
		t.Fatalf("expected 1 warning, got %d: %s", lines, buf.String())
	}
}

func TestTrustedDomainsList_FromField(t *testing.T) {
	t.Parallel()
	c := &Client{TrustedDomains: []string{"a.com", "b.com"}}
	got := c.trustedDomainsList()
	if len(got) != 2 || got[0] != "a.com" {
		t.Fatalf("expected field domains, got %v", got)
	}
}

func TestTrustedDomainsList_FromEnv(t *testing.T) {
	t.Setenv("DWS_TRUSTED_DOMAINS", "x.com,y.com")
	c := &Client{}
	got := c.trustedDomainsList()
	if len(got) != 2 || got[0] != "x.com" {
		t.Fatalf("expected env domains, got %v", got)
	}
}

func TestTrustedDomainsList_Default(t *testing.T) {
	t.Setenv("DWS_TRUSTED_DOMAINS", "")
	c := &Client{}
	got := c.trustedDomainsList()
	if len(got) == 0 {
		t.Fatal("expected default domains")
	}
}

func TestIsEndpointTrusted_WildcardTriggersWarning(t *testing.T) {
	var buf bytes.Buffer
	c := NewClient(nil)
	c.TrustedDomains = []string{"*"}
	c.Stderr = &buf
	t.Setenv("DWS_ALLOW_HTTP_ENDPOINTS", "")

	result := c.isEndpointTrusted("https://evil.com/api")
	if !result {
		t.Fatal("wildcard should trust all HTTPS endpoints")
	}
	if !strings.Contains(buf.String(), "[WARN]") {
		t.Fatalf("expected warning, got: %s", buf.String())
	}
}

func TestIsEndpointTrusted_HTTPRejected(t *testing.T) {
	t.Setenv("DWS_ALLOW_HTTP_ENDPOINTS", "")
	c := NewClient(nil)
	c.TrustedDomains = []string{"*"}
	result := c.isEndpointTrusted("http://evil.com/api")
	if result {
		t.Fatal("plain HTTP to non-loopback should be rejected")
	}
}

func TestIsEndpointTrusted_HTTPLoopbackAllowed(t *testing.T) {
	t.Setenv("DWS_ALLOW_HTTP_ENDPOINTS", "1")
	c := NewClient(nil)
	c.TrustedDomains = []string{"*"}
	var buf bytes.Buffer
	c.Stderr = &buf
	result := c.isEndpointTrusted("http://127.0.0.1:8080/api")
	if !result {
		t.Fatal("HTTP loopback with env var should be allowed")
	}
}

func TestIsEndpointTrusted_DomainMatch(t *testing.T) {
	t.Setenv("DWS_ALLOW_HTTP_ENDPOINTS", "")
	c := NewClient(nil)
	c.TrustedDomains = []string{"*.dingtalk.com"}
	if !c.isEndpointTrusted("https://api.dingtalk.com/v1") {
		t.Fatal("should trust *.dingtalk.com")
	}
	if c.isEndpointTrusted("https://evil.com/v1") {
		t.Fatal("should not trust evil.com")
	}
}

func TestHttpStatusError(t *testing.T) {
	t.Parallel()
	codes := []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusInternalServerError,
	}
	for _, code := range codes {
		err := httpStatusError("tools/call", "https://api.example.com/mcp", code, "", "")
		if err == nil {
			t.Fatalf("expected error for status %d", code)
		}
	}
}

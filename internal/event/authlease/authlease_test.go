package authlease

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestIsStrictRejectionMatrix(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"401", http.StatusUnauthorized, `{}`, true},
		{"40014 string", http.StatusOK, `{"error":{"errorCode":"40014"}}`, true},
		{"40014 number", http.StatusBadRequest, `{"code":40014}`, true},
		{"token verified failed", http.StatusOK, `{"errorCode":"TOKEN_VERIFIED_FAILED"}`, true},
		{"403 status", http.StatusForbidden, `{"code":40014}`, false},
		{"401 PAT", http.StatusUnauthorized, `{"code":"PAT_SCOPE_AUTH_REQUIRED"}`, false},
		{"401 org policy", http.StatusUnauthorized, `{"errorCode":"PAT_ORG_POLICY_DENIED"}`, false},
		{"401 low risk permission", http.StatusUnauthorized, `{"errorCode":"PAT_LOW_RISK_NO_PERMISSION"}`, false},
		{"401 batch auth", http.StatusUnauthorized, `{"errorCode":"PAT_BATCH_AUTH_PENDING"}`, false},
		{"401 missing scopes", http.StatusUnauthorized, `{"code":40014,"data":{"missingScopes":["mail:send"]}}`, false},
		{"401 empty missing scopes", http.StatusUnauthorized, `{"code":40014,"data":{"missingScopes":[]}}`, true},
		{"401 empty required scopes object", http.StatusUnauthorized, `{"code":40014,"data":{"requiredScopes":{}}}`, true},
		{"401 nil scope", http.StatusUnauthorized, `{"code":40014,"data":{"missingScope":null}}`, true},
		{"401 nested 403", http.StatusUnauthorized, `{"code":40014,"details":{"errorCode":403}}`, false},
		{"200 explicit success code", http.StatusOK, `{"success":true,"code":40014}`, false},
		{"200 explicit ok token code", http.StatusOK, `{"ok":"true","errorCode":"TOKEN_VERIFIED_FAILED"}`, false},
		{"200 explicit success permission metadata", http.StatusOK, `{"success":true,"data":{"requiredScopes":["mail:send"],"status":403}}`, false},
		{"prose", http.StatusBadRequest, `{"message":"please not 40014"}`, false},
		{"malformed 401", http.StatusUnauthorized, `not-json`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsStrictRejection(tc.status, []byte(tc.body)); got != tc.want {
				t.Fatalf("IsStrictRejection() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveAndRefreshErrorsAreSafeButUnwrap(t *testing.T) {
	secret := "token-secret-for-uid-4496576595"
	wantErr := errors.New(secret)
	_, err := Resolve(context.Background(), func(context.Context) (Lease, error) {
		return Lease{}, wantErr
	}, nil, "", "personal_ticket_token_resolve")
	if !errors.Is(err, wantErr) || strings.Contains(err.Error(), secret) {
		t.Fatalf("Resolve() error = %v, errors.Is=%v", err, errors.Is(err, wantErr))
	}

	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })
	_, err = RefreshRejected(context.Background(), Lease{
		AccessToken: "old-secret",
		RefreshRejected: func(context.Context) (string, error) {
			return "", wantErr
		},
	}, "personal_ticket_rejected_refresh")
	if !errors.Is(err, wantErr) || strings.Contains(err.Error(), secret) {
		t.Fatalf("RefreshRejected() error = %v, errors.Is=%v", err, errors.Is(err, wantErr))
	}
	if got := logs.String(); strings.Contains(got, secret) || strings.Contains(got, "old-secret") || !strings.Contains(got, "event.auth_recovery") {
		t.Fatalf("unsafe or missing auth recovery log: %s", got)
	}
}

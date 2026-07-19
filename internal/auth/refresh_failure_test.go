package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestClassifyRefreshFailureUsesOnlyStructuredSignals(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want RefreshFailureClass
	}{
		{name: "local expiry sentinel", err: ErrRefreshTokenExpired, want: RefreshFailureTerminal},
		{name: "invalid grant", err: &OAuthEndpointError{StatusCode: http.StatusBadRequest, Code: "invalid_grant"}, want: RefreshFailureTerminal},
		{name: "revoked", err: &OAuthEndpointError{StatusCode: http.StatusBadRequest, Code: "refresh_token_revoked"}, want: RefreshFailureTerminal},
		{name: "rate limited", err: &OAuthEndpointError{StatusCode: http.StatusTooManyRequests, Code: "busy"}, want: RefreshFailureTransient},
		{name: "server unavailable", err: &OAuthEndpointError{StatusCode: http.StatusServiceUnavailable}, want: RefreshFailureTransient},
		{name: "deadline", err: context.DeadlineExceeded, want: RefreshFailureTransient},
		{name: "terminal words are not trusted", err: errors.New("invalid_grant refresh token revoked"), want: RefreshFailureUnknown},
		{name: "ordinary bad request", err: &OAuthEndpointError{StatusCode: http.StatusBadRequest, Code: "invalid_parameter"}, want: RefreshFailureUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyRefreshFailure(tt.err); got != tt.want {
				t.Fatalf("ClassifyRefreshFailure() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOAuthEndpointErrorDoesNotExposeServerMessage(t *testing.T) {
	const secret = "refresh-token-secret"
	err := (&OAuthEndpointError{StatusCode: http.StatusBadRequest, Code: "invalid_grant", Message: "rejected " + secret}).Error()
	if strings.Contains(err, secret) || strings.Contains(err, "rejected") {
		t.Fatalf("OAuthEndpointError leaked server message: %q", err)
	}
	if !strings.Contains(err, "invalid_grant") {
		t.Fatalf("OAuthEndpointError omitted stable code: %q", err)
	}
}

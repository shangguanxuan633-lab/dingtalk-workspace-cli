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
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
)

func TestWaitForPatAuthorizationPropagatesCredentialProviderFailure(t *testing.T) {
	oldResolve := patResolveAccessToken
	oldTimeout := patAuthorizationTimeout
	oldInterval := patAuthorizationPollInterval
	oldLogger := slog.Default()
	t.Cleanup(func() {
		patResolveAccessToken = oldResolve
		patAuthorizationTimeout = oldTimeout
		patAuthorizationPollInterval = oldInterval
		slog.SetDefault(oldLogger)
	})

	secretText := "raw-profile raw-uid raw-corp raw-access-token"
	wantErr := errors.New(secretText)
	patResolveAccessToken = func(context.Context, string) (string, error) { return "", wantErr }
	patAuthorizationTimeout = time.Second
	patAuthorizationPollInterval = time.Millisecond
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))

	ok, err := WaitForPatAuthorization(t.Context(), "/config/profile-a", io.Discard)
	if ok || !errors.Is(err, wantErr) {
		t.Fatalf("WaitForPatAuthorization() = %v, %v; want provider cause", ok, err)
	}
	logText := logs.String()
	if !strings.Contains(logText, "pat_authorization_wait") || !strings.Contains(logText, "error_type") {
		t.Fatalf("safe auth diagnostics missing: %s", logText)
	}
	if strings.Contains(logText, secretText) || strings.Contains(logText, "/config/profile-a") {
		t.Fatalf("auth diagnostics leaked credential/profile data: %s", logText)
	}
}

func TestPollPatDeviceFlowProviderFailureStopsBeforeHTTP(t *testing.T) {
	oldResolve := patResolveAccessToken
	oldDo := patPollHTTPDo
	t.Cleanup(func() {
		patResolveAccessToken = oldResolve
		patPollHTTPDo = oldDo
	})

	wantErr := errors.New("keychain unavailable")
	patResolveAccessToken = func(context.Context, string) (string, error) { return "", wantErr }
	var httpCalls atomic.Int32
	patPollHTTPDo = func(*http.Client, *http.Request) (*http.Response, error) {
		httpCalls.Add(1)
		return nil, errors.New("must not be called")
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, _, err := pollPatDeviceFlowWithInterval(ctx, "flow", "/config/profile-a", io.Discard, time.Millisecond)
	if !errors.Is(err, wantErr) {
		t.Fatalf("pollPatDeviceFlowWithInterval() error = %v, want provider cause", err)
	}
	if got := httpCalls.Load(); got != 0 {
		t.Fatalf("business HTTP calls = %d, want 0", got)
	}
}

func TestPollPatDeviceFlowResolvesFreshTokenPerPollRequest(t *testing.T) {
	oldResolve := patResolveAccessToken
	oldDo := patPollHTTPDo
	t.Cleanup(func() {
		patResolveAccessToken = oldResolve
		patPollHTTPDo = oldDo
	})

	var providerCalls atomic.Int32
	patResolveAccessToken = func(context.Context, string) (string, error) {
		call := providerCalls.Add(1)
		if call == 1 {
			return "token-1", nil
		}
		return "token-2", nil
	}
	var gotTokens []string
	patPollHTTPDo = func(_ *http.Client, req *http.Request) (*http.Response, error) {
		gotTokens = append(gotTokens, req.Header.Get("x-user-access-token"))
		status := "PENDING"
		if len(gotTokens) == 2 {
			status = "APPROVED"
		}
		body := `{"success":true,"data":{"status":"` + status + `","authCode":"approved-code"}}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	status, authCode, err := pollPatDeviceFlowWithInterval(ctx, "flow", "/config/profile-a", io.Discard, time.Millisecond)
	if err != nil || status != authpkg.StatusApproved || authCode != "approved-code" {
		t.Fatalf("poll result = %q, %q, %v", status, authCode, err)
	}
	if got := providerCalls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2", got)
	}
	if want := []string{"token-1", "token-2"}; !reflect.DeepEqual(gotTokens, want) {
		t.Fatalf("request tokens = %#v, want %#v", gotTokens, want)
	}
}

func TestPollPatDeviceFlowTrueMissingPreservesHeaderOptionalFlow(t *testing.T) {
	oldResolve := patResolveAccessToken
	oldDo := patPollHTTPDo
	t.Cleanup(func() {
		patResolveAccessToken = oldResolve
		patPollHTTPDo = oldDo
	})

	patResolveAccessToken = func(context.Context, string) (string, error) {
		return "", authpkg.ErrTokenDataNotFound
	}
	patPollHTTPDo = func(_ *http.Client, req *http.Request) (*http.Response, error) {
		if token := req.Header.Get("x-user-access-token"); token != "" {
			t.Fatalf("missing-credential poll sent token header %q", token)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"success":true,"data":{"status":"APPROVED"}}`,
			)),
		}, nil
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	status, _, err := pollPatDeviceFlowWithInterval(ctx, "flow", "/config/profile-a", io.Discard, time.Millisecond)
	if err != nil || status != authpkg.StatusApproved {
		t.Fatalf("missing-credential poll = %q, %v", status, err)
	}
}

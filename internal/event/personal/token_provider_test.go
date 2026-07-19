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

package personal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestClientAccessTokenProviderResolvesPerLogicalRequest(t *testing.T) {
	var gotTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTokens = append(gotTokens, r.Header.Get("x-user-access-token"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, Identity{
		AccessToken: "stale-at-startup",
		ClientID:    "client",
		SourceID:    "open",
	})
	var providerCalls atomic.Int32
	client.AccessTokenProvider = func(context.Context) (string, error) {
		call := providerCalls.Add(1)
		return "fresh-token-" + string(rune('0'+call)), nil
	}

	if err := client.DeleteSubscription(t.Context(), "sub-1"); err != nil {
		t.Fatalf("DeleteSubscription(sub-1): %v", err)
	}
	if err := client.DeleteSubscription(t.Context(), "sub-2"); err != nil {
		t.Fatalf("DeleteSubscription(sub-2): %v", err)
	}

	if got := providerCalls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2", got)
	}
	if want := []string{"fresh-token-1", "fresh-token-2"}; !reflect.DeepEqual(gotTokens, want) {
		t.Fatalf("request tokens = %#v, want %#v", gotTokens, want)
	}
}

func TestClientAccessTokenProviderFailureStopsBeforeBusinessHTTP(t *testing.T) {
	var httpCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	wantErr := errors.New("keychain unavailable")
	client := NewClient(srv.URL, Identity{AccessToken: "stale-at-startup"})
	client.AccessTokenProvider = func(context.Context) (string, error) {
		return "", wantErr
	}

	err := client.DeleteSubscription(t.Context(), "sub-1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("DeleteSubscription() error = %v, want cause %v", err, wantErr)
	}
	if got := httpCalls.Load(); got != 0 {
		t.Fatalf("business HTTP calls = %d, want 0", got)
	}
}

func TestClientAccessTokenProviderEmptyTokenDoesNotUseStaticFallback(t *testing.T) {
	var httpCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, Identity{AccessToken: "stale-at-startup"})
	client.AccessTokenProvider = func(context.Context) (string, error) { return "  ", nil }
	if err := client.DeleteSubscription(t.Context(), "sub-1"); err == nil {
		t.Fatal("DeleteSubscription() error = nil, want empty-provider error")
	}
	if got := httpCalls.Load(); got != 0 {
		t.Fatalf("business HTTP calls = %d, want 0", got)
	}
}

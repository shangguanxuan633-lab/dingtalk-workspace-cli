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

package source

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestPersonalTicketProviderResolvesAgainForEachReconnectAttempt(t *testing.T) {
	var gotTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTokens = append(gotTokens, r.Header.Get("x-user-access-token"))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"endpoint": "ws://127.0.0.1/connect",
			"ticket":   "ticket",
		})
	}))
	defer srv.Close()

	var providerCalls atomic.Int32
	src, err := NewPersonal(PersonalConfig{
		AccessToken: "stale-at-startup",
		AccessTokenProvider: func(context.Context) (string, error) {
			call := providerCalls.Add(1)
			return "fresh-token-" + string(rune('0'+call)), nil
		},
		ClientID:   "client",
		SourceID:   "open",
		TicketURL:  srv.URL,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewPersonal(): %v", err)
	}

	// fetchTicket is the first operation of every runAttempt. Calling it twice
	// models the token boundary across an initial connection and a reconnect.
	if _, err := src.fetchTicket(t.Context()); err != nil {
		t.Fatalf("first fetchTicket(): %v", err)
	}
	if _, err := src.fetchTicket(t.Context()); err != nil {
		t.Fatalf("second fetchTicket(): %v", err)
	}

	if got := providerCalls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2", got)
	}
	if want := []string{"fresh-token-1", "fresh-token-2"}; !reflect.DeepEqual(gotTokens, want) {
		t.Fatalf("ticket request tokens = %#v, want %#v", gotTokens, want)
	}
}

func TestPersonalTicketProviderFailureStopsBeforeBusinessHTTP(t *testing.T) {
	var httpCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wantErr := errors.New("refresh timeout")
	src, err := NewPersonal(PersonalConfig{
		AccessTokenProvider: func(context.Context) (string, error) { return "", wantErr },
		ClientID:            "client",
		SourceID:            "open",
		TicketURL:           srv.URL,
		HTTPClient:          srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewPersonal(): %v", err)
	}
	_, err = src.fetchTicket(t.Context())
	if !errors.Is(err, wantErr) {
		t.Fatalf("fetchTicket() error = %v, want cause %v", err, wantErr)
	}
	if got := httpCalls.Load(); got != 0 {
		t.Fatalf("business HTTP calls = %d, want 0", got)
	}
}

func TestPortalTicketProviderResolvesPerLogicalRequest(t *testing.T) {
	var gotTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTokens = append(gotTokens, r.Header.Get("x-user-access-token"))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"endpoint": "ws://127.0.0.1/connect",
			"ticket":   "ticket",
		})
	}))
	defer srv.Close()

	var providerCalls atomic.Int32
	cfg := &PortalTicketConfig{
		TicketURL:   srv.URL,
		AccessToken: "stale-at-startup",
		AccessTokenProvider: func(context.Context) (string, error) {
			call := providerCalls.Add(1)
			return "fresh-token-" + string(rune('0'+call)), nil
		},
		SourceID:   "open",
		HTTPClient: srv.Client(),
	}
	if _, err := requestPortalTicket(t.Context(), cfg); err != nil {
		t.Fatalf("first requestPortalTicket(): %v", err)
	}
	if _, err := requestPortalTicket(t.Context(), cfg); err != nil {
		t.Fatalf("second requestPortalTicket(): %v", err)
	}

	if got := providerCalls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2", got)
	}
	if want := []string{"fresh-token-1", "fresh-token-2"}; !reflect.DeepEqual(gotTokens, want) {
		t.Fatalf("ticket request tokens = %#v, want %#v", gotTokens, want)
	}
}

func TestPortalTicketProviderFailureStopsBeforeBusinessHTTP(t *testing.T) {
	var httpCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wantErr := errors.New("token store unavailable")
	cfg := &PortalTicketConfig{
		TicketURL:           srv.URL,
		AccessTokenProvider: func(context.Context) (string, error) { return "", wantErr },
		SourceID:            "open",
		HTTPClient:          srv.Client(),
	}
	_, err := requestPortalTicket(t.Context(), cfg)
	if !errors.Is(err, wantErr) {
		t.Fatalf("requestPortalTicket() error = %v, want cause %v", err, wantErr)
	}
	if got := httpCalls.Load(); got != 0 {
		t.Fatalf("business HTTP calls = %d, want 0", got)
	}
}

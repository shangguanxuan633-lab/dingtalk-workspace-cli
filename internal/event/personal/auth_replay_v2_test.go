package personal

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestControlCreateManagedLeaseReplaysWithStableIdempotencyBody(t *testing.T) {
	var calls, refreshes atomic.Int32
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, raw)
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"result":{"subscribe_id":"sub-1"}}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, Identity{ClientID: "client", SourceID: "open"})
	client.HTTPClient = server.Client()
	client.AccessTokenSnapshotProvider = func(context.Context) (AccessTokenLease, error) {
		return AccessTokenLease{AccessToken: "old", RefreshRejected: func(context.Context) (string, error) {
			refreshes.Add(1)
			return "new", nil
		}}, nil
	}
	sub, err := client.CreateSubscription(context.Background(), CreateSubscriptionRequest{
		EventKey: "chat", RuleType: "singleChat", RuleParam: map[string]any{"uid": "u"}, IdempotencyKey: "idem-stable",
	})
	if err != nil || sub == nil || sub.SubscribeID != "sub-1" {
		t.Fatalf("CreateSubscription() = %#v, %v", sub, err)
	}
	if calls.Load() != 2 || refreshes.Load() != 1 || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || !bytes.Contains(bodies[0], []byte("idem-stable")) {
		t.Fatalf("calls=%d refreshes=%d bodies=%q", calls.Load(), refreshes.Load(), bodies)
	}
}

func TestControlCreateWithoutIdempotencyDoesNotReplay(t *testing.T) {
	var calls, refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	client := NewClient(server.URL, Identity{ClientID: "client", SourceID: "open"})
	client.HTTPClient = server.Client()
	client.AccessTokenSnapshotProvider = func(context.Context) (AccessTokenLease, error) {
		return AccessTokenLease{AccessToken: "old", RefreshRejected: func(context.Context) (string, error) {
			refreshes.Add(1)
			return "new", nil
		}}, nil
	}
	_, err := client.CreateSubscription(context.Background(), CreateSubscriptionRequest{
		EventKey: "chat", RuleType: "singleChat", RuleParam: map[string]any{"uid": "u"},
	})
	if err == nil || calls.Load() != 1 || refreshes.Load() != 0 {
		t.Fatalf("err=%v calls=%d refreshes=%d", err, calls.Load(), refreshes.Load())
	}
}

func TestControlGETPATVetoDoesNotRefresh(t *testing.T) {
	var calls, refreshes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":"PAT_SCOPE_AUTH_REQUIRED"}`)
	}))
	defer server.Close()
	client := NewClient(server.URL, Identity{ClientID: "client", SourceID: "open"})
	client.HTTPClient = server.Client()
	client.AccessTokenSnapshotProvider = func(context.Context) (AccessTokenLease, error) {
		return AccessTokenLease{AccessToken: "old", RefreshRejected: func(context.Context) (string, error) {
			refreshes.Add(1)
			return "new", nil
		}}, nil
	}
	err := client.do(context.Background(), http.MethodGet, "/event/sublist", nil, nil, nil)
	if err == nil || calls.Load() != 1 || refreshes.Load() != 0 {
		t.Fatalf("err=%v calls=%d refreshes=%d", err, calls.Load(), refreshes.Load())
	}
}

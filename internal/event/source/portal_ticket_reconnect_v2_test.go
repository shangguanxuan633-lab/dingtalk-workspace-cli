package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dwsevent "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/event"
	"github.com/gorilla/websocket"
	"github.com/open-dingtalk/dingtalk-stream-sdk-go/payload"
)

func TestPortalSourceReconnectsWithFreshProfileTokenAndTicket(t *testing.T) {
	var tokenCalls atomic.Int32
	var connections atomic.Int32
	var tokensMu sync.Mutex
	var ticketTokens []string
	upgrader := websocket.Upgrader{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wsEndpoint string
	mux := http.NewServeMux()
	mux.HandleFunc("/ticket", func(w http.ResponseWriter, r *http.Request) {
		tokensMu.Lock()
		ticketTokens = append(ticketTokens, r.Header.Get("x-user-access-token"))
		tokensMu.Unlock()
		_, _ = fmt.Fprintf(w, `{"endpoint":%q,"ticket":"ticket-%d"}`, wsEndpoint, len(ticketTokens))
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		attempt := connections.Add(1)
		frame := payload.DataFrame{
			Type:    "event",
			Headers: payload.DataFrameHeader{payload.DataFrameHeaderKMessageId: fmt.Sprintf("m-%d", attempt)},
			Data:    fmt.Sprintf(`{"attempt":%d}`, attempt),
		}
		_ = conn.WriteJSON(frame)
		_, _, _ = conn.ReadMessage()
		if attempt == 1 {
			return
		}
		<-ctx.Done()
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	wsEndpoint = "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	src, err := New(Config{PortalTicket: &PortalTicketConfig{
		TicketURL: server.URL + "/ticket",
		AccessTokenProvider: func(context.Context) (string, error) {
			return fmt.Sprintf("token-%d", tokenCalls.Add(1)), nil
		},
		SourceID:     "open",
		HTTPClient:   server.Client(),
		ReconnectMin: 5 * time.Millisecond,
		ReconnectMax: 10 * time.Millisecond,
	}})
	if err != nil {
		t.Fatal(err)
	}
	emitted := make(chan *dwsevent.RawEvent, 4)
	done := make(chan error, 1)
	go func() { done <- src.Start(ctx, func(event *dwsevent.RawEvent) { emitted <- event }) }()
	for i := 0; i < 2; i++ {
		select {
		case <-emitted:
		case <-time.After(2 * time.Second):
			t.Fatalf("event %d timeout", i+1)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start() = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("portal source did not stop")
	}
	tokensMu.Lock()
	gotTokens := append([]string(nil), ticketTokens...)
	tokensMu.Unlock()
	if len(gotTokens) < 2 || gotTokens[0] != "token-1" || gotTokens[1] != "token-2" {
		t.Fatalf("ticket tokens = %q", gotTokens)
	}
	if src.State().ReconnectCount < 1 {
		t.Fatalf("reconnect count = %d", src.State().ReconnectCount)
	}
}

func TestPortalSourceRetriesInitialTicketAndWebsocketFailuresWithFreshToken(t *testing.T) {
	var tokenCalls atomic.Int32
	var ticketCalls atomic.Int32
	var wsEndpoint string
	var tokensMu sync.Mutex
	var tokens []string
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/ticket", func(w http.ResponseWriter, r *http.Request) {
		tokensMu.Lock()
		tokens = append(tokens, r.Header.Get("x-user-access-token"))
		tokensMu.Unlock()
		switch ticketCalls.Add(1) {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"errorCode":"TEMPORARY","errorMsg":"do-not-log-token"}`)
		case 2:
			_, _ = io.WriteString(w, `{"endpoint":"ws://127.0.0.1:1","ticket":"sensitive-ticket"}`)
		default:
			_, _ = fmt.Fprintf(w, `{"endpoint":%q,"ticket":"ok"}`, wsEndpoint)
		}
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		frame := payload.DataFrame{Type: "event", Headers: payload.DataFrameHeader{payload.DataFrameHeaderKMessageId: "ready"}, Data: `{}`}
		_ = conn.WriteJSON(frame)
		_, _, _ = conn.ReadMessage()
		<-r.Context().Done()
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	wsEndpoint = "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	src, err := New(Config{PortalTicket: &PortalTicketConfig{
		TicketURL: server.URL + "/ticket",
		AccessTokenProvider: func(context.Context) (string, error) {
			return fmt.Sprintf("token-%d", tokenCalls.Add(1)), nil
		},
		SourceID: "open", HTTPClient: server.Client(), ReconnectMin: time.Millisecond, ReconnectMax: 2 * time.Millisecond,
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	emitted := make(chan struct{}, 1)
	go func() { done <- src.Start(ctx, func(*dwsevent.RawEvent) { emitted <- struct{}{} }) }()
	select {
	case <-emitted:
	case <-time.After(2 * time.Second):
		t.Fatal("portal source did not recover")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start() = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("portal source did not stop")
	}
	tokensMu.Lock()
	got := append([]string(nil), tokens...)
	tokensMu.Unlock()
	if len(got) < 3 || got[0] != "token-1" || got[1] != "token-2" || got[2] != "token-3" {
		t.Fatalf("ticket tokens = %q", got)
	}
	if src.State().ReconnectCount < 2 {
		t.Fatalf("reconnect count = %d", src.State().ReconnectCount)
	}
}

func TestPortalErrorsDoNotExposeBodyMessageOrWebsocketTicket(t *testing.T) {
	const secret = "token-secret-uid-4496576595"
	httpFailure := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader(`{"errorCode":"TOKEN_INVALID","errorMsg":"` + secret + `","actionUrl":"https://x/?token=` + secret + `"}`)),
			Header:     make(http.Header),
		}, nil
	})}
	_, err := requestPortalTicket(context.Background(), &PortalTicketConfig{
		TicketURL: "https://ticket.invalid", AccessToken: "access", SourceID: "open", HTTPClient: httpFailure,
	})
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("safe HTTP error = %v", err)
	}

	src, err := New(Config{PortalTicket: &PortalTicketConfig{
		TicketURL: "https://ticket.invalid", AccessToken: "access", SourceID: "open",
		DisableReconnect: true,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"endpoint":"ws://127.0.0.1:1/path?existing=` + secret + `","ticket":"` + secret + `"}`)), Header: make(http.Header)}, nil
		})},
	}})
	if err != nil {
		t.Fatal(err)
	}
	err = src.Start(context.Background(), func(*dwsevent.RawEvent) {})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("safe websocket error = %v", err)
	}
}

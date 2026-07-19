package source

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPersonalTicketManagedLeaseRefreshesAndReplaysOnce(t *testing.T) {
	var requests, refreshes atomic.Int32
	var bodies [][]byte
	var tokens []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, raw)
		tokens = append(tokens, r.Header.Get("x-user-access-token"))
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"code":401}`)
			return
		}
		_, _ = io.WriteString(w, `{"endpoint":"wss://example.test/stream","ticket":"ticket-1"}`)
	}))
	defer server.Close()
	source := &PersonalSource{cfg: PersonalConfig{
		AccessTokenSnapshotProvider: func(context.Context) (AccessTokenLease, error) {
			return AccessTokenLease{AccessToken: "old", RefreshRejected: func(context.Context) (string, error) {
				refreshes.Add(1)
				return "new", nil
			}}, nil
		},
		ClientID: "client", SourceID: "open", TicketURL: server.URL, TicketMode: "normal", HTTPClient: server.Client(),
	}}
	ticket, err := source.fetchTicket(context.Background())
	if err != nil || ticket == nil || ticket.Ticket != "ticket-1" {
		t.Fatalf("fetchTicket() = %#v, %v", ticket, err)
	}
	if requests.Load() != 2 || refreshes.Load() != 1 || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("requests=%d refreshes=%d bodies=%q", requests.Load(), refreshes.Load(), bodies)
	}
	if strings.Join(tokens, ",") != "old,new" {
		t.Fatalf("tokens = %#v", tokens)
	}
}

func TestPortalTicketManagedLeaseStrict40014ReplaysAndVetoesPermission(t *testing.T) {
	for _, tc := range []struct {
		name        string
		firstStatus int
		firstBody   string
		wantRefresh int32
		wantCalls   int32
	}{
		{"40014", http.StatusOK, `{"success":false,"errorCode":"40014"}`, 1, 2},
		{"403", http.StatusForbidden, `{"errorCode":"40014"}`, 0, 1},
		{"PAT veto", http.StatusUnauthorized, `{"code":"PAT_SCOPE_AUTH_REQUIRED"}`, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls, refreshes atomic.Int32
			var bodies [][]byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				bodies = append(bodies, raw)
				if calls.Add(1) == 1 {
					w.WriteHeader(tc.firstStatus)
					_, _ = io.WriteString(w, tc.firstBody)
					return
				}
				_, _ = io.WriteString(w, `{"endpoint":"wss://example.test/stream","ticket":"ticket-2"}`)
			}))
			defer server.Close()
			cfg := &PortalTicketConfig{
				TicketURL: server.URL, SourceID: "open", Mode: "normal", HTTPClient: server.Client(),
				AccessTokenSnapshotProvider: func(context.Context) (AccessTokenLease, error) {
					return AccessTokenLease{AccessToken: "old", RefreshRejected: func(context.Context) (string, error) {
						refreshes.Add(1)
						return "new", nil
					}}, nil
				},
			}
			_, err := requestPortalTicket(context.Background(), cfg)
			if tc.wantCalls == 2 && err != nil {
				t.Fatalf("requestPortalTicket() error = %v", err)
			}
			if calls.Load() != tc.wantCalls || refreshes.Load() != tc.wantRefresh {
				t.Fatalf("calls=%d refreshes=%d", calls.Load(), refreshes.Load())
			}
			if len(bodies) == 2 && !bytes.Equal(bodies[0], bodies[1]) {
				t.Fatalf("replayed body changed: %q", bodies)
			}
		})
	}
}

func TestTicketRefreshFailurePreservesCauseWithoutLeaking(t *testing.T) {
	secret := "token-secret-for-uid-4496576595"
	wantErr := errors.New(secret)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	_, err := requestPortalTicket(context.Background(), &PortalTicketConfig{
		TicketURL: server.URL, SourceID: "open", Mode: "normal", HTTPClient: server.Client(),
		AccessTokenSnapshotProvider: func(context.Context) (AccessTokenLease, error) {
			return AccessTokenLease{AccessToken: "old", RefreshRejected: func(context.Context) (string, error) { return "", wantErr }}, nil
		},
	})
	if !errors.Is(err, wantErr) || strings.Contains(err.Error(), secret) {
		t.Fatalf("requestPortalTicket() error = %v, errors.Is=%v", err, errors.Is(err, wantErr))
	}
}

func TestSafePortalCodeCollapsesUnknownMachineLookingSecrets(t *testing.T) {
	if got := safePortalCode("token-secret-uid-4496576595"); got != "other" {
		t.Fatalf("safePortalCode() = %q", got)
	}
	err := (&portalStageError{stage: "ticket_response", code: safePortalCode("token-secret-uid-4496576595")}).Error()
	if strings.Contains(err, "4496576595") || !strings.Contains(err, "other") {
		t.Fatalf("portal error = %q", err)
	}
}

func TestPersonalTicketEndpointParseErrorDoesNotExposeURL(t *testing.T) {
	secretURL := "%token-secret-uid-4496576595?ticket=secret"
	_, err := endpointWithTicket(secretURL, "ticket-secret")
	if err == nil || strings.Contains(err.Error(), "4496576595") || strings.Contains(err.Error(), "ticket-secret") {
		t.Fatalf("endpointWithTicket() error = %v", err)
	}
}

func TestTicketRequestBuildErrorsDoNotExposeConfiguredURLs(t *testing.T) {
	secret := "ticket-url-secret-for-uid-4496576595"
	badURL := "https://example.test/\n" + secret + "?access_token=" + secret

	personalSource, err := NewPersonal(PersonalConfig{
		AccessToken: "token",
		ClientID:    "client",
		SourceID:    "source",
		TicketURL:   badURL,
	})
	if err != nil {
		t.Fatalf("NewPersonal() = %v", err)
	}
	_, err = personalSource.fetchTicket(context.Background())
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "personal_ticket_request_build") {
		t.Fatalf("personal request build error = %v", err)
	}

	_, err = requestPortalTicket(context.Background(), &PortalTicketConfig{
		TicketURL:   badURL,
		AccessToken: "token",
		SourceID:    "source",
		Mode:        PortalTicketModeNormal,
	})
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "ticket request build") {
		t.Fatalf("portal request build error = %v", err)
	}
	var stageErr *portalStageError
	if !errors.As(err, &stageErr) || stageErr.stage != "ticket_request_build" {
		t.Fatalf("portal request build error did not retain typed cause chain: %T %v", err, err)
	}
}

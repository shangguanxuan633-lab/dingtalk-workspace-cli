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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	dwsevent "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/event"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/event/consume"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/event/personal"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/event/source"
)

func TestPersonalControlProductionProviderResolvesPerRequest(t *testing.T) {
	oldResolve := personalResolveAuxiliaryAccessToken
	t.Cleanup(func() { personalResolveAuxiliaryAccessToken = oldResolve })

	var gotConfigDirs []string
	var providerCalls atomic.Int32
	personalResolveAuxiliaryAccessToken = func(_ context.Context, configDir, explicit string) (string, error) {
		if explicit != "" {
			t.Fatalf("explicit token = %q, want empty", explicit)
		}
		gotConfigDirs = append(gotConfigDirs, configDir)
		call := providerCalls.Add(1)
		return "fresh-token-" + string(rune('0'+call)), nil
	}

	var gotTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTokens = append(gotTokens, r.Header.Get("x-user-access-token"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := newPersonalEventControlClient("/config/profile-a", srv.URL, personal.Identity{
		AccessToken: "stale-at-startup",
	})
	if client.Identity.AccessToken != "" {
		t.Fatalf("production client retained startup token %q", client.Identity.AccessToken)
	}
	if err := client.DeleteSubscription(t.Context(), "sub-1"); err != nil {
		t.Fatalf("first DeleteSubscription(): %v", err)
	}
	if err := client.DeleteSubscription(t.Context(), "sub-2"); err != nil {
		t.Fatalf("second DeleteSubscription(): %v", err)
	}

	if want := []string{"/config/profile-a", "/config/profile-a"}; !reflect.DeepEqual(gotConfigDirs, want) {
		t.Fatalf("provider config dirs = %#v, want %#v", gotConfigDirs, want)
	}
	if want := []string{"fresh-token-1", "fresh-token-2"}; !reflect.DeepEqual(gotTokens, want) {
		t.Fatalf("request tokens = %#v, want %#v", gotTokens, want)
	}
}

func TestPortalSourceProductionProviderIsLazyAndPreservesCause(t *testing.T) {
	oldNew := eventNewDingtalkSource
	oldResolve := eventResolveAccessToken
	t.Cleanup(func() {
		eventNewDingtalkSource = oldNew
		eventResolveAccessToken = oldResolve
	})

	wantErr := errors.New("keychain denied")
	var providerCalls atomic.Int32
	eventResolveAccessToken = func(_ context.Context, configDir, explicit string) (string, error) {
		providerCalls.Add(1)
		if configDir != "/config/profile-a" || explicit != "" {
			t.Fatalf("resolve args = (%q, %q)", configDir, explicit)
		}
		return "", wantErr
	}
	var captured source.Config
	eventNewDingtalkSource = func(cfg source.Config, _ ...source.SourceOption) (*source.DingtalkSource, error) {
		captured = cfg
		return &source.DingtalkSource{}, nil
	}

	_, err := newEventSource(t.Context(), "/config/profile-a", "client", "secret", eventStreamTicketOptions{Mode: "custom"})
	if err != nil {
		t.Fatalf("newEventSource(): %v", err)
	}
	if got := providerCalls.Load(); got != 0 {
		t.Fatalf("provider called during construction = %d, want 0", got)
	}
	if captured.PortalTicket == nil || captured.PortalTicket.AccessTokenProvider == nil {
		t.Fatal("portal source did not receive a dynamic provider")
	}
	if captured.PortalTicket.AccessToken != "" {
		t.Fatalf("portal source retained startup token %q", captured.PortalTicket.AccessToken)
	}
	_, err = captured.PortalTicket.AccessTokenProvider(t.Context())
	if !errors.Is(err, wantErr) {
		t.Fatalf("provider error = %v, want cause %v", err, wantErr)
	}
	if got := providerCalls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
}

func TestPortalSourceProviderAndSpawnArgsKeepExactProfileLease(t *testing.T) {
	oldNew := eventNewDingtalkSource
	oldResolve := eventResolveTokenForProfile
	t.Cleanup(func() {
		eventNewDingtalkSource = oldNew
		eventResolveTokenForProfile = oldResolve
	})
	var captured source.Config
	eventNewDingtalkSource = func(cfg source.Config, _ ...source.SourceOption) (*source.DingtalkSource, error) {
		captured = cfg
		return &source.DingtalkSource{}, nil
	}
	var gotProfile string
	eventResolveTokenForProfile = func(_ context.Context, configDir, explicit, profile string) (string, error) {
		if configDir != "/config" || explicit != "" {
			t.Fatalf("resolve args = (%q,%q)", configDir, explicit)
		}
		gotProfile = profile
		return "token-b", nil
	}
	opts := eventStreamTicketOptions{Mode: "normal", SourceID: "open", Profile: "corp-b:user-b"}
	if _, err := newEventSource(t.Context(), "/config", "portal", "", opts); err != nil {
		t.Fatal(err)
	}
	if _, err := captured.PortalTicket.AccessTokenProvider(t.Context()); err != nil {
		t.Fatal(err)
	}
	if gotProfile != "corp-b:user-b" {
		t.Fatalf("provider profile = %q", gotProfile)
	}
	args := opts.spawnArgs()
	if !reflect.DeepEqual(args[len(args)-2:], []string{"--profile", "corp-b:user-b"}) {
		t.Fatalf("spawn args = %#v", args)
	}
	for _, mode := range []string{"normal", "custom"} {
		a := eventStreamIdentityHash("same-client", eventStreamTicketOptions{Mode: mode, SourceID: "open", Profile: "corp-a:user-a"})
		b := eventStreamIdentityHash("same-client", eventStreamTicketOptions{Mode: mode, SourceID: "open", Profile: "corp-b:user-b"})
		if a == b || strings.Contains(a, "corp-") || strings.Contains(b, "corp-") {
			t.Fatalf("mode=%s bus hashes A=%q B=%q", mode, a, b)
		}
	}
}

func TestPersonalSourceProductionProviderFailureStopsBeforeTicketHTTP(t *testing.T) {
	oldResolve := personalResolveAuxiliaryAccessToken
	t.Cleanup(func() { personalResolveAuxiliaryAccessToken = oldResolve })

	wantErr := errors.New("refresh DNS failure")
	personalResolveAuxiliaryAccessToken = func(_ context.Context, configDir, explicit string) (string, error) {
		if configDir != "/config/profile-a" || explicit != "" {
			t.Fatalf("resolve args = (%q, %q)", configDir, explicit)
		}
		return "", wantErr
	}
	var httpCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	src, err := newPersonalStreamSource(t.Context(), personalStreamSourceOptions{
		ConfigDir: "/config/profile-a",
		Identity: personal.Identity{
			AccessToken: "stale-at-startup",
			ClientID:    "client",
			SourceID:    "open",
		},
		TicketURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("newPersonalStreamSource(): %v", err)
	}
	err = src.Start(t.Context(), func(*dwsevent.RawEvent) {})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Start() error = %v, want cause %v", err, wantErr)
	}
	if got := httpCalls.Load(); got != 0 {
		t.Fatalf("ticket HTTP calls = %d, want 0", got)
	}
}

func TestResolvePersonalEventIdentityPropagatesMetadataLoadFailure(t *testing.T) {
	oldResolve := personalResolveAuxiliaryAccessToken
	oldLoad := personalLoadTokenData
	t.Cleanup(func() {
		personalResolveAuxiliaryAccessToken = oldResolve
		personalLoadTokenData = oldLoad
	})

	wantErr := errors.New("token store corrupt")
	personalResolveAuxiliaryAccessToken = func(context.Context, string, string) (string, error) {
		return "fresh-token", nil
	}
	personalLoadTokenData = func(string) (*authpkg.TokenData, error) {
		return nil, wantErr
	}

	_, err := resolvePersonalEventIdentity(t.Context(), "/config/profile-a", "open")
	if !errors.Is(err, wantErr) {
		t.Fatalf("resolvePersonalEventIdentity() error = %v, want cause %v", err, wantErr)
	}
}

func TestPersonalConsumeCleanupLogsDynamicTokenFailure(t *testing.T) {
	oldIdentity := personalResolveEventIdentity
	oldEnsure := personalEnsureSubscription
	oldUpsert := personalUpsertRunState
	oldDelete := personalDeleteSubscription
	oldRemove := personalRemoveRunStates
	oldConsume := personalConsumeRun
	oldResolve := personalResolveAuxiliaryAccessToken
	oldLogger := slog.Default()
	t.Cleanup(func() {
		personalResolveEventIdentity = oldIdentity
		personalEnsureSubscription = oldEnsure
		personalUpsertRunState = oldUpsert
		personalDeleteSubscription = oldDelete
		personalRemoveRunStates = oldRemove
		personalConsumeRun = oldConsume
		personalResolveAuxiliaryAccessToken = oldResolve
		slog.SetDefault(oldLogger)
	})

	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	personalResolveEventIdentity = func(context.Context, string, string) (personal.Identity, error) {
		return personal.Identity{ClientID: "client", SourceID: "open"}, nil
	}
	personalEnsureSubscription = func(context.Context, *personal.Client, personal.Identity, personalConsumeOptions) (*personal.Subscription, string, string, error) {
		return &personal.Subscription{SubscribeID: "sub-1"}, personal.EventMention, "at", nil
	}
	personalUpsertRunState = func(string, personal.RunState) error { return nil }
	personalDeleteSubscription = (*personal.Client).DeleteSubscription
	personalRemoveRunStates = func(string, []string) error { return nil }
	runErr := errors.New("consumer stopped")
	personalConsumeRun = func(context.Context, consume.Config) error { return runErr }
	authErr := errors.New("keychain unavailable")
	var providerCalls atomic.Int32
	personalResolveAuxiliaryAccessToken = func(context.Context, string, string) (string, error) {
		providerCalls.Add(1)
		return "", authErr
	}

	err := runPersonalEventConsume(newPersonalCoverageCommand(), personalConsumeOptions{EventKey: personal.EventMention})
	if !errors.Is(err, runErr) {
		t.Fatalf("runPersonalEventConsume() error = %v, want %v", err, runErr)
	}
	if got := providerCalls.Load(); got != 1 {
		t.Fatalf("cleanup provider calls = %d, want 1", got)
	}
	logText := logs.String()
	if !strings.Contains(logText, "personal event cleanup failed") ||
		!strings.Contains(logText, "cancel_subscription") ||
		!strings.Contains(logText, "event_cleanup") ||
		!strings.Contains(logText, "error_type") {
		t.Fatalf("cleanup auth failure was not logged with safe diagnostics: %s", logText)
	}
	if strings.Contains(logText, authErr.Error()) {
		t.Fatalf("cleanup auth failure leaked raw error text: %s", logText)
	}
}

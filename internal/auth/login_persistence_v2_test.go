package auth

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

func installDirectLoginCredentials(t *testing.T) {
	t.Helper()
	oldID, oldSecret := ClientID(), ClientSecret()
	SetClientID("persistence-client")
	SetClientSecret("persistence-secret")
	t.Cleanup(func() {
		SetClientID(oldID)
		SetClientSecret(oldSecret)
	})
}

func TestExchangeCodeFailsBeforeHTTPWhenAppCredentialPersistenceFails(t *testing.T) {
	installDirectLoginCredentials(t)
	sentinel := errors.New("app credential store unavailable")
	originalSaveApp := oauthSaveAppConfig
	originalSaveSecret := oauthSaveClientSecret
	t.Cleanup(func() {
		oauthSaveAppConfig = originalSaveApp
		oauthSaveClientSecret = originalSaveSecret
	})
	oauthSaveAppConfig = func(string, *AppConfig) error { return sentinel }
	oauthSaveClientSecret = func(string, string) error { return nil }
	var requests atomic.Int32
	p := NewOAuthProvider(t.TempDir(), nil)
	p.Output = io.Discard
	p.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected HTTP")
	})}
	if _, err := p.exchangeCode(context.Background(), "one-time-code"); !errors.Is(err, sentinel) {
		t.Fatalf("exchangeCode() error = %v, want persistence cause", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("token endpoint requests = %d, want 0", got)
	}
}

func TestExchangeCodeFailsBeforeHTTPWhenRefreshSecretPersistenceFails(t *testing.T) {
	installDirectLoginCredentials(t)
	sentinel := errors.New("refresh secret store unavailable")
	originalSaveApp := oauthSaveAppConfig
	originalHasApp := oauthHasAppConfig
	originalSaveSecret := oauthSaveClientSecret
	t.Cleanup(func() {
		oauthSaveAppConfig = originalSaveApp
		oauthHasAppConfig = originalHasApp
		oauthSaveClientSecret = originalSaveSecret
	})
	oauthSaveAppConfig = func(string, *AppConfig) error { return nil }
	oauthHasAppConfig = func(string) bool { return true }
	oauthSaveClientSecret = func(string, string) error { return sentinel }
	var requests atomic.Int32
	p := NewOAuthProvider(t.TempDir(), nil)
	p.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected HTTP")
	})}
	if _, err := p.exchangeCode(context.Background(), "one-time-code"); !errors.Is(err, sentinel) {
		t.Fatalf("exchangeCode() error = %v, want secret-store cause", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("token endpoint requests = %d, want 0", got)
	}
}

func TestBrowserAndDeviceLoginPreflightAppConfigBeforeStartingFlow(t *testing.T) {
	installDirectLoginCredentials(t)
	sentinel := errors.New("app config unwritable")
	originalSaveApp := oauthSaveAppConfig
	originalListen := oauthListen
	originalDeviceLoginOnce := deviceLoginOnce
	t.Cleanup(func() {
		oauthSaveAppConfig = originalSaveApp
		oauthListen = originalListen
		deviceLoginOnce = originalDeviceLoginOnce
	})
	oauthSaveAppConfig = func(string, *AppConfig) error { return sentinel }
	var browserStarts, deviceStarts atomic.Int32
	oauthListen = func(string, string) (net.Listener, error) {
		browserStarts.Add(1)
		return nil, errors.New("unexpected listener")
	}
	deviceLoginOnce = func(*DeviceFlowProvider, context.Context, int) (*TokenData, error) {
		deviceStarts.Add(1)
		return nil, errors.New("unexpected device flow")
	}
	if _, err := NewOAuthProvider(t.TempDir(), nil).Login(context.Background(), true); !errors.Is(err, sentinel) {
		t.Fatalf("browser Login() error = %v", err)
	}
	if _, err := NewDeviceFlowProvider(t.TempDir(), nil).Login(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("device Login() error = %v", err)
	}
	if browserStarts.Load() != 0 || deviceStarts.Load() != 0 {
		t.Fatalf("flows started: browser=%d device=%d", browserStarts.Load(), deviceStarts.Load())
	}
}

func TestEditionTokenStoreV2PreflightBlocksInitialExchangeBeforeHTTP(t *testing.T) {
	installDirectLoginCredentials(t)
	previousHooks := edition.Get()
	previousSaveApp := oauthSaveAppConfig
	previousHasApp := oauthHasAppConfig
	previousSaveSecret := oauthSaveClientSecret
	t.Cleanup(func() {
		edition.Override(previousHooks)
		oauthSaveAppConfig = previousSaveApp
		oauthHasAppConfig = previousHasApp
		oauthSaveClientSecret = previousSaveSecret
	})
	sentinel := errors.New("profile store preflight failed")
	store := &memoryProfileTokenStoreV2{}
	edition.Override(store.hooks(func(string, string) error { return sentinel }))
	oauthSaveAppConfig = func(string, *AppConfig) error { return nil }
	oauthHasAppConfig = func(string) bool { return true }
	oauthSaveClientSecret = func(string, string) error { return nil }
	var requests atomic.Int32
	p := NewOAuthProviderForProfile(t.TempDir(), nil, "profile-a")
	p.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected HTTP")
	})}
	// exchangeCode's public compatibility path reads RuntimeProfile for the
	// preflight; pin it to the same selector used by the provider.
	previousProfile := RuntimeProfile()
	SetRuntimeProfile("profile-a")
	t.Cleanup(func() { SetRuntimeProfile(previousProfile) })
	if _, err := p.exchangeCode(context.Background(), "one-time-code"); !errors.Is(err, sentinel) {
		t.Fatalf("exchangeCode() error = %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("token endpoint requests = %d, want 0", requests.Load())
	}
}

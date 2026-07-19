package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/keychain"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

type fakeSnapshotProvider struct {
	get func(context.Context) (*authpkg.TokenData, error)
}

func (p fakeSnapshotProvider) GetTokenSnapshot(ctx context.Context) (*authpkg.TokenData, error) {
	return p.get(ctx)
}

func (p fakeSnapshotProvider) GetAccessToken(ctx context.Context) (string, error) {
	data, err := p.get(ctx)
	if err != nil || data == nil {
		return "", err
	}
	return data.AccessToken, nil
}

func installTokenManagerProvider(t *testing.T, factory func(string) accessTokenGetter) {
	t.Helper()
	originalProvider := newAccessTokenProvider
	originalHooks := edition.Get()
	originalProfile := authpkg.RuntimeProfile()
	newAccessTokenProvider = factory
	edition.Override(&edition.Hooks{})
	authpkg.SetRuntimeProfile("")
	t.Cleanup(func() {
		newAccessTokenProvider = originalProvider
		edition.Override(originalHooks)
		authpkg.SetRuntimeProfile(originalProfile)
		ResetRuntimeTokenCache()
	})
}

func writeTokenManagerMarker(t *testing.T, configDir string, generation uint64) {
	t.Helper()
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(authpkg.TokenMarker{UpdatedAt: time.Now().Format(time.RFC3339), Generation: generation})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "token.json"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

func managerToken(access string, expiresAt time.Time, generation uint64) *authpkg.TokenData {
	return &authpkg.TokenData{AccessToken: access, ExpiresAt: expiresAt, Generation: generation, UpdatedAt: time.Now().Format(time.RFC3339)}
}

func TestTokenManagerCachesOnlyFreshSnapshotsAndDoesNotRepeatProviderCalls(t *testing.T) {
	configDir := t.TempDir()
	writeTokenManagerMarker(t, configDir, 1)
	var calls atomic.Int32
	installTokenManagerProvider(t, func(string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			calls.Add(1)
			return managerToken("fresh", time.Now().Add(time.Hour), 1), nil
		}}
	})
	manager := NewTokenManager()
	for i := 0; i < 3; i++ {
		snapshot, err := manager.Get(context.Background(), configDir, "")
		if err != nil || snapshot.AccessToken != "fresh" {
			t.Fatalf("Get(%d) = %#v, %v", i, snapshot, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
}

func TestTokenManagerDoesNotCacheInsideRefreshWindow(t *testing.T) {
	configDir := t.TempDir()
	writeTokenManagerMarker(t, configDir, 1)
	var calls atomic.Int32
	installTokenManagerProvider(t, func(string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			calls.Add(1)
			return managerToken("near-expiry", time.Now().Add(4*time.Minute), 1), nil
		}}
	})
	manager := NewTokenManager()
	if _, err := manager.Get(context.Background(), configDir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Get(context.Background(), configDir, ""); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2", got)
	}
}

func TestTokenManagerMarkerChangeInvalidatesLongRunningSnapshot(t *testing.T) {
	configDir := t.TempDir()
	writeTokenManagerMarker(t, configDir, 1)
	var calls atomic.Int32
	installTokenManagerProvider(t, func(string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			call := calls.Add(1)
			return managerToken(fmt.Sprintf("token-%d", call), time.Now().Add(time.Hour), uint64(call)), nil
		}}
	})
	manager := NewTokenManager()
	first, err := manager.Get(context.Background(), configDir, "")
	if err != nil || first.AccessToken != "token-1" {
		t.Fatalf("first Get = %#v, %v", first, err)
	}
	writeTokenManagerMarker(t, configDir, 2)
	second, err := manager.Get(context.Background(), configDir, "")
	if err != nil || second.AccessToken != "token-2" {
		t.Fatalf("second Get = %#v, %v", second, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2", got)
	}
}

func TestTokenManagerRetriesWhenMarkerChangesDuringBlobRead(t *testing.T) {
	configDir := t.TempDir()
	writeTokenManagerMarker(t, configDir, 1)
	var calls atomic.Int32
	installTokenManagerProvider(t, func(string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			if calls.Add(1) == 1 {
				writeTokenManagerMarker(t, configDir, 2)
				return managerToken("stale-token", time.Now().Add(time.Hour), 1), nil
			}
			return managerToken("published-token", time.Now().Add(time.Hour), 2), nil
		}}
	})
	snapshot, err := NewTokenManager().Get(context.Background(), configDir, "")
	if err != nil || snapshot.AccessToken != "published-token" || snapshot.ObservedGeneration != 2 {
		t.Fatalf("stable Get = %#v, %v", snapshot, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2", got)
	}
}

func TestTokenManagerSerializesConcurrentResolutionPerConfigAndProfile(t *testing.T) {
	configDir := t.TempDir()
	writeTokenManagerMarker(t, configDir, 1)
	var calls atomic.Int32
	installTokenManagerProvider(t, func(string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			calls.Add(1)
			time.Sleep(15 * time.Millisecond)
			return managerToken("shared", time.Now().Add(time.Hour), 1), nil
		}}
	})
	manager := NewTokenManager()
	const callers = 20
	start := make(chan struct{})
	errCh := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			snapshot, err := manager.Get(context.Background(), configDir, "")
			if err == nil && snapshot.AccessToken != "shared" {
				err = fmt.Errorf("token = %q", snapshot.AccessToken)
			}
			errCh <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
}

func TestTokenManagerIsolatesConfigDirectoryAndProfile(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	writeTokenManagerMarker(t, dirA, 1)
	writeTokenManagerMarker(t, dirB, 1)
	counts := map[string]int{}
	var countsMu sync.Mutex
	installTokenManagerProvider(t, func(configDir string) accessTokenGetter {
		profile := authpkg.RuntimeProfile()
		key := filepath.Clean(configDir) + "|" + profile
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			countsMu.Lock()
			counts[key]++
			countsMu.Unlock()
			return managerToken(key, time.Now().Add(time.Hour), 1), nil
		}}
	})
	manager := NewTokenManager()

	first, err := manager.Get(context.Background(), dirA, "")
	if err != nil {
		t.Fatal(err)
	}
	authpkg.SetRuntimeProfile("profile-b")
	second, err := manager.Get(context.Background(), dirA, "")
	if err != nil {
		t.Fatal(err)
	}
	third, err := manager.Get(context.Background(), dirB, "")
	if err != nil {
		t.Fatal(err)
	}
	authpkg.SetRuntimeProfile("")
	again, err := manager.Get(context.Background(), dirA, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.AccessToken == second.AccessToken || second.AccessToken == third.AccessToken || again.AccessToken != first.AccessToken {
		t.Fatalf("isolation tokens: first=%q second=%q third=%q again=%q", first.AccessToken, second.AccessToken, third.AccessToken, again.AccessToken)
	}
	countsMu.Lock()
	defer countsMu.Unlock()
	for key, count := range counts {
		if count != 1 {
			t.Fatalf("provider calls for %q = %d, want 1", key, count)
		}
	}
}

func TestTokenManagerPreservesProviderErrorCause(t *testing.T) {
	configDir := t.TempDir()
	writeTokenManagerMarker(t, configDir, 1)
	sentinel := errors.New("key store unavailable")
	installTokenManagerProvider(t, func(string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			return nil, &os.PathError{Op: "read", Path: "credential", Err: sentinel}
		}}
	})
	_, err := NewTokenManager().Get(context.Background(), configDir, "")
	if !errors.Is(err, sentinel) {
		t.Fatalf("Get() error = %v, want sentinel in chain", err)
	}
}

func TestTokenManagerDefaultProfileObservesCrossProcessSelectionPublication(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv(keychain.DisableKeychainEnv, "1")
	t.Setenv("DWS_CONFIG_DIR", configDir)
	previousHooks := edition.Get()
	previousProfile := authpkg.RuntimeProfile()
	edition.Override(&edition.Hooks{})
	authpkg.SetRuntimeProfile("")
	t.Cleanup(func() {
		edition.Override(previousHooks)
		authpkg.SetRuntimeProfile(previousProfile)
		ResetRuntimeTokenCache()
	})

	profileToken := func(corpID, userID, accessToken string) *authpkg.TokenData {
		return &authpkg.TokenData{
			AccessToken:  accessToken,
			RefreshToken: "refresh-" + accessToken,
			ExpiresAt:    time.Now().Add(time.Hour),
			RefreshExpAt: time.Now().Add(24 * time.Hour),
			CorpID:       corpID,
			UserID:       userID,
			ClientID:     "client",
		}
	}
	if err := authpkg.SaveTokenData(configDir, profileToken("corp-switch-a", "user-a", "token-a")); err != nil {
		t.Fatal(err)
	}
	authpkg.SetRuntimeProfile("corp-switch-b:user-b")
	if err := authpkg.SaveTokenData(configDir, profileToken("corp-switch-b", "user-b", "token-b")); err != nil {
		t.Fatal(err)
	}
	authpkg.SetRuntimeProfile("")

	manager := NewTokenManager()
	first, err := manager.Get(context.Background(), configDir, "")
	if err != nil || first.AccessToken != "token-a" {
		t.Fatalf("default profile before switch = %#v, %v", first, err)
	}
	beforeGeneration, present, err := authpkg.ReadTokenMarkerGeneration(configDir)
	if err != nil || !present {
		t.Fatalf("marker before switch = (%d, %v, %v)", beforeGeneration, present, err)
	}
	if _, err := authpkg.SetCurrentProfile(configDir, "corp-switch-b:user-b"); err != nil {
		t.Fatal(err)
	}
	afterGeneration, present, err := authpkg.ReadTokenMarkerGeneration(configDir)
	if err != nil || !present || afterGeneration <= beforeGeneration {
		t.Fatalf("marker after switch = (%d, %v, %v), want > %d", afterGeneration, present, err, beforeGeneration)
	}
	second, err := manager.Get(context.Background(), configDir, "")
	if err != nil || second.AccessToken != "token-b" {
		t.Fatalf("long-running manager after switch = %#v, %v", second, err)
	}
}

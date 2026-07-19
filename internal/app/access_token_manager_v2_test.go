package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

func installTokenManagerProvider(t *testing.T, factory func(string, string) accessTokenGetter) {
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
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
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
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
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
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
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

func TestTokenManagerDeleteReloginCannotReuseMissedGeneration(t *testing.T) {
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

	newToken := func(accessToken string) *authpkg.TokenData {
		return &authpkg.TokenData{
			AccessToken:  accessToken,
			RefreshToken: "refresh-" + accessToken,
			ExpiresAt:    time.Now().Add(time.Hour),
			RefreshExpAt: time.Now().Add(24 * time.Hour),
			CorpID:       "corp-aba",
			UserID:       "user-aba",
			ClientID:     "client-aba",
		}
	}

	firstData := newToken("token-before-logout")
	if err := authpkg.SaveTokenData(configDir, firstData); err != nil {
		t.Fatal(err)
	}
	manager := NewTokenManager()
	first, err := manager.Get(context.Background(), configDir, "")
	if err != nil || first.AccessToken != firstData.AccessToken {
		t.Fatalf("first Get = %#v, %v", first, err)
	}

	// Simulate another process logging out and back in while this long-running
	// manager is idle. It deliberately never observes token.json being absent.
	if err := authpkg.DeleteAllTokenData(configDir); err != nil {
		t.Fatal(err)
	}
	if _, present, err := authpkg.ReadTokenMarkerGeneration(configDir); err != nil || present {
		t.Fatalf("marker after logout = present %v, err %v", present, err)
	}
	secondData := newToken("token-after-relogin")
	if err := authpkg.SaveTokenData(configDir, secondData); err != nil {
		t.Fatal(err)
	}
	if secondData.Generation <= first.ObservedGeneration {
		t.Fatalf("re-login generation = %d, want > cached generation %d", secondData.Generation, first.ObservedGeneration)
	}

	second, err := manager.Get(context.Background(), configDir, "")
	if err != nil || second.AccessToken != secondData.AccessToken {
		t.Fatalf("Get after missed logout/re-login = %#v, %v", second, err)
	}
	if second.AccessToken == first.AccessToken {
		t.Fatal("long-running manager reused the pre-logout token")
	}
}

func TestTokenManagerMixedVersionLogoutCannotReuseGeneration(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv(keychain.DisableKeychainEnv, "1")
	t.Setenv("DWS_CONFIG_DIR", configDir)
	writeTokenManagerMarker(t, configDir, 1)
	current := managerToken("legacy-token", time.Now().Add(time.Hour), 1)
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			copy := *current
			return &copy, nil
		}}
	})

	manager := NewTokenManager()
	first, err := manager.Get(context.Background(), configDir, "")
	if err != nil || first.AccessToken != "legacy-token" || first.ObservedGeneration != 1 {
		t.Fatalf("legacy Get = %#v, %v", first, err)
	}

	// An older binary removes token.json and has no allocator to preserve. The
	// fixed binary's first login must seed a new publication epoch instead of
	// restarting the old 1, even though this manager never saw the absence.
	if err := os.Remove(filepath.Join(configDir, "token.json")); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(configDir, ".token-generation.json"))
	relogin := &authpkg.TokenData{
		AccessToken:  "fixed-token",
		RefreshToken: "fixed-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
		RefreshExpAt: time.Now().Add(24 * time.Hour),
		CorpID:       "corp-mixed-version",
		UserID:       "user-mixed-version",
		ClientID:     "client-mixed-version",
	}
	if err := authpkg.SaveTokenData(configDir, relogin); err != nil {
		t.Fatal(err)
	}
	if relogin.Generation == first.ObservedGeneration {
		t.Fatalf("mixed-version re-login reused generation %d", relogin.Generation)
	}
	current = managerToken(relogin.AccessToken, relogin.ExpiresAt, relogin.Generation)

	second, err := manager.Get(context.Background(), configDir, "")
	if err != nil || second.AccessToken != relogin.AccessToken {
		t.Fatalf("Get after mixed-version logout/re-login = %#v, %v", second, err)
	}
}

func TestTokenManagerRetriesWhenMarkerChangesDuringBlobRead(t *testing.T) {
	configDir := t.TempDir()
	writeTokenManagerMarker(t, configDir, 1)
	var calls atomic.Int32
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
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
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
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

func TestTokenManagerCoalescesConcurrentTransientFailures(t *testing.T) {
	configDir := t.TempDir()
	writeTokenManagerMarker(t, configDir, 1)
	sentinel := errors.New("token-secret-uid-4496576595")
	var calls atomic.Int32
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			calls.Add(1)
			time.Sleep(15 * time.Millisecond)
			return nil, errors.Join(sentinel, &authpkg.OAuthEndpointError{StatusCode: http.StatusServiceUnavailable})
		}}
	})
	manager := NewTokenManager()
	base := time.Unix(100, 0)
	manager.now = func() time.Time { return base }

	const callers = 100
	start := make(chan struct{})
	errCh := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := manager.Get(context.Background(), configDir, "")
			errCh <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if !errors.Is(err, sentinel) {
			t.Fatalf("Get() error = %v, want shared sentinel cause", err)
		}
		if strings.Contains(err.Error(), "4496576595") || strings.Contains(err.Error(), "token-secret") {
			t.Fatalf("cached failure exposed raw cause: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
}

func TestTokenManagerTransientFailureRetriesAfterCooldown(t *testing.T) {
	configDir := t.TempDir()
	writeTokenManagerMarker(t, configDir, 7)
	sentinel := errors.New("transient refresh sentinel")
	var calls atomic.Int32
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			calls.Add(1)
			return nil, errors.Join(sentinel, &authpkg.OAuthEndpointError{StatusCode: http.StatusTooManyRequests})
		}}
	})
	manager := NewTokenManager()
	base := time.Unix(200, 0)
	current := base
	manager.now = func() time.Time { return current }

	if _, err := manager.Get(context.Background(), configDir, ""); !errors.Is(err, sentinel) {
		t.Fatalf("first Get() error = %v", err)
	}
	if _, err := manager.Get(context.Background(), configDir, ""); !errors.Is(err, sentinel) {
		t.Fatalf("cooldown Get() error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls inside cooldown = %d, want 1", got)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.Get(canceled, configDir, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Get() error = %v, want context canceled", err)
	}
	current = base.Add(tokenFailureInitialBackoff)
	if _, err := manager.Get(context.Background(), configDir, ""); !errors.Is(err, sentinel) {
		t.Fatalf("post-cooldown Get() error = %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("provider calls after cooldown = %d, want 2", got)
	}
}

func TestTokenManagerMarkerChangeBypassesTransientFailureCooldown(t *testing.T) {
	configDir := t.TempDir()
	writeTokenManagerMarker(t, configDir, 11)
	sentinel := errors.New("transient refresh sentinel")
	var calls atomic.Int32
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			calls.Add(1)
			return nil, errors.Join(sentinel, &authpkg.OAuthEndpointError{StatusCode: http.StatusInternalServerError})
		}}
	})
	manager := NewTokenManager()
	manager.now = func() time.Time { return time.Unix(300, 0) }
	if _, err := manager.Get(context.Background(), configDir, ""); !errors.Is(err, sentinel) {
		t.Fatalf("first Get() error = %v", err)
	}
	writeTokenManagerMarker(t, configDir, 12)
	if _, err := manager.Get(context.Background(), configDir, ""); !errors.Is(err, sentinel) {
		t.Fatalf("marker-change Get() error = %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("provider calls after marker change = %d, want 2", got)
	}
}

func TestTokenManagerIsolatesConfigDirectoryAndProfile(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	for _, dir := range []string{dirA, dirB} {
		if err := authpkg.SaveProfiles(dir, &authpkg.ProfilesConfig{
			Version:  2,
			Profiles: []authpkg.Profile{{Name: "profile-b", CorpID: "corp-b", UserID: "user-b"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	writeTokenManagerMarker(t, dirA, 1)
	writeTokenManagerMarker(t, dirB, 1)
	counts := map[string]int{}
	var countsMu sync.Mutex
	installTokenManagerProvider(t, func(configDir, profile string) accessTokenGetter {
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
	installTokenManagerProvider(t, func(string, string) accessTokenGetter {
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
	if first.profile != "corp-switch-a:user-a" || !first.profilePinned {
		t.Fatalf("default profile lease = %q pinned=%v", first.profile, first.profilePinned)
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

func TestTokenManagerPinsLoaderToKeyAcrossConcurrentRuntimeProfileSwitch(t *testing.T) {
	configDir := t.TempDir()
	if err := authpkg.SaveProfiles(configDir, &authpkg.ProfilesConfig{
		Version: 2,
		Profiles: []authpkg.Profile{
			{Name: "profile-a", CorpID: "corp-a", UserID: "user-a"},
			{Name: "profile-b", CorpID: "corp-b", UserID: "user-b"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	writeTokenManagerMarker(t, configDir, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	installTokenManagerProvider(t, func(_ string, profile string) accessTokenGetter {
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			calls.Add(1)
			close(started)
			<-release
			return managerToken("token-for-"+profile, time.Now().Add(time.Hour), 1), nil
		}}
	})
	authpkg.SetRuntimeProfile("profile-a")
	manager := NewTokenManager()
	type result struct {
		snapshot AccessTokenSnapshot
		err      error
	}
	done := make(chan result, 1)
	go func() {
		snapshot, err := manager.Get(context.Background(), configDir, "")
		done <- result{snapshot: snapshot, err: err}
	}()
	<-started
	authpkg.SetRuntimeProfile("profile-b")
	close(release)
	first := <-done
	if first.err != nil || first.snapshot.AccessToken != "token-for-corp-a:user-a" {
		t.Fatalf("in-flight profile-a resolution = %#v, %v", first.snapshot, first.err)
	}
	authpkg.SetRuntimeProfile("profile-a")
	again, err := manager.Get(context.Background(), configDir, "")
	if err != nil || again.AccessToken != "token-for-corp-a:user-a" {
		t.Fatalf("cached profile-a resolution = %#v, %v", again, err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("provider calls = %d, want 1", got)
	}
}

func TestResolveAuxiliaryAccessTokenSnapshotForProfileCanonicalizesAlias(t *testing.T) {
	configDir := t.TempDir()
	if err := authpkg.SaveProfiles(configDir, &authpkg.ProfilesConfig{
		Version:        2,
		CurrentProfile: "corp-a:user-a",
		Profiles: []authpkg.Profile{{
			Name: "friendly-a", CorpID: "corp-a", UserID: "user-a",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	writeTokenManagerMarker(t, configDir, 1)
	var providerProfile string
	installTokenManagerProvider(t, func(_ string, profile string) accessTokenGetter {
		providerProfile = profile
		return fakeSnapshotProvider{get: func(context.Context) (*authpkg.TokenData, error) {
			return managerToken("alias-token", time.Now().Add(time.Hour), 1), nil
		}}
	})
	previousManager := runtimeTokenManager
	runtimeTokenManager = NewTokenManager()
	t.Cleanup(func() { runtimeTokenManager = previousManager })

	snapshot, err := ResolveAuxiliaryAccessTokenSnapshotForProfile(context.Background(), configDir, "", "friendly-a")
	if err != nil || snapshot.AccessToken != "alias-token" {
		t.Fatalf("alias facade = %#v, %v", snapshot, err)
	}
	if providerProfile != "corp-a:user-a" || snapshot.profile != "corp-a:user-a" {
		t.Fatalf("provider=%q snapshot lease=%q", providerProfile, snapshot.profile)
	}
}

func TestPassiveRefreshUsesSnapshotProfileAfterRuntimeSwitch(t *testing.T) {
	originalFactory := newRejectedTokenRefresher
	originalProfile := authpkg.RuntimeProfile()
	t.Cleanup(func() {
		newRejectedTokenRefresher = originalFactory
		authpkg.SetRuntimeProfile(originalProfile)
	})
	gotProfile := ""
	newRejectedTokenRefresher = func(_ string, profile string) rejectedTokenRefresher {
		gotProfile = profile
		return fakeRejectedTokenRefresher{token: "rotated"}
	}
	authpkg.SetRuntimeProfile("profile-b")
	rejected := AccessTokenSnapshot{
		AccessToken:   "rejected",
		Generation:    9,
		profile:       "profile-a",
		profilePinned: true,
	}
	got, err := forceRefreshRejectedTokenForSnapshot(context.Background(), t.TempDir(), rejected)
	if err != nil || got != "rotated" {
		t.Fatalf("profile-pinned refresh = %q, %v", got, err)
	}
	if gotProfile != "profile-a" {
		t.Fatalf("refresh factory profile = %q, want profile-a", gotProfile)
	}
}

func TestPublicSnapshotRecoveryDeletesOnlyTerminalCredential(t *testing.T) {
	configDir := t.TempDir()
	previousHooks := edition.Get()
	previousProfile := authpkg.RuntimeProfile()
	previousForce := forceRefreshRejectedTokenForProfileFunc
	var storeMu sync.Mutex
	store := make(map[string][]byte)
	edition.Override(&edition.Hooks{TokenStoreV2: &edition.TokenStoreV2Hooks{
		Save: func(_, profile string, blob []byte) error {
			storeMu.Lock()
			defer storeMu.Unlock()
			store[profile] = append([]byte(nil), blob...)
			return nil
		},
		Load: func(_, profile string) ([]byte, error) {
			storeMu.Lock()
			defer storeMu.Unlock()
			blob, ok := store[profile]
			if !ok {
				return nil, authpkg.ErrTokenDataNotFound
			}
			return append([]byte(nil), blob...), nil
		},
		Delete: func(_, profile string) error {
			storeMu.Lock()
			defer storeMu.Unlock()
			delete(store, profile)
			return nil
		},
	}})
	t.Cleanup(func() {
		edition.Override(previousHooks)
		authpkg.SetRuntimeProfile(previousProfile)
		forceRefreshRejectedTokenForProfileFunc = previousForce
	})
	profile := "corp-a:user-a"
	authpkg.SetRuntimeProfile(profile)
	seed := func(access string) *authpkg.TokenData {
		return &authpkg.TokenData{
			AccessToken:  access,
			RefreshToken: "refresh-" + access,
			ExpiresAt:    time.Now().Add(time.Hour),
			RefreshExpAt: time.Now().Add(24 * time.Hour),
			ClientID:     "client",
			CorpID:       "corp-a",
			UserID:       "user-a",
		}
	}

	terminalData := seed("terminal-token")
	if err := authpkg.SaveTokenData(configDir, terminalData); err != nil {
		t.Fatal(err)
	}
	terminalCause := &authpkg.OAuthEndpointError{StatusCode: http.StatusBadRequest, Code: "invalid_grant"}
	forceRefreshRejectedTokenForProfileFunc = func(context.Context, string, string, string, ...uint64) (string, error) {
		return "", terminalCause
	}
	terminalSnapshot := AccessTokenSnapshot{
		AccessToken: terminalData.AccessToken, Generation: terminalData.Generation,
		Source: "oauth", profile: profile, profilePinned: true,
	}
	if _, err := RefreshRejectedAccessTokenSnapshot(context.Background(), configDir, terminalSnapshot); !errors.Is(err, terminalCause) {
		t.Fatalf("terminal recovery error = %v", err)
	}
	if _, err := authpkg.LoadTokenDataForProfile(configDir, profile); !errors.Is(err, authpkg.ErrTokenDataNotFound) {
		t.Fatalf("terminal credential still present: %v", err)
	}

	transientData := seed("transient-token")
	if err := authpkg.SaveTokenData(configDir, transientData); err != nil {
		t.Fatal(err)
	}
	forceRefreshRejectedTokenForProfileFunc = func(context.Context, string, string, string, ...uint64) (string, error) {
		return "", context.DeadlineExceeded
	}
	transientSnapshot := AccessTokenSnapshot{
		AccessToken: transientData.AccessToken, Generation: transientData.Generation,
		Source: "oauth", profile: profile, profilePinned: true,
	}
	if _, err := RefreshRejectedAccessTokenSnapshot(context.Background(), configDir, transientSnapshot); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("transient recovery error = %v", err)
	}
	stored, err := authpkg.LoadTokenDataForProfile(configDir, profile)
	if err != nil || stored.AccessToken != transientData.AccessToken {
		t.Fatalf("transient credential changed = %#v, %v", stored, err)
	}
}

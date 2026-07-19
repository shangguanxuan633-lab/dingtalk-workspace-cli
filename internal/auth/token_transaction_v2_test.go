package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

type memoryProfileTokenStoreV2 struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func (s *memoryProfileTokenStoreV2) hooks(preflight func(string, string) error) *edition.Hooks {
	if s.blobs == nil {
		s.blobs = make(map[string][]byte)
	}
	return &edition.Hooks{TokenStoreV2: &edition.TokenStoreV2Hooks{
		Preflight: preflight,
		Save: func(_, profile string, data []byte) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.blobs[profile] = append([]byte(nil), data...)
			return nil
		},
		Load: func(_, profile string) ([]byte, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			blob, ok := s.blobs[profile]
			if !ok {
				return nil, ErrTokenDataNotFound
			}
			return append([]byte(nil), blob...), nil
		},
		Delete: func(_, profile string) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			delete(s.blobs, profile)
			return nil
		},
	}}
}

func v2ProfileToken(corpID, userID, access string) *TokenData {
	data := rejectedTokenData(access)
	data.CorpID = corpID
	data.UserID = userID
	data.CorpName = corpID + " name"
	data.UserName = userID + " name"
	return data
}

func TestEditionTokenStorePreflightRequiresCompleteTransactionHooks(t *testing.T) {
	previous := edition.Get()
	edition.Override(&edition.Hooks{SaveToken: func(string, []byte) error { return nil }})
	t.Cleanup(func() { edition.Override(previous) })

	if err := preflightTokenPersistence(t.TempDir()); err == nil || !strings.Contains(err.Error(), "SaveToken, LoadToken, and DeleteToken") {
		t.Fatalf("preflightTokenPersistence() error = %v", err)
	}
	if err := preflightTokenRefreshPersistence(t.TempDir(), rejectedTokenData("old")); err == nil || !strings.Contains(err.Error(), "SaveToken, LoadToken, and DeleteToken") {
		t.Fatalf("preflightTokenRefreshPersistence() error = %v", err)
	}
	data := rejectedTokenData("new")
	if err := SaveTokenData(t.TempDir(), data); err == nil {
		t.Fatal("SaveTokenData() accepted an incomplete edition store")
	}
	if data.Generation != 0 {
		t.Fatalf("failed SaveTokenData mutated caller generation to %d", data.Generation)
	}
}

func TestEditionTokenStoreV2RequiresCompleteTransactionHooks(t *testing.T) {
	previous := edition.Get()
	edition.Override(&edition.Hooks{TokenStoreV2: &edition.TokenStoreV2Hooks{
		Save: func(string, string, []byte) error { return nil },
	}})
	t.Cleanup(func() { edition.Override(previous) })
	if err := preflightTokenPersistence(t.TempDir()); err == nil || !strings.Contains(err.Error(), "TokenStoreV2 must provide Save, Load, and Delete") {
		t.Fatalf("incomplete TokenStoreV2 preflight error = %v", err)
	}
}

func TestGenerationAllocatorSurvivesLogoutFromLegacyMarker(t *testing.T) {
	previous := edition.Get()
	previousProfile := RuntimeProfile()
	store := &memoryProfileTokenStoreV2{}
	edition.Override(store.hooks(nil))
	SetRuntimeProfile("")
	t.Cleanup(func() {
		edition.Override(previous)
		SetRuntimeProfile(previousProfile)
	})
	configDir := t.TempDir()

	first := v2ProfileToken("corp-epoch", "user-epoch", "token-before-logout")
	if err := SaveTokenData(configDir, first); err != nil {
		t.Fatal(err)
	}
	// Simulate an installation upgraded from a build that had generation in
	// token.json but no durable allocator yet.
	if err := os.Remove(filepath.Join(configDir, tokenGenerationFile)); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAllTokenData(configDir); err != nil {
		t.Fatal(err)
	}
	if _, present, err := ReadTokenMarkerGeneration(configDir); err != nil || present {
		t.Fatalf("marker after logout = present %v, err %v", present, err)
	}
	remembered, exists, err := readTokenGeneration(configDir)
	if err != nil || !exists || remembered < first.Generation {
		t.Fatalf("allocator after logout = (%d, %v, %v), want >= %d", remembered, exists, err, first.Generation)
	}

	second := v2ProfileToken("corp-epoch", "user-epoch", "token-after-relogin")
	if err := SaveTokenData(configDir, second); err != nil {
		t.Fatal(err)
	}
	if second.Generation <= first.Generation {
		t.Fatalf("re-login generation = %d, want > %d", second.Generation, first.Generation)
	}
}

func TestGenerationAllocatorDoesNotRollBackFailedReservation(t *testing.T) {
	previous := edition.Get()
	previousProfile := RuntimeProfile()
	store := &memoryProfileTokenStoreV2{}
	edition.Override(store.hooks(nil))
	SetRuntimeProfile("")
	t.Cleanup(func() {
		edition.Override(previous)
		SetRuntimeProfile(previousProfile)
	})
	configDir := t.TempDir()

	first := v2ProfileToken("corp-gap", "user-gap", "token-a")
	if err := SaveTokenData(configDir, first); err != nil {
		t.Fatal(err)
	}
	originalWriteMarker := tokenWriteMarkerGeneration
	sentinel := errors.New("injected marker publication failure")
	tokenWriteMarkerGeneration = func(string, bool, uint64) error { return sentinel }
	t.Cleanup(func() { tokenWriteMarkerGeneration = originalWriteMarker })
	failed := v2ProfileToken("corp-gap", "user-gap", "token-b")
	if err := SaveTokenData(configDir, failed); !errors.Is(err, sentinel) {
		t.Fatalf("failed SaveTokenData() error = %v, want %v", err, sentinel)
	}
	if failed.Generation != 0 {
		t.Fatalf("failed save mutated caller generation to %d", failed.Generation)
	}
	reserved, exists, err := readTokenGeneration(configDir)
	if err != nil || !exists || reserved <= first.Generation {
		t.Fatalf("reserved generation = (%d, %v, %v), want > %d", reserved, exists, err, first.Generation)
	}

	tokenWriteMarkerGeneration = originalWriteMarker
	third := v2ProfileToken("corp-gap", "user-gap", "token-c")
	if err := SaveTokenData(configDir, third); err != nil {
		t.Fatal(err)
	}
	if third.Generation <= reserved {
		t.Fatalf("generation after failed reservation = %d, want > %d", third.Generation, reserved)
	}
}

func TestCorruptGenerationAllocatorDoesNotPermanentlyBlockResetOrLogin(t *testing.T) {
	previous := edition.Get()
	previousProfile := RuntimeProfile()
	store := &memoryProfileTokenStoreV2{}
	edition.Override(store.hooks(nil))
	SetRuntimeProfile("")
	t.Cleanup(func() {
		edition.Override(previous)
		SetRuntimeProfile(previousProfile)
	})
	configDir := t.TempDir()

	first := v2ProfileToken("corp-repair", "user-repair", "token-before-corruption")
	if err := SaveTokenData(configDir, first); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, tokenGenerationFile), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAllTokenData(configDir); err != nil {
		t.Fatalf("auth reset with corrupt allocator: %v", err)
	}
	if _, present, err := ReadTokenMarkerGeneration(configDir); err != nil || present {
		t.Fatalf("marker after repaired reset = present %v, err %v", present, err)
	}
	repaired, exists, err := readTokenGeneration(configDir)
	if err != nil || !exists || repaired == 0 {
		t.Fatalf("repaired allocator = (%d, %v, %v)", repaired, exists, err)
	}

	second := v2ProfileToken("corp-repair", "user-repair", "token-after-corruption")
	if err := SaveTokenData(configDir, second); err != nil {
		t.Fatalf("login after repaired reset: %v", err)
	}
	if second.Generation <= repaired {
		t.Fatalf("generation after repair = %d, want > %d", second.Generation, repaired)
	}
}

func TestEditionTokenStoreV2IsolatesProfilesAndPublishesDeletion(t *testing.T) {
	previous := edition.Get()
	previousProfile := RuntimeProfile()
	store := &memoryProfileTokenStoreV2{}
	var preflightProfile string
	edition.Override(store.hooks(func(_, profile string) error {
		preflightProfile = profile
		return nil
	}))
	t.Cleanup(func() {
		edition.Override(previous)
		SetRuntimeProfile(previousProfile)
	})
	configDir := t.TempDir()

	SetRuntimeProfile("corp-a")
	dataA := v2ProfileToken("corp-a", "user-a", "token-a")
	if err := SaveTokenData(configDir, dataA); err != nil {
		t.Fatal(err)
	}
	SetRuntimeProfile("corp-b")
	dataB := v2ProfileToken("corp-b", "user-b", "token-b")
	if err := SaveTokenData(configDir, dataB); err != nil {
		t.Fatal(err)
	}
	if dataB.Generation <= dataA.Generation {
		t.Fatalf("generations A=%d B=%d", dataA.Generation, dataB.Generation)
	}

	loadedA, err := LoadTokenDataForProfile(configDir, "corp-a:user-a")
	if err != nil || loadedA.AccessToken != "token-a" {
		t.Fatalf("profile A = %#v, %v", loadedA, err)
	}
	loadedB, err := LoadTokenDataForProfile(configDir, "corp-b:user-b")
	if err != nil || loadedB.AccessToken != "token-b" {
		t.Fatalf("profile B = %#v, %v", loadedB, err)
	}
	if err := preflightTokenRefreshPersistenceForProfile(configDir, "corp-a:user-a", loadedA); err != nil {
		t.Fatal(err)
	}
	if preflightProfile != "corp-a:user-a" {
		t.Fatalf("preflight profile = %q", preflightProfile)
	}

	beforeDelete, present, err := ReadTokenMarkerGeneration(configDir)
	if err != nil || !present {
		t.Fatalf("marker before delete = (%d, %v, %v)", beforeDelete, present, err)
	}
	if err := DeleteTokenDataForProfile(configDir, "corp-a:user-a"); err != nil {
		t.Fatal(err)
	}
	afterDelete, present, err := ReadTokenMarkerGeneration(configDir)
	if err != nil || !present || afterDelete <= beforeDelete {
		t.Fatalf("marker after delete = (%d, %v, %v), want > %d", afterDelete, present, err, beforeDelete)
	}
	if _, err := LoadTokenDataForProfile(configDir, "corp-a:user-a"); !errors.Is(err, ErrTokenDataNotFound) {
		t.Fatalf("deleted profile A load error = %v", err)
	}
	loadedB, err = LoadTokenDataForProfile(configDir, "corp-b:user-b")
	if err != nil || loadedB.AccessToken != "token-b" {
		t.Fatalf("profile B after deleting A = %#v, %v", loadedB, err)
	}
}

func TestEditionTokenStoreV2PreflightBlocksRejectedRefreshBeforeOAuth(t *testing.T) {
	previous := edition.Get()
	previousProfile := RuntimeProfile()
	previousRefresh := oauthRefreshToken
	store := &memoryProfileTokenStoreV2{}
	edition.Override(store.hooks(nil))
	t.Cleanup(func() {
		edition.Override(previous)
		SetRuntimeProfile(previousProfile)
		oauthRefreshToken = previousRefresh
	})
	configDir := t.TempDir()
	SetRuntimeProfile("corp-a")
	data := v2ProfileToken("corp-a", "user-a", "rejected")
	if err := SaveTokenData(configDir, data); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("profile store preflight failed")
	edition.Override(store.hooks(func(_, profile string) error {
		if profile != "corp-a:user-a" {
			t.Fatalf("preflight profile = %q", profile)
		}
		return sentinel
	}))
	var exchanges atomic.Int32
	oauthRefreshToken = func(*OAuthProvider, context.Context, *TokenData) (*TokenData, error) {
		exchanges.Add(1)
		return nil, errors.New("unexpected OAuth refresh")
	}
	provider := NewOAuthProviderForProfile(configDir, nil, "corp-a:user-a")
	if _, err := provider.ForceRefreshRejectedToken(context.Background(), data.AccessToken, data.Generation); !errors.Is(err, sentinel) {
		t.Fatalf("ForceRefreshRejectedToken() error = %v", err)
	}
	if got := exchanges.Load(); got != 0 {
		t.Fatalf("OAuth refresh exchanges = %d, want 0", got)
	}
}

func TestEditionTokenStoreV2ABProfileLifecycleAndPinnedRefresh(t *testing.T) {
	previous := edition.Get()
	previousProfile := RuntimeProfile()
	previousRefresh := oauthRefreshToken
	store := &memoryProfileTokenStoreV2{}
	edition.Override(store.hooks(nil))
	t.Cleanup(func() {
		edition.Override(previous)
		SetRuntimeProfile(previousProfile)
		oauthRefreshToken = previousRefresh
	})
	configDir := t.TempDir()

	SetRuntimeProfile("ding-a")
	a := v2ProfileToken("ding-a", "user-a", "a-old")
	if err := SaveTokenData(configDir, a); err != nil {
		t.Fatal(err)
	}
	SetRuntimeProfile("ding-b")
	b := v2ProfileToken("ding-b", "user-b", "b-stable")
	if err := SaveTokenData(configDir, b); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	_, hasAExact := store.blobs["ding-a:user-a"]
	_, hasBExact := store.blobs["ding-b:user-b"]
	_, hasARaw := store.blobs["ding-a"]
	_, hasBRaw := store.blobs["ding-b"]
	store.mu.Unlock()
	if !hasAExact || !hasBExact || hasARaw || hasBRaw {
		t.Fatalf("store keys exact=(%v,%v) raw=(%v,%v)", hasAExact, hasBExact, hasARaw, hasBRaw)
	}
	profiles, err := LoadProfiles(configDir)
	if err != nil || len(profiles.Profiles) != 2 {
		t.Fatalf("profiles after A/B login = %#v, %v", profiles, err)
	}
	if _, err := SetCurrentProfile(configDir, "ding-b"); err != nil {
		t.Fatal(err)
	}
	selected, err := LoadTokenDataForProfile(configDir, "")
	if err != nil || selected.AccessToken != "b-stable" {
		t.Fatalf("selected B token = %#v, %v", selected, err)
	}

	var refreshedProfile string
	oauthRefreshToken = func(p *OAuthProvider, _ context.Context, current *TokenData) (*TokenData, error) {
		refreshedProfile = p.runtimeProfile()
		out := *current
		out.AccessToken = "a-new"
		out.ExpiresAt = time.Now().Add(time.Hour)
		if err := saveTokenDataLockedForProfile(p.configDir, p.runtimeProfile(), &out); err != nil {
			return nil, err
		}
		return &out, nil
	}
	providerA := NewOAuthProviderForProfile(configDir, nil, "ding-a:user-a")
	if got, err := providerA.ForceRefreshRejectedToken(context.Background(), "a-old", a.Generation); err != nil || got != "a-new" {
		t.Fatalf("refresh A = %q, %v", got, err)
	}
	if refreshedProfile != "ding-a:user-a" {
		t.Fatalf("refresh lease = %q", refreshedProfile)
	}
	loadedB, err := LoadTokenDataForProfile(configDir, "ding-b:user-b")
	if err != nil || loadedB.AccessToken != "b-stable" {
		t.Fatalf("B changed during A refresh = %#v, %v", loadedB, err)
	}
}

func TestEditionTokenStoreV2ExpiredSnapshotRefreshesThroughLockedHookLoader(t *testing.T) {
	previous := edition.Get()
	previousProfile := RuntimeProfile()
	previousRefresh := oauthRefreshToken
	store := &memoryProfileTokenStoreV2{}
	edition.Override(store.hooks(nil))
	t.Cleanup(func() {
		edition.Override(previous)
		SetRuntimeProfile(previousProfile)
		oauthRefreshToken = previousRefresh
	})
	configDir := t.TempDir()
	SetRuntimeProfile("ding-a")
	expired := v2ProfileToken("ding-a", "user-a", "old")
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	if err := SaveTokenData(configDir, expired); err != nil {
		t.Fatal(err)
	}
	var refreshes atomic.Int32
	oauthRefreshToken = func(p *OAuthProvider, _ context.Context, current *TokenData) (*TokenData, error) {
		refreshes.Add(1)
		updated := *current
		updated.AccessToken = "new"
		updated.RefreshToken = "refresh-new"
		updated.ExpiresAt = time.Now().Add(time.Hour)
		if err := saveTokenDataLockedForProfile(p.configDir, p.runtimeProfile(), &updated); err != nil {
			return nil, err
		}
		return &updated, nil
	}
	provider := NewOAuthProviderForProfile(configDir, nil, "ding-a:user-a")
	snapshot, err := provider.GetTokenSnapshot(context.Background())
	if err != nil || snapshot.AccessToken != "new" {
		t.Fatalf("GetTokenSnapshot() = %#v, %v", snapshot, err)
	}
	if refreshes.Load() != 1 {
		t.Fatalf("refreshes = %d", refreshes.Load())
	}
	store.mu.Lock()
	blob := append([]byte(nil), store.blobs["ding-a:user-a"]...)
	store.mu.Unlock()
	persisted, err := parseEditionTokenBlob(blob)
	if err != nil || persisted.AccessToken != "new" {
		t.Fatalf("persisted refreshed blob = %#v, %v", persisted, err)
	}
}

func TestEditionTokenStoreV2MigratesLegacyEmptyOAuthSlot(t *testing.T) {
	previous := edition.Get()
	store := &memoryProfileTokenStoreV2{}
	edition.Override(store.hooks(nil))
	t.Cleanup(func() { edition.Override(previous) })
	configDir := t.TempDir()
	legacy := v2ProfileToken("ding-a", "user-a", "legacy-a")
	blob, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	store.blobs[""] = blob
	if err := tokenWriteMarkerGeneration(configDir, false, 1); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadTokenDataForProfile(configDir, "")
	if err != nil || loaded.AccessToken != "legacy-a" {
		t.Fatalf("legacy load = %#v, %v", loaded, err)
	}
	store.mu.Lock()
	_, exactExists := store.blobs["ding-a:user-a"]
	_, emptyExists := store.blobs[""]
	store.mu.Unlock()
	if !exactExists || emptyExists {
		t.Fatalf("migration exact=%v empty=%v", exactExists, emptyExists)
	}
	profiles, err := LoadProfiles(configDir)
	if err != nil || profiles.CurrentProfile != "ding-a:user-a" || len(profiles.Profiles) != 1 {
		t.Fatalf("migrated profiles = %#v, %v", profiles, err)
	}
}

func TestEditionTokenStoreV2MigratesCurrentMetadataFromLegacyEmptySlot(t *testing.T) {
	previous := edition.Get()
	store := &memoryProfileTokenStoreV2{}
	edition.Override(store.hooks(nil))
	t.Cleanup(func() { edition.Override(previous) })
	configDir := t.TempDir()
	legacy := v2ProfileToken("ding-a", "user-a", "legacy-a")
	if err := SaveProfiles(configDir, &ProfilesConfig{
		Version:        profilesVersion,
		CurrentProfile: "ding-a:user-a",
		Profiles: []Profile{{
			Name: "alias-a", CorpID: "ding-a", UserID: "user-a", Status: ProfileStatusActive,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(legacy)
	store.blobs[""] = blob
	if err := tokenWriteMarkerGeneration(configDir, false, 1); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTokenDataForProfile(configDir, "alias-a")
	if err != nil || loaded.AccessToken != "legacy-a" {
		t.Fatalf("metadata migration load = %#v, %v", loaded, err)
	}
	store.mu.Lock()
	_, exactExists := store.blobs["ding-a:user-a"]
	_, emptyExists := store.blobs[""]
	store.mu.Unlock()
	if !exactExists || emptyExists {
		t.Fatalf("metadata migration exact=%v empty=%v", exactExists, emptyExists)
	}
}

func TestEditionTokenStoreV2ManualTokenOverridesAndSurvivesSelectiveLogout(t *testing.T) {
	previous := edition.Get()
	previousProfile := RuntimeProfile()
	store := &memoryProfileTokenStoreV2{}
	edition.Override(store.hooks(nil))
	t.Cleanup(func() {
		edition.Override(previous)
		SetRuntimeProfile(previousProfile)
	})
	configDir := t.TempDir()
	SetRuntimeProfile("")
	if err := SaveTokenData(configDir, v2ProfileToken("ding-a", "user-a", "oauth-a")); err != nil {
		t.Fatal(err)
	}
	manual := rejectedTokenData("manual")
	manual.RefreshToken = ""
	manual.RefreshExpAt = time.Time{}
	if err := SaveTokenData(configDir, manual); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTokenDataForProfile(configDir, "")
	if err != nil || loaded.AccessToken != "manual" {
		t.Fatalf("manual default = %#v, %v", loaded, err)
	}
	if err := DeleteTokenDataForProfile(configDir, "ding-a:user-a"); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadTokenDataForProfile(configDir, "")
	if err != nil || loaded.AccessToken != "manual" {
		t.Fatalf("manual after selective logout = %#v, %v", loaded, err)
	}
	manualMarker, err := manualTokenMarkerActive(configDir)
	if err != nil || !manualMarker {
		t.Fatalf("manual marker = %v, %v", manualMarker, err)
	}
}

func TestEditionTokenStoreV2LogoutAllSweepsKnownAndOrphanSlots(t *testing.T) {
	previous := edition.Get()
	previousProfile := RuntimeProfile()
	store := &memoryProfileTokenStoreV2{}
	hooks := store.hooks(nil)
	hooks.TokenStoreV2.DeleteAll = func(string) error {
		store.mu.Lock()
		defer store.mu.Unlock()
		clear(store.blobs)
		return nil
	}
	edition.Override(hooks)
	t.Cleanup(func() {
		edition.Override(previous)
		SetRuntimeProfile(previousProfile)
	})
	configDir := t.TempDir()
	SetRuntimeProfile("ding-a")
	if err := SaveTokenData(configDir, v2ProfileToken("ding-a", "user-a", "a")); err != nil {
		t.Fatal(err)
	}
	SetRuntimeProfile("ding-b")
	if err := SaveTokenData(configDir, v2ProfileToken("ding-b", "user-b", "b")); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.blobs["old-raw-alias"] = []byte(`{"access_token":"orphan"}`)
	store.mu.Unlock()
	if err := DeleteAllTokenData(configDir); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	remaining := len(store.blobs)
	store.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("remaining token blobs = %d", remaining)
	}
	profiles, err := LoadProfiles(configDir)
	if err != nil || len(profiles.Profiles) != 0 || profiles.CurrentProfile != "" {
		t.Fatalf("profiles after logout-all = %#v, %v", profiles, err)
	}
	if _, present, err := ReadTokenMarkerGeneration(configDir); err != nil || present {
		t.Fatalf("marker after logout-all present=%v err=%v", present, err)
	}
}

func TestEditionTokenStoreV2LogoutAllRollsBackCorePublicationFailures(t *testing.T) {
	previous := edition.Get()
	previousProfile := RuntimeProfile()
	store := &memoryProfileTokenStoreV2{}
	hooks := store.hooks(nil)
	edition.Override(hooks)
	t.Cleanup(func() {
		edition.Override(previous)
		SetRuntimeProfile(previousProfile)
	})
	configDir := t.TempDir()
	SetRuntimeProfile("ding-a")
	seed := v2ProfileToken("ding-a", "user-a", "a")
	if err := SaveTokenData(configDir, seed); err != nil {
		t.Fatal(err)
	}
	assertRestored := func(t *testing.T) {
		t.Helper()
		loaded, err := LoadTokenDataForProfile(configDir, "ding-a:user-a")
		if err != nil || loaded.AccessToken != "a" {
			t.Fatalf("credential not restored = %#v, %v", loaded, err)
		}
		profiles, err := LoadProfiles(configDir)
		if err != nil || len(profiles.Profiles) != 1 {
			t.Fatalf("profiles not restored = %#v, %v", profiles, err)
		}
		if _, present, err := ReadTokenMarkerGeneration(configDir); err != nil || !present {
			t.Fatalf("marker not restored present=%v err=%v", present, err)
		}
	}

	t.Run("profiles publication", func(t *testing.T) {
		original := tokenSaveProfiles
		failure := errors.New("profiles publish failed")
		calls := 0
		tokenSaveProfiles = func(dir string, cfg *ProfilesConfig) error {
			calls++
			if calls == 1 {
				return failure
			}
			return original(dir, cfg)
		}
		err := DeleteAllTokenData(configDir)
		tokenSaveProfiles = original
		if !errors.Is(err, failure) {
			t.Fatalf("DeleteAllTokenData() = %v", err)
		}
		assertRestored(t)
	})

	t.Run("marker publication", func(t *testing.T) {
		original := tokenDeleteMarker
		failure := errors.New("marker delete failed")
		tokenDeleteMarker = func(string) error { return failure }
		err := DeleteAllTokenData(configDir)
		tokenDeleteMarker = original
		if !errors.Is(err, failure) {
			t.Fatalf("DeleteAllTokenData() = %v", err)
		}
		assertRestored(t)
	})

	t.Run("host DeleteAll", func(t *testing.T) {
		failure := errors.New("host sweep failed")
		failingHooks := store.hooks(nil)
		failingHooks.TokenStoreV2.DeleteAll = func(string) error { return failure }
		edition.Override(failingHooks)
		err := DeleteAllTokenData(configDir)
		if !errors.Is(err, failure) {
			t.Fatalf("DeleteAllTokenData() = %v", err)
		}
		assertRestored(t)
	})
}

func TestHookLoadWaitsForBlobAndMarkerPublication(t *testing.T) {
	store, configDir := installMemoryEditionTokenStore(t)
	first := rejectedTokenData("token-a")
	if err := SaveTokenData(configDir, first); err != nil {
		t.Fatal(err)
	}

	baseHooks := store.hooks()
	blobWritten := make(chan struct{})
	releaseSave := make(chan struct{})
	var signalOnce sync.Once
	baseSave := baseHooks.SaveToken
	baseHooks.SaveToken = func(configDir string, blob []byte) error {
		if err := baseSave(configDir, blob); err != nil {
			return err
		}
		var data TokenData
		if err := json.Unmarshal(blob, &data); err == nil && data.AccessToken == "token-b" {
			signalOnce.Do(func() { close(blobWritten) })
			<-releaseSave
		}
		return nil
	}
	edition.Override(baseHooks)

	saveDone := make(chan error, 1)
	go func() { saveDone <- SaveTokenData(configDir, rejectedTokenData("token-b")) }()
	select {
	case <-blobWritten:
	case <-time.After(2 * time.Second):
		t.Fatal("save did not reach unpublished blob stage")
	}

	type loadResult struct {
		data *TokenData
		err  error
	}
	loadDone := make(chan loadResult, 1)
	go func() {
		data, err := LoadTokenData(configDir)
		loadDone <- loadResult{data: data, err: err}
	}()
	select {
	case got := <-loadDone:
		close(releaseSave)
		t.Fatalf("LoadTokenData observed an unpublished blob: %#v, %v", got.data, got.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseSave)
	if err := <-saveDone; err != nil {
		t.Fatalf("SaveTokenData(token-b) error = %v", err)
	}
	got := <-loadDone
	if got.err != nil || got.data == nil || got.data.AccessToken != "token-b" {
		t.Fatalf("LoadTokenData after publication = %#v, %v", got.data, got.err)
	}
}

func TestHookSaveRollsBackBlobWhenMarkerSyncFails(t *testing.T) {
	store, configDir := installMemoryEditionTokenStore(t)
	first := rejectedTokenData("token-a")
	if err := SaveTokenData(configDir, first); err != nil {
		t.Fatal(err)
	}
	initialGeneration, present, err := ReadTokenMarkerGeneration(configDir)
	if err != nil || !present {
		t.Fatalf("initial marker = (%d, %v, %v)", initialGeneration, present, err)
	}

	originalSync := tokenSyncFile
	var syncCalls atomic.Int32
	tokenSyncFile = func(path string) error {
		if syncCalls.Add(1) == 1 {
			return errors.New("injected marker fsync failure")
		}
		return originalSync(path)
	}
	t.Cleanup(func() { tokenSyncFile = originalSync })

	second := rejectedTokenData("token-b")
	if err := SaveTokenData(configDir, second); err == nil {
		t.Fatal("SaveTokenData(token-b) succeeded despite marker fsync failure")
	}
	if second.Generation != 0 {
		t.Fatalf("failed save mutated caller generation to %d", second.Generation)
	}
	store.mu.Lock()
	blob := append([]byte(nil), store.blob...)
	store.mu.Unlock()
	var persisted TokenData
	if err := json.Unmarshal(blob, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.AccessToken != "token-a" || persisted.Generation != first.Generation {
		t.Fatalf("hook blob was not rolled back: %#v", persisted)
	}
	generation, present, err := ReadTokenMarkerGeneration(configDir)
	if err != nil || !present || generation != initialGeneration {
		t.Fatalf("marker rollback = (%d, %v, %v), want generation %d", generation, present, err, initialGeneration)
	}
}

func TestHookDeleteRollsBackWhenDirectorySyncFails(t *testing.T) {
	_, configDir := installMemoryEditionTokenStore(t)
	data := rejectedTokenData("token-a")
	if err := SaveTokenData(configDir, data); err != nil {
		t.Fatal(err)
	}
	originalSyncDir := tokenSyncDirectory
	var syncCalls atomic.Int32
	tokenSyncDirectory = func(path string) error {
		if syncCalls.Add(1) == 1 {
			return errors.New("injected directory fsync failure")
		}
		return originalSyncDir(path)
	}
	t.Cleanup(func() { tokenSyncDirectory = originalSyncDir })

	if err := DeleteTokenData(configDir); err == nil {
		t.Fatal("DeleteTokenData() succeeded despite marker deletion fsync failure")
	}
	loaded, err := LoadTokenData(configDir)
	if err != nil || loaded.AccessToken != "token-a" || loaded.Generation != data.Generation {
		t.Fatalf("credential rollback after failed delete = %#v, %v", loaded, err)
	}
	generation, present, err := ReadTokenMarkerGeneration(configDir)
	if err != nil || !present || generation != data.Generation {
		t.Fatalf("marker after failed delete = (%d, %v, %v)", generation, present, err)
	}
}

func TestHookSaveRollsBackPartialWriteOperationError(t *testing.T) {
	store, configDir := installMemoryEditionTokenStore(t)
	first := rejectedTokenData("token-a")
	if err := SaveTokenData(configDir, first); err != nil {
		t.Fatal(err)
	}
	partialErr := errors.New("hook fsync failed after partial write")
	hooks := store.hooks()
	baseSave := hooks.SaveToken
	hooks.SaveToken = func(configDir string, blob []byte) error {
		if err := baseSave(configDir, blob); err != nil {
			return err
		}
		var data TokenData
		if err := json.Unmarshal(blob, &data); err == nil && data.AccessToken == "token-b" {
			return partialErr
		}
		return nil
	}
	edition.Override(hooks)

	if err := SaveTokenData(configDir, rejectedTokenData("token-b")); !errors.Is(err, partialErr) {
		t.Fatalf("SaveTokenData() error = %v, want partial write cause", err)
	}
	loaded, err := LoadTokenData(configDir)
	if err != nil || loaded.AccessToken != "token-a" || loaded.Generation != first.Generation {
		t.Fatalf("credential after partial hook save = %#v, %v", loaded, err)
	}
	generation, present, err := ReadTokenMarkerGeneration(configDir)
	if err != nil || !present || generation != first.Generation {
		t.Fatalf("marker after partial hook save = (%d, %v, %v)", generation, present, err)
	}
}

func TestHookDeleteRollsBackPartialDeleteOperationError(t *testing.T) {
	store, configDir := installMemoryEditionTokenStore(t)
	first := rejectedTokenData("token-a")
	if err := SaveTokenData(configDir, first); err != nil {
		t.Fatal(err)
	}
	partialErr := errors.New("hook delete failed after removal")
	hooks := store.hooks()
	baseDelete := hooks.DeleteToken
	hooks.DeleteToken = func(configDir string) error {
		if err := baseDelete(configDir); err != nil {
			return err
		}
		return partialErr
	}
	edition.Override(hooks)

	if err := DeleteTokenData(configDir); !errors.Is(err, partialErr) {
		t.Fatalf("DeleteTokenData() error = %v, want partial delete cause", err)
	}
	loaded, err := LoadTokenData(configDir)
	if err != nil || loaded.AccessToken != "token-a" || loaded.Generation != first.Generation {
		t.Fatalf("credential after partial hook delete = %#v, %v", loaded, err)
	}
	generation, present, err := ReadTokenMarkerGeneration(configDir)
	if err != nil || !present || generation != first.Generation {
		t.Fatalf("marker after partial hook delete = (%d, %v, %v)", generation, present, err)
	}
}

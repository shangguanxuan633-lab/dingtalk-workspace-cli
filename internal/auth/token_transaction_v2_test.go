package auth

import (
	"context"
	"encoding/json"
	"errors"
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

	SetRuntimeProfile("profile-a")
	dataA := rejectedTokenData("token-a")
	if err := SaveTokenData(configDir, dataA); err != nil {
		t.Fatal(err)
	}
	SetRuntimeProfile("profile-b")
	dataB := rejectedTokenData("token-b")
	if err := SaveTokenData(configDir, dataB); err != nil {
		t.Fatal(err)
	}
	if dataB.Generation <= dataA.Generation {
		t.Fatalf("generations A=%d B=%d", dataA.Generation, dataB.Generation)
	}

	loadedA, err := LoadTokenDataForProfile(configDir, "profile-a")
	if err != nil || loadedA.AccessToken != "token-a" {
		t.Fatalf("profile A = %#v, %v", loadedA, err)
	}
	loadedB, err := LoadTokenDataForProfile(configDir, "profile-b")
	if err != nil || loadedB.AccessToken != "token-b" {
		t.Fatalf("profile B = %#v, %v", loadedB, err)
	}
	if err := preflightTokenRefreshPersistenceForProfile(configDir, "profile-a", loadedA); err != nil {
		t.Fatal(err)
	}
	if preflightProfile != "profile-a" {
		t.Fatalf("preflight profile = %q", preflightProfile)
	}

	beforeDelete, present, err := ReadTokenMarkerGeneration(configDir)
	if err != nil || !present {
		t.Fatalf("marker before delete = (%d, %v, %v)", beforeDelete, present, err)
	}
	if err := DeleteTokenDataForProfile(configDir, "profile-a"); err != nil {
		t.Fatal(err)
	}
	afterDelete, present, err := ReadTokenMarkerGeneration(configDir)
	if err != nil || !present || afterDelete <= beforeDelete {
		t.Fatalf("marker after delete = (%d, %v, %v), want > %d", afterDelete, present, err, beforeDelete)
	}
	if _, err := LoadTokenDataForProfile(configDir, "profile-a"); !errors.Is(err, ErrTokenDataNotFound) {
		t.Fatalf("deleted profile A load error = %v", err)
	}
	loadedB, err = LoadTokenDataForProfile(configDir, "profile-b")
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
	SetRuntimeProfile("profile-a")
	data := rejectedTokenData("rejected")
	if err := SaveTokenData(configDir, data); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("profile store preflight failed")
	edition.Override(store.hooks(func(_, profile string) error {
		if profile != "profile-a" {
			t.Fatalf("preflight profile = %q", profile)
		}
		return sentinel
	}))
	var exchanges atomic.Int32
	oauthRefreshToken = func(*OAuthProvider, context.Context, *TokenData) (*TokenData, error) {
		exchanges.Add(1)
		return nil, errors.New("unexpected OAuth refresh")
	}
	provider := NewOAuthProviderForProfile(configDir, nil, "profile-a")
	if _, err := provider.ForceRefreshRejectedToken(context.Background(), data.AccessToken, data.Generation); !errors.Is(err, sentinel) {
		t.Fatalf("ForceRefreshRejectedToken() error = %v", err)
	}
	if got := exchanges.Load(); got != 0 {
		t.Fatalf("OAuth refresh exchanges = %d, want 0", got)
	}
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

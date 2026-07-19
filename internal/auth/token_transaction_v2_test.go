package auth

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

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

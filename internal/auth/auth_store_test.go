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

package auth

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/keychain"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

func withEditionHooks(t *testing.T, hooks *edition.Hooks) {
	t.Helper()
	previous := edition.Get()
	edition.Override(hooks)
	t.Cleanup(func() { edition.Override(previous) })
}

func TestResolveAuthStoreLegacyDoesNotInferIsolation(t *testing.T) {
	base := filepath.Join(t.TempDir(), "custom")
	withEditionHooks(t, &edition.Hooks{
		Name:      "different-edition",
		ConfigDir: func() string { return filepath.Join(t.TempDir(), "ignored") },
	})

	store := ResolveAuthStore(base)
	if store.Explicit || store.Segment != "" {
		t.Fatalf("legacy store = %#v, want no explicit isolation", store)
	}
	if store.ConfigDir != base {
		t.Fatalf("ConfigDir = %q, want legacy path %q", store.ConfigDir, base)
	}
	if store.KeychainService != keychain.Service {
		t.Fatalf("service = %q, want %q", store.KeychainService, keychain.Service)
	}
}

func TestResolveAuthStoreNamedIsStableSafeAndIdempotent(t *testing.T) {
	const expectedSegment = "39b077bf02d5ffb0c3f658aab3dfac5d9e80c117255baaa36b06e47cb7300f4d"
	base := filepath.Join(t.TempDir(), "base")
	withEditionHooks(t, &edition.Hooks{AuthStoreNamespace: "  work  "})

	first := ResolveAuthStore(base)
	second := ResolveAuthStore(first.ConfigDir)
	if first != second {
		t.Fatalf("resolution is not idempotent: first=%#v second=%#v", first, second)
	}
	if baseKey, resolvedKey := AuthStoreCacheKey(base), AuthStoreCacheKey(first.ConfigDir); baseKey != resolvedKey {
		t.Fatalf("cache key is not idempotent: base=%q resolved=%q", baseKey, resolvedKey)
	}
	if first.Segment != expectedSegment {
		t.Fatalf("segment = %q, want persistent contract %q", first.Segment, expectedSegment)
	}
	if first.ConfigDir != filepath.Join(base, authStoresDirName, expectedSegment) {
		t.Fatalf("ConfigDir = %q", first.ConfigDir)
	}
	if first.KeychainService != authStoreServicePrefix+expectedSegment {
		t.Fatalf("service = %q", first.KeychainService)
	}
	if bytes.Contains([]byte(first.ConfigDir+first.KeychainService), []byte("work")) {
		t.Fatal("raw namespace leaked into persistent storage identifiers")
	}
}

func TestInternalDefaultConfigDirScopesOnlyExplicitStore(t *testing.T) {
	base := filepath.Join(t.TempDir(), "custom")
	t.Setenv("DWS_CONFIG_DIR", base)
	previous := edition.Get()
	defer edition.Override(previous)

	edition.Override(&edition.Hooks{Name: "legacy-custom-dir"})
	if got := getDefaultConfigDir(); got != base {
		t.Fatalf("legacy getDefaultConfigDir() = %q, want %q", got, base)
	}
	edition.Override(&edition.Hooks{AuthStoreNamespace: "endpoint-store"})
	if got, want := getDefaultConfigDir(), ResolveAuthStore(base).ConfigDir; got != want {
		t.Fatalf("named getDefaultConfigDir() = %q, want %q", got, want)
	}
}

func TestNamedStoresKeepSameCorpTokenAndDefaultStoreDisjoint(t *testing.T) {
	t.Setenv(keychain.DisableKeychainEnv, "1")
	t.Setenv(keychain.StorageDirEnv, filepath.Join(t.TempDir(), "keychain"))
	base := filepath.Join(t.TempDir(), ".dws")
	previous := edition.Get()
	defer edition.Override(previous)
	SetRuntimeProfile("")
	defer SetRuntimeProfile("")

	if err := keychain.Set(keychain.Service, keychain.AccountToken, "legacy-sentinel"); err != nil {
		t.Fatalf("seed legacy token: %v", err)
	}

	edition.Override(&edition.Hooks{AuthStoreNamespace: "person-a"})
	storeA := ResolveAuthStore(base)
	if err := SaveTokenData(base, testStoreToken("corp-shared", "token-a")); err != nil {
		t.Fatalf("SaveTokenData(A): %v", err)
	}

	edition.Override(&edition.Hooks{AuthStoreNamespace: "person-b"})
	storeB := ResolveAuthStore(base)
	if err := SaveTokenData(base, testStoreToken("corp-shared", "token-b")); err != nil {
		t.Fatalf("SaveTokenData(B): %v", err)
	}
	loadedB, err := LoadTokenData(base)
	if err != nil || loadedB.AccessToken != "token-b" {
		t.Fatalf("LoadTokenData(B) = %#v, %v", loadedB, err)
	}
	if err := DeleteAllTokenData(base); err != nil {
		t.Fatalf("DeleteAllTokenData(B): %v", err)
	}

	edition.Override(&edition.Hooks{AuthStoreNamespace: "person-a"})
	loadedA, err := LoadTokenData(base)
	if err != nil || loadedA.AccessToken != "token-a" {
		t.Fatalf("LoadTokenData(A) = %#v, %v", loadedA, err)
	}
	if storeA.ConfigDir == storeB.ConfigDir || storeA.KeychainService == storeB.KeychainService {
		t.Fatalf("named stores overlap: A=%#v B=%#v", storeA, storeB)
	}

	edition.Override(&edition.Hooks{})
	legacy, err := keychain.Get(keychain.Service, keychain.AccountToken)
	if err != nil || legacy != "legacy-sentinel" {
		t.Fatalf("legacy token after named reset = %q, %v", legacy, err)
	}
}

func TestNamedManagerKeepsTokenScopedAndMCPURLGlobal(t *testing.T) {
	base := filepath.Join(t.TempDir(), ".dws")
	withEditionHooks(t, &edition.Hooks{AuthStoreNamespace: "manager-store"})
	store := ResolveAuthStore(base)

	manager := NewManager(store.ConfigDir, nil)
	if err := manager.SaveToken("scoped-token"); err != nil {
		t.Fatal(err)
	}
	if err := manager.SaveMCPURL("https://global.example.com/mcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.ConfigDir, tokenFileName)); err != nil {
		t.Fatalf("named token not stored in credential home: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "mcp_url")); err != nil {
		t.Fatalf("MCP URL not stored in global config home: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.ConfigDir, "mcp_url")); !os.IsNotExist(err) {
		t.Fatalf("MCP URL leaked into named credential home: %v", err)
	}
	if got, err := manager.GetMCPURL(); err != nil || got != "https://global.example.com/mcp" {
		t.Fatalf("GetMCPURL() = %q, %v", got, err)
	}
}

func testStoreToken(corpID, accessToken string) *TokenData {
	return &TokenData{
		CorpID:       corpID,
		AccessToken:  accessToken,
		RefreshToken: "refresh-" + accessToken,
		ExpiresAt:    time.Now().Add(time.Hour),
		RefreshExpAt: time.Now().Add(24 * time.Hour),
	}
}

func TestLegacyPartialTokenHookRemainsIndependentlyDispatched(t *testing.T) {
	base := filepath.Join(t.TempDir(), "legacy")
	called := false
	withEditionHooks(t, &edition.Hooks{
		SaveToken: func(configDir string, _ []byte) error {
			called = true
			if configDir != base {
				t.Fatalf("legacy hook configDir = %q, want %q", configDir, base)
			}
			return nil
		},
	})
	if err := SaveTokenData(base, &TokenData{AccessToken: "legacy-hook"}); err != nil {
		t.Fatalf("legacy partial SaveToken returned error: %v", err)
	}
	if !called {
		t.Fatal("legacy partial SaveToken hook was not called")
	}
}

func TestLegacyPartialLoadAndDeleteHooksRemainIndependentlyDispatched(t *testing.T) {
	t.Run("load", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "legacy-load")
		withEditionHooks(t, &edition.Hooks{
			LoadToken: func(configDir string) ([]byte, error) {
				if configDir != base {
					t.Fatalf("legacy LoadToken configDir = %q, want %q", configDir, base)
				}
				return []byte(`{"access_token":"legacy-load"}`), nil
			},
		})
		data, err := LoadTokenData(base)
		if err != nil || data.AccessToken != "legacy-load" {
			t.Fatalf("LoadTokenData() = %#v, %v", data, err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "legacy-delete")
		called := false
		withEditionHooks(t, &edition.Hooks{
			DeleteToken: func(configDir string) error {
				called = true
				if configDir != base {
					t.Fatalf("legacy DeleteToken configDir = %q, want %q", configDir, base)
				}
				return nil
			},
		})
		if err := DeleteTokenData(base); err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatal("legacy partial DeleteToken hook was not called")
		}
	})
}

func TestNamedStoreRejectsPartialTokenHooksBeforeWrite(t *testing.T) {
	called := false
	withEditionHooks(t, &edition.Hooks{
		AuthStoreNamespace: "named-hook",
		SaveToken: func(string, []byte) error {
			called = true
			return nil
		},
	})
	err := SaveTokenData(t.TempDir(), &TokenData{AccessToken: "must-not-write"})
	if !errors.Is(err, ErrIncompleteTokenHooks) {
		t.Fatalf("SaveTokenData error = %v, want ErrIncompleteTokenHooks", err)
	}
	if called {
		t.Fatal("partial named-store hook was called")
	}
}

func TestNamedCompleteTokenHooksReceiveScopedStoreHome(t *testing.T) {
	base := filepath.Join(t.TempDir(), "base")
	var savedAt string
	withEditionHooks(t, &edition.Hooks{
		AuthStoreNamespace: "hook-home",
		SaveToken: func(configDir string, _ []byte) error {
			savedAt = configDir
			return nil
		},
		LoadToken:   func(string) ([]byte, error) { return []byte(`{"access_token":"loaded"}`), nil },
		DeleteToken: func(string) error { return nil },
	})
	if err := SaveTokenData(base, &TokenData{AccessToken: "saved"}); err != nil {
		t.Fatal(err)
	}
	if want := ResolveAuthStore(base).ConfigDir; savedAt != want {
		t.Fatalf("hook configDir = %q, want store home %q", savedAt, want)
	}
}

func TestAppConfigCacheIsBucketedByNamedStore(t *testing.T) {
	base := filepath.Join(t.TempDir(), "base")
	previous := edition.Get()
	defer edition.Override(previous)
	resetAppConfigCaches()
	defer resetAppConfigCaches()

	edition.Override(&edition.Hooks{Name: "overlay", AuthStoreNamespace: "cache-a"})
	if err := SaveAppConfig(base, &AppConfig{ClientID: "client-a"}); err != nil {
		t.Fatalf("SaveAppConfig(A): %v", err)
	}
	edition.Override(&edition.Hooks{Name: "overlay", AuthStoreNamespace: "cache-b"})
	if err := SaveAppConfig(base, &AppConfig{ClientID: "client-b"}); err != nil {
		t.Fatalf("SaveAppConfig(B): %v", err)
	}
	if id, _ := ResolveAppCredentials(base); id != "client-b" {
		t.Fatalf("ResolveAppCredentials(B) id = %q", id)
	}
	edition.Override(&edition.Hooks{Name: "overlay", AuthStoreNamespace: "cache-a"})
	if id, _ := ResolveAppCredentials(base); id != "client-a" {
		t.Fatalf("ResolveAppCredentials(A) id = %q", id)
	}
}

func TestProcessLockAndMigrationAreBucketedByStore(t *testing.T) {
	base := filepath.Join(t.TempDir(), "base")
	previous := edition.Get()
	defer edition.Override(previous)

	edition.Override(&edition.Hooks{AuthStoreNamespace: "lock-a"})
	lockA := processLockKey(base)
	EnsureMigration(base, nil)
	if !IsMigrationDoneFor(base) {
		t.Fatal("migration bucket A was not marked done")
	}

	edition.Override(&edition.Hooks{AuthStoreNamespace: "lock-b"})
	lockB := processLockKey(base)
	if lockA == lockB {
		t.Fatalf("process lock keys overlap: %q", lockA)
	}
	if IsMigrationDoneFor(base) {
		t.Fatal("migration bucket B inherited bucket A state")
	}
	EnsureMigration(base, nil)
	if !IsMigrationDoneFor(base) {
		t.Fatal("migration bucket B was not marked done")
	}
}

func TestPortableImportRejectsServiceMismatchBeforeWriting(t *testing.T) {
	t.Setenv(keychain.StorageDirEnv, filepath.Join(t.TempDir(), "keychain"))
	base := filepath.Join(t.TempDir(), "base")
	var bundle bytes.Buffer
	gz := gzip.NewWriter(&bundle)
	tw := tar.NewWriter(gz)
	if err := writePortableManifest(tw, portableAuthBundleManifest{
		Version:         1,
		KeychainService: keychain.Service,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writePortableBytes(tw, "config/profiles.json", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	withEditionHooks(t, &edition.Hooks{AuthStoreNamespace: "portable-target"})
	store := ResolveAuthStore(base)
	if _, err := ImportPortableAuthBundle(base, bytes.NewReader(bundle.Bytes())); err == nil {
		t.Fatal("ImportPortableAuthBundle should reject a different keychain service")
	}
	if _, err := os.Stat(store.ConfigDir); !os.IsNotExist(err) {
		t.Fatalf("named config store was touched before mismatch failure: %v", err)
	}
	if _, err := os.Stat(keychain.StorageDir(store.KeychainService)); !os.IsNotExist(err) {
		t.Fatalf("named keychain store was touched before mismatch failure: %v", err)
	}
}

func TestNamedPortableStoreRejectsGlobalEndpoints(t *testing.T) {
	t.Setenv(keychain.StorageDirEnv, filepath.Join(t.TempDir(), "keychain"))
	base := filepath.Join(t.TempDir(), "base")
	withEditionHooks(t, &edition.Hooks{AuthStoreNamespace: "portable-endpoint-target"})
	store := ResolveAuthStore(base)
	if err := os.MkdirAll(store.ConfigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"app.json", "mcp_url", "terminal_url"} {
		if err := os.WriteFile(filepath.Join(store.ConfigDir, name), []byte("value"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := portableConfigFiles(store.ConfigDir, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != "app.json" {
		t.Fatalf("named portable config files = %v, want only app.json", files)
	}

	var bundle bytes.Buffer
	gz := gzip.NewWriter(&bundle)
	tw := tar.NewWriter(gz)
	if err := writePortableManifest(tw, portableAuthBundleManifest{
		Version:         1,
		KeychainService: store.KeychainService,
		ConfigFiles:     []string{"mcp_url"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writePortableBytes(tw, "config/mcp_url", []byte("https://forbidden.example.com"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportPortableAuthBundle(base, bytes.NewReader(bundle.Bytes())); err == nil {
		t.Fatal("named import should reject global endpoint config")
	}
	if data, err := os.ReadFile(filepath.Join(store.ConfigDir, "mcp_url")); err != nil || string(data) != "value" {
		t.Fatalf("rejected import changed existing endpoint sentinel: %q, %v", data, err)
	}
}

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
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/keychain"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

const (
	// authStoreDerivationDomain is part of the persistent storage contract.
	// Changing it would make existing named stores unreachable, so introduce a
	// separate migration instead of editing this value in a future release.
	authStoreDerivationDomain = "dws-cli/auth-store/v1\x00"
	authStoresDirName         = "auth-stores"
	authStoreServicePrefix    = keychain.Service + "-store-"
)

// AuthStore is the resolved storage boundary for the active edition. A legacy
// store leaves ConfigDir untouched and uses keychain.Service. A named store
// partitions both filesystem metadata and every keychain account through a
// domain-separated, non-reversible namespace digest.
type AuthStore struct {
	ConfigDir       string
	KeychainService string
	Segment         string
	Explicit        bool
}

// ResolveAuthStore resolves baseConfigDir for the active edition. Resolution
// is idempotent so callers may safely pass either the legacy base directory or
// an already-resolved named-store home.
func ResolveAuthStore(baseConfigDir string) AuthStore {
	namespace := strings.TrimSpace(edition.Get().AuthStoreNamespace)
	if namespace == "" {
		return AuthStore{
			ConfigDir:       baseConfigDir,
			KeychainService: keychain.Service,
		}
	}

	digest := sha256.Sum256([]byte(authStoreDerivationDomain + namespace))
	segment := hex.EncodeToString(digest[:])
	configDir := baseConfigDir
	if !isResolvedAuthStoreDir(configDir, segment) {
		configDir = filepath.Join(configDir, authStoresDirName, segment)
	}
	return AuthStore{
		ConfigDir:       configDir,
		KeychainService: authStoreServicePrefix + segment,
		Segment:         segment,
		Explicit:        true,
	}
}

func isResolvedAuthStoreDir(configDir, segment string) bool {
	clean := filepath.Clean(configDir)
	return filepath.Base(clean) == segment && filepath.Base(filepath.Dir(clean)) == authStoresDirName
}

// ActiveAuthStoreService returns the keychain service selected by the active
// edition. Empty namespaces always return the legacy service.
func ActiveAuthStoreService() string {
	return ResolveAuthStore("").KeychainService
}

// AuthStoreConfigDir scopes a legacy base config directory for the active
// edition. It is intentionally a no-op for the default/legacy store.
func AuthStoreConfigDir(baseConfigDir string) string {
	return ResolveAuthStore(baseConfigDir).ConfigDir
}

// AuthStoreBaseConfigDir returns the global DWS config directory for an input
// that may already point at the active named-store home. Global product
// settings such as endpoint overrides and PAT policy must continue to use this
// directory even when credentials are isolated.
func AuthStoreBaseConfigDir(configDir string) string {
	store := ResolveAuthStore(configDir)
	if !store.Explicit || !isResolvedAuthStoreDir(configDir, store.Segment) {
		return configDir
	}
	return filepath.Dir(filepath.Dir(filepath.Clean(configDir)))
}

// AuthStoreCacheKey returns a stable in-process bucket key. Both the selected
// keychain service and the normalized config directory are included because
// tests and embedded hosts can switch edition hooks within one process.
func AuthStoreCacheKey(configDir string) string {
	store := ResolveAuthStore(configDir)
	return store.KeychainService + "\x00" + filepath.Clean(store.ConfigDir)
}

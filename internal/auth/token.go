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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/keychain"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/logging"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

var (
	tokenJSONMarshalIndent       = json.MarshalIndent
	tokenJSONMarshal             = json.Marshal
	tokenMkdirAll                = os.MkdirAll
	tokenReadFile                = os.ReadFile
	tokenWriteFile               = os.WriteFile
	tokenRename                  = os.Rename
	tokenSyncFile                = syncTokenFile
	tokenSyncDirectory           = syncTokenDirectory
	tokenRemove                  = os.Remove
	tokenGlob                    = filepath.Glob
	tokenSaveKeychainForCorpID   = SaveTokenDataKeychainForCorpID
	tokenSaveKeychainForIdentity = SaveTokenDataKeychainForIdentity
	tokenSaveKeychain            = SaveTokenDataKeychain
	tokenLoadKeychainForCorpID   = LoadTokenDataKeychainForCorpID
	tokenLoadKeychainIdentity    = LoadTokenDataKeychainForIdentity
	tokenLoadKeychain            = LoadTokenDataKeychain
	tokenKeychainExists          = TokenDataExistsKeychain
	tokenDeleteKeychainForCorpID = DeleteTokenDataKeychainForCorpID
	tokenDeleteKeychainIdentity  = DeleteTokenDataKeychainForIdentity
	tokenDeleteKeychain          = DeleteTokenDataKeychain
	tokenRemoveAuthTokenEntries  = keychain.RemoveAuthTokenEntries
	tokenLoadSecure              = LoadSecureTokenData
	tokenDeleteSecure            = DeleteSecureData
	tokenResolveProfile          = func(configDir, selector string) (*Profile, error) {
		profile, _, err := resolveProfileForLoadLocked(configDir, selector)
		return profile, err
	}
	tokenResolveDeletion        = resolveProfileDeletionSelection
	tokenResolveSelection       = resolveProfileSelection
	tokenUpsertProfile          = upsertProfileFromTokenWithCurrentLocked
	tokenRemoveProfile          = removeProfileLocked
	tokenSyncLegacyMirror       = syncLegacyTokenMirrorLocked
	tokenSyncSelectedMirror     = syncSelectedLegacyTokenMirrorLocked
	tokenBumpMarkerGeneration   = bumpTokenMarkerGeneration
	tokenSyncOrganizationMirror = syncOrganizationTokenMirrorForProfile
	tokenLoadProfiles           = LoadProfiles
	tokenSaveProfiles           = SaveProfiles
	tokenWriteMarker            = WriteTokenMarker
	tokenWriteManualMarker      = WriteManualTokenMarker
	tokenWriteMarkerGeneration  = writeTokenMarkerGeneration
	tokenDeleteMarker           = DeleteTokenMarker
	tokenParseURL               = url.Parse
	tokenNewRequest             = http.NewRequestWithContext
	tokenDefaultConfigDir       = getDefaultConfigDir
	tokenLoadData               = LoadTokenData
	tokenRevokeURL              = GetRevokeTokenURL
	tokenMCPBaseURL             = GetMCPBaseURL
	tokenLogoutURL              = LogoutURL
	tokenLogoutContinueURL      = LogoutContinueURL
	tokenLogoutHTTPClient       = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	tokenRevokeHTTPClient       = &http.Client{Timeout: 10 * time.Second}
)

// TokenData holds the OAuth token set persisted to disk.
type TokenData struct {
	AccessToken    string    `json:"access_token"`
	RefreshToken   string    `json:"refresh_token"`
	PersistentCode string    `json:"persistent_code"`
	ExpiresAt      time.Time `json:"expires_at"`
	RefreshExpAt   time.Time `json:"refresh_expires_at"`
	CorpID         string    `json:"corp_id"`
	UserID         string    `json:"user_id,omitempty"`
	UserName       string    `json:"user_name,omitempty"`
	CorpName       string    `json:"corp_name,omitempty"`
	ClientID       string    `json:"client_id,omitempty"` // Associated app client ID for refresh
	UpdatedAt      string    `json:"updated_at,omitempty"`
	Source         string    `json:"source,omitempty"`
	Generation     uint64    `json:"generation,omitempty"`
}

// IsAccessTokenValid returns true if the access token has not expired.
func (t *TokenData) IsAccessTokenValid() bool {
	if t == nil || t.AccessToken == "" {
		return false
	}
	// Give 5-minute buffer before actual expiry.
	return time.Now().Before(t.ExpiresAt.Add(-5 * time.Minute))
}

// IsRefreshTokenValid returns true if the refresh token has not expired.
func (t *TokenData) IsRefreshTokenValid() bool {
	if t == nil || t.RefreshToken == "" {
		return false
	}
	return time.Now().Before(t.RefreshExpAt)
}

// HasPersistentCode returns true if a persistent code is available.
func (t *TokenData) HasPersistentCode() bool {
	return t != nil && t.PersistentCode != ""
}

const tokenJSONFile = "token.json"

// TokenMarker is a lightweight file the host application reads to detect
// whether the CLI has a valid token without accessing the keychain.
type TokenMarker struct {
	UpdatedAt   string `json:"updated_at"`
	ManualToken bool   `json:"manual_token,omitempty"`
	Generation  uint64 `json:"generation,omitempty"`
}

// WriteTokenMarker writes a token.json marker containing only an updated_at
// timestamp. The host application uses this file's presence and mtime to
// decide whether it needs to trigger a new auth exchange.
func WriteTokenMarker(configDir string) error {
	generation, _, err := ReadTokenMarkerGeneration(configDir)
	if err != nil {
		return err
	}
	return writeTokenMarker(configDir, false, generation)
}

// WriteManualTokenMarker marks the legacy global keychain slot as an explicit
// `auth login --token` credential. The additive field keeps older hosts, which
// only inspect token.json presence and mtime, fully compatible.
func WriteManualTokenMarker(configDir string) error {
	generation, _, err := ReadTokenMarkerGeneration(configDir)
	if err != nil {
		return err
	}
	return writeTokenMarker(configDir, true, generation)
}

func writeTokenMarker(configDir string, manual bool, generation uint64) error {
	marker := TokenMarker{
		UpdatedAt:   time.Now().Format(time.RFC3339),
		ManualToken: manual,
		Generation:  generation,
	}
	data, err := tokenJSONMarshalIndent(marker, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token publication marker: %w", err)
	}
	if err := tokenMkdirAll(configDir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(configDir, tokenJSONFile+"."+uuid.New().String()+".tmp")
	renamed := false
	defer func() {
		if !renamed {
			_ = tokenRemove(tmp)
		}
	}()
	if err := tokenWriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := tokenSyncFile(tmp); err != nil {
		return fmt.Errorf("sync token publication marker: %w", err)
	}
	if err := tokenRename(tmp, filepath.Join(configDir, tokenJSONFile)); err != nil {
		return err
	}
	renamed = true
	if err := tokenSyncDirectory(configDir); err != nil {
		return fmt.Errorf("sync token publication directory: %w", err)
	}
	return nil
}

func syncTokenFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(syncErr, closeErr)
}

func syncTokenDirectory(path string) error {
	// Windows has no portable directory fsync equivalent. Rename is already
	// atomic there; durable directory publication is enforced on Unix hosts.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}

func editionTokenStoreConfigured(h *edition.Hooks) bool {
	return h != nil && (h.TokenStoreV2 != nil || h.SaveToken != nil || h.LoadToken != nil || h.DeleteToken != nil)
}

func validateEditionTokenStore(h *edition.Hooks) error {
	if !editionTokenStoreConfigured(h) {
		return nil
	}
	if h.TokenStoreV2 != nil {
		if h.TokenStoreV2.Save == nil || h.TokenStoreV2.Load == nil || h.TokenStoreV2.Delete == nil {
			return fmt.Errorf("edition TokenStoreV2 must provide Save, Load, and Delete")
		}
		return nil
	}
	if h.SaveToken == nil || h.LoadToken == nil || h.DeleteToken == nil {
		return fmt.Errorf("edition token store must provide SaveToken, LoadToken, and DeleteToken")
	}
	return nil
}

func editionTokenStoreSupportsProfiles(h *edition.Hooks) bool {
	return h != nil && h.TokenStoreV2 != nil
}

func loadEditionToken(h *edition.Hooks, configDir, profile string) ([]byte, error) {
	if h != nil && h.TokenStoreV2 != nil {
		return h.TokenStoreV2.Load(configDir, strings.TrimSpace(profile))
	}
	if strings.TrimSpace(profile) != "" {
		return nil, fmt.Errorf("profile selection is not supported by the legacy edition auth backend")
	}
	return h.LoadToken(configDir)
}

func saveEditionToken(h *edition.Hooks, configDir, profile string, data []byte) error {
	if h != nil && h.TokenStoreV2 != nil {
		return h.TokenStoreV2.Save(configDir, strings.TrimSpace(profile), data)
	}
	if strings.TrimSpace(profile) != "" {
		return fmt.Errorf("profile selection is not supported by the legacy edition auth backend")
	}
	return h.SaveToken(configDir, data)
}

func deleteEditionToken(h *edition.Hooks, configDir, profile string) error {
	if h != nil && h.TokenStoreV2 != nil {
		return h.TokenStoreV2.Delete(configDir, strings.TrimSpace(profile))
	}
	if strings.TrimSpace(profile) != "" {
		return fmt.Errorf("profile selection is not supported by the legacy edition auth backend")
	}
	return h.DeleteToken(configDir)
}

// canonicalEditionProfileForData returns the only selector TokenStoreV2 is
// allowed to persist for an OAuth identity. User-facing aliases, organization
// names, and the mutable "current" selector never cross the edition boundary.
// An identity-less token is the legacy/manual singleton and therefore uses the
// empty key; it cannot be combined with an explicit profile lease.
func canonicalEditionProfileForData(configDir, runtimeSelector string, data *TokenData) (string, bool, error) {
	if data == nil {
		return "", false, fmt.Errorf("token data is nil")
	}
	runtimeSelector = strings.TrimSpace(runtimeSelector)
	corpID := strings.TrimSpace(data.CorpID)
	userID := strings.TrimSpace(data.UserID)
	if corpID == "" {
		if runtimeSelector != "" {
			return "", false, fmt.Errorf("identity-less token cannot be saved for an explicit profile")
		}
		return "", false, nil
	}
	if userID == "" {
		return "", false, fmt.Errorf("TokenStoreV2 requires userId for organization %q", corpID)
	}
	canonical := profileSelector(corpID, userID)
	makeCurrent := runtimeSelector == ""
	if runtimeSelector == "" {
		return canonical, makeCurrent, nil
	}

	cfg, err := tokenLoadProfiles(configDir)
	if err != nil {
		return "", false, err
	}
	if selected, _, resolveErr := tokenResolveSelection(configDir, cfg, runtimeSelector); resolveErr == nil {
		if ProfileSelector(*selected) != canonical {
			return "", false, fmt.Errorf("profile lease does not match refreshed token identity")
		}
		return canonical, false, nil
	}
	// A brand-new identity may be addressed by its already-canonical selector
	// or its target corpId before profiles.json contains it. Arbitrary aliases
	// are deliberately not accepted here because they cannot be reconstructed
	// after process restart.
	if runtimeSelector == corpID {
		return canonical, false, nil
	}
	selectorCorp, selectorUser, exact := ParseIdentitySelector(runtimeSelector)
	if !exact || profileSelector(selectorCorp, selectorUser) != canonical {
		return "", false, fmt.Errorf("profile %q is not a canonical identity lease", runtimeSelector)
	}
	return canonical, false, nil
}

// resolveCanonicalEditionProfileLocked maps current/corp/name/alias selectors
// to a stable identity key while the caller holds the auth/profile lock.
func resolveCanonicalEditionProfileLocked(configDir, selector string) (string, *Profile, *ProfilesConfig, error) {
	cfg, err := tokenLoadProfiles(configDir)
	if err != nil {
		return "", nil, nil, err
	}
	if err := ensureProfilesWritable(cfg); err != nil {
		return "", nil, nil, err
	}
	selector = strings.TrimSpace(selector)
	if selector == "" {
		selector = strings.TrimSpace(cfg.CurrentProfile)
		if selector == "" {
			return "", nil, cfg, nil
		}
	}
	selected, _, err := tokenResolveSelection(configDir, cfg, selector)
	if err != nil {
		return "", nil, cfg, err
	}
	canonical := ProfileSelector(*selected)
	if strings.TrimSpace(selected.CorpID) != "" && strings.TrimSpace(selected.UserID) == "" {
		return "", nil, cfg, fmt.Errorf("TokenStoreV2 profile %q has no userId", canonical)
	}
	return canonical, selected, cfg, nil
}

func parseEditionTokenBlob(blob []byte) (*TokenData, error) {
	var data TokenData
	if err := json.Unmarshal(blob, &data); err != nil {
		return nil, fmt.Errorf("parsing token data from hook: %w", err)
	}
	return &data, nil
}

func loadEditionTokenV2Locked(h *edition.Hooks, configDir, requested string) ([]byte, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		manual, err := manualTokenMarkerActive(configDir)
		if err != nil {
			return nil, err
		}
		if manual {
			blob, err := loadEditionToken(h, configDir, "")
			if err != nil {
				return nil, err
			}
			data, err := parseEditionTokenBlob(blob)
			if err != nil {
				return nil, err
			}
			if TokenProfileSelector(data) != "" {
				return nil, fmt.Errorf("manual TokenStoreV2 slot contains an OAuth identity")
			}
			return blob, nil
		}
	}
	canonical, _, cfg, resolveErr := resolveCanonicalEditionProfileLocked(configDir, requested)
	if resolveErr == nil {
		blob, err := loadEditionToken(h, configDir, canonical)
		if err == nil {
			data, parseErr := parseEditionTokenBlob(blob)
			if parseErr != nil {
				return nil, parseErr
			}
			blobIdentity := TokenProfileSelector(data)
			if canonical == "" && blobIdentity != "" {
				if strings.TrimSpace(data.UserID) == "" {
					return nil, fmt.Errorf("legacy edition token profile has no userId")
				}
				if err := migrateEditionTokenV2Locked(h, configDir, "", blobIdentity, cfg, data, blob, true); err != nil {
					return nil, err
				}
				return blob, nil
			}
			if canonical != "" && blobIdentity != canonical {
				return nil, fmt.Errorf("edition token identity does not match canonical profile")
			}
			return blob, nil
		}
		if !errors.Is(err, ErrTokenDataNotFound) && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	// Compatibility migration for builds that handed a raw alias/current key to
	// TokenStoreV2 before Core owned canonicalization. The blob's embedded
	// corpId:userId is authoritative; aliases are never retained as store keys.
	candidates := make([]string, 0, 2)
	if requested != canonical {
		candidates = append(candidates, requested)
	}
	if requested == "" && canonical != "" {
		candidates = append(candidates, "")
	}
	if canonical != "" && cfg != nil && canonicalStoredSelector(cfg, cfg.CurrentProfile) == canonical {
		candidates = append(candidates, "")
	}
	seen := map[string]struct{}{canonical: {}}
	for _, legacyKey := range candidates {
		if _, ok := seen[legacyKey]; ok {
			continue
		}
		seen[legacyKey] = struct{}{}
		blob, err := loadEditionToken(h, configDir, legacyKey)
		if err != nil {
			if errors.Is(err, ErrTokenDataNotFound) || errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		data, err := parseEditionTokenBlob(blob)
		if err != nil {
			return nil, err
		}
		exact := TokenProfileSelector(data)
		if exact == "" {
			if requested == "" && canonical == "" {
				return blob, nil
			}
			return nil, fmt.Errorf("legacy edition token has no profile identity")
		}
		if strings.TrimSpace(data.UserID) == "" {
			return nil, fmt.Errorf("legacy edition token profile has no userId")
		}
		if canonical != "" && exact != canonical {
			if legacyKey == "" {
				continue
			}
			return nil, fmt.Errorf("legacy edition token identity does not match selected profile")
		}
		if corpID, userID, isExact := ParseIdentitySelector(requested); isExact && profileSelector(corpID, userID) != exact {
			return nil, fmt.Errorf("legacy edition token identity does not match requested profile")
		}
		if err := migrateEditionTokenV2Locked(h, configDir, legacyKey, exact, cfg, data, blob, requested == ""); err != nil {
			return nil, err
		}
		return blob, nil
	}
	if resolveErr != nil {
		return nil, errors.Join(ErrTokenDataNotFound, resolveErr)
	}
	return nil, ErrTokenDataNotFound
}

func migrateEditionTokenV2Locked(h *edition.Hooks, configDir, legacyKey, canonical string, cfg *ProfilesConfig, data *TokenData, blob []byte, makeCurrent bool) error {
	markerSnapshot, err := snapshotTokenMarker(configDir)
	if err != nil {
		return err
	}
	profilesSnapshot := cloneProfilesConfig(cfg)
	canonicalPrevious, loadErr := loadEditionToken(h, configDir, canonical)
	canonicalExisted := loadErr == nil
	if loadErr != nil && !errors.Is(loadErr, ErrTokenDataNotFound) && !errors.Is(loadErr, os.ErrNotExist) {
		return loadErr
	}
	rollback := func(operationErr error) error {
		var rollbackErr error
		if canonicalExisted {
			rollbackErr = errors.Join(rollbackErr, saveEditionToken(h, configDir, canonical, canonicalPrevious))
		} else {
			rollbackErr = errors.Join(rollbackErr, deleteEditionToken(h, configDir, canonical))
		}
		if legacyKey != canonical {
			rollbackErr = errors.Join(rollbackErr, saveEditionToken(h, configDir, legacyKey, blob))
		}
		rollbackErr = errors.Join(rollbackErr, tokenSaveProfiles(configDir, cloneProfilesConfig(profilesSnapshot)))
		rollbackErr = errors.Join(rollbackErr, restoreTokenMarker(configDir, markerSnapshot))
		if rollbackErr != nil {
			return errors.Join(operationErr, fmt.Errorf("rollback legacy TokenStoreV2 migration: %w", rollbackErr))
		}
		return operationErr
	}
	if err := saveEditionToken(h, configDir, canonical, blob); err != nil {
		return rollback(err)
	}
	if err := tokenUpsertProfile(configDir, data, makeCurrent); err != nil {
		return rollback(err)
	}
	if legacyKey != canonical {
		if err := deleteEditionToken(h, configDir, legacyKey); err != nil {
			return rollback(err)
		}
	}
	if err := tokenBumpMarkerGeneration(configDir, false, data.Generation); err != nil {
		return rollback(err)
	}
	return nil
}

// ReadTokenMarkerGeneration reads the lightweight publication marker without
// opening Keychain. present=false represents logout/deletion and invalidates
// every in-memory snapshot, including legacy generation-zero entries.
func ReadTokenMarkerGeneration(configDir string) (generation uint64, present bool, err error) {
	data, err := tokenReadFile(filepath.Join(configDir, tokenJSONFile))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	var marker TokenMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return 0, true, fmt.Errorf("parse token publication marker: %w", err)
	}
	return marker.Generation, true, nil
}

func writeTokenMarkerGeneration(configDir string, manual bool, generation uint64) error {
	return writeTokenMarker(configDir, manual, generation)
}

// bumpTokenMarkerGeneration publishes a metadata-only credential change
// (for example current-profile selection) without rewriting token blobs. The
// optional floor keeps the publication generation ahead of the selected
// credential even when migrating an old/missing marker.
func bumpTokenMarkerGeneration(configDir string, manual bool, floor uint64) error {
	generation, _, err := ReadTokenMarkerGeneration(configDir)
	if err != nil {
		return err
	}
	if floor > generation {
		generation = floor
	}
	if generation == ^uint64(0) {
		return fmt.Errorf("token generation overflow")
	}
	return writeTokenMarkerGeneration(configDir, manual, generation+1)
}

func manualTokenMarkerActive(configDir string) (bool, error) {
	data, err := tokenReadFile(filepath.Join(configDir, tokenJSONFile))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var marker TokenMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		// Historical hosts only require the marker's presence. A malformed old
		// marker must not make profile authentication unusable.
		return false, nil
	}
	return marker.ManualToken, nil
}

// ManualTokenMarkerActive reports whether the default credential is the
// identity-less token installed by `auth login --token`. Explicit profile
// requests intentionally ignore this override.
func ManualTokenMarkerActive(configDir string) (bool, error) {
	return manualTokenMarkerActive(configDir)
}

// DeleteTokenMarker removes the token.json marker file.
func DeleteTokenMarker(configDir string) error {
	if err := tokenRemove(filepath.Join(configDir, tokenJSONFile)); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := tokenSyncDirectory(configDir); err != nil {
		return fmt.Errorf("sync token marker deletion: %w", err)
	}
	return nil
}

// SaveTokenData persists TokenData. When an edition hook (SaveToken) is
// registered, it delegates entirely to the hook; otherwise it falls back
// to the default keychain-based storage.
func SaveTokenData(configDir string, data *TokenData) error {
	profile := RuntimeProfile()
	return withProfilesLock(configDir, func() error {
		return saveTokenDataLockedForProfile(configDir, profile, data)
	})
}

// saveTokenDataLocked performs the keychain + profiles.json + legacy mirror
// writes assuming the auth dual-layer lock is already held. Callers that
// already hold the lock (OAuthProvider refresh path, the legacy secure->keychain
// migration in LoadTokenDataForProfile) must use this instead of SaveTokenData
// to avoid deadlocking on the non-reentrant lock.
func saveTokenDataLocked(configDir string, data *TokenData) (retErr error) {
	return saveTokenDataLockedForProfile(configDir, RuntimeProfile(), data)
}

// saveTokenDataLockedForProfile is the selector-pinned transaction used by
// long-running token providers. The selector must be captured before the
// operation starts; consulting RuntimeProfile midway through a refresh can
// write profile A's rotated credential into profile B's selected state.
func saveTokenDataLockedForProfile(configDir, runtimeProfile string, data *TokenData) (retErr error) {
	if data == nil {
		return fmt.Errorf("token data is nil")
	}
	original := data
	working := *data
	data = &working
	data.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := assignNextTokenGeneration(configDir, data); err != nil {
		return fmt.Errorf("prepare token generation: %w", err)
	}
	defer func() {
		if retErr == nil {
			*original = *data
		}
	}()
	if h := edition.Get(); editionTokenStoreConfigured(h) {
		if err := validateEditionTokenStore(h); err != nil {
			return err
		}
		return saveTokenViaHookTransaction(h, configDir, runtimeProfile, data)
	}
	if data != nil && strings.TrimSpace(data.CorpID) != "" {
		corpID := strings.TrimSpace(data.CorpID)
		userID := strings.TrimSpace(data.UserID)
		cfg, err := tokenLoadProfiles(configDir)
		if err != nil {
			return err
		}
		if err := ensureProfilesWritable(cfg); err != nil {
			return err
		}
		runtimeSelector := strings.TrimSpace(runtimeProfile)
		makeCurrent := runtimeSelector == ""
		exactSelector := profileSelector(corpID, userID)
		mirrorOrg := makeCurrent ||
			exactProfileSelectorForCorp(cfg, corpID, cfg.OrgCurrentProfiles[corpID]) == exactSelector
		existingIdentity := profileIndexByIdentity(cfg, corpID, userID) >= 0
		upgradesLegacyProfile := !existingIdentity && userID != "" && legacyProfileIndexByCorpID(cfg, corpID) >= 0
		logging.AuthDebug(
			"auth.token.persist.plan",
			"corp_id", corpID,
			"user_id", userID,
			"user_name", strings.TrimSpace(data.UserName),
			"identity_selector", exactSelector,
			"existing_identity", existingIdentity,
			"upgrades_legacy_profile", upgradesLegacyProfile,
			"profiles_before", len(cfg.Profiles),
			"runtime_profile", runtimeSelector,
			"write_identity_slot", userID != "",
			"write_org_mirror", mirrorOrg,
			"write_global_mirror", makeCurrent,
		)
		snapshot, err := snapshotTokenPersistence(configDir, cfg, corpID, userID, mirrorOrg)
		if err != nil {
			return err
		}
		preserveManualDefault := !makeCurrent &&
			snapshot.marker.known &&
			snapshot.marker.exists &&
			snapshot.marker.manual
		rollback := func(operationErr error) error {
			if rollbackErr := restoreTokenPersistence(configDir, snapshot); rollbackErr != nil {
				return errors.Join(operationErr, fmt.Errorf("rollback token persistence: %w", rollbackErr))
			}
			return operationErr
		}
		if userID != "" {
			if err := tokenSaveKeychainForIdentity(corpID, userID, data); err != nil {
				return rollback(err)
			}
		} else {
			for _, profile := range cfg.Profiles {
				if strings.TrimSpace(profile.CorpID) == corpID && strings.TrimSpace(profile.UserID) != "" {
					return fmt.Errorf("cannot store profile for corpId %q without userId because account identities already exist", corpID)
				}
			}
		}
		if err := tokenUpsertProfile(configDir, data, makeCurrent); err != nil {
			return rollback(err)
		}
		if mirrorOrg {
			if err := tokenSaveKeychainForCorpID(corpID, data); err != nil {
				return rollback(err)
			}
		}
		if makeCurrent {
			if err := tokenSaveKeychain(data); err != nil {
				return rollback(err)
			}
		} else if !preserveManualDefault {
			if err := tokenSyncLegacyMirror(configDir); err != nil {
				return rollback(err)
			}
		}
		if preserveManualDefault {
			if err := tokenWriteMarkerGeneration(configDir, true, data.Generation); err != nil {
				return rollback(err)
			}
		} else if err := tokenWriteMarkerGeneration(configDir, false, data.Generation); err != nil {
			return rollback(err)
		}
		logging.AuthDebug(
			"auth.token.persist.done",
			"corp_id", corpID,
			"user_id", userID,
			"user_name", strings.TrimSpace(data.UserName),
			"identity_selector", exactSelector,
			"write_identity_slot", userID != "",
			"write_org_mirror", mirrorOrg,
			"write_global_mirror", makeCurrent,
		)
		return nil
	}
	legacySnapshot, err := snapshotTokenSlot(tokenLoadKeychain)
	if err != nil {
		return err
	}
	markerSnapshot, err := snapshotTokenMarker(configDir)
	if err != nil {
		return err
	}
	if err := tokenSaveKeychain(data); err != nil {
		return err
	}
	if err := tokenWriteMarkerGeneration(configDir, true, data.Generation); err != nil {
		var rollbackErr error
		if restoreErr := restoreTokenSlot(
			legacySnapshot,
			tokenSaveKeychain,
			tokenDeleteKeychain,
		); restoreErr != nil {
			rollbackErr = errors.Join(rollbackErr, restoreErr)
		}
		if restoreErr := restoreTokenMarker(configDir, markerSnapshot); restoreErr != nil {
			rollbackErr = errors.Join(rollbackErr, restoreErr)
		}
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback manual token persistence: %w", rollbackErr))
		}
		return err
	}
	return nil
}

func saveTokenViaHookTransaction(h *edition.Hooks, configDir, profile string, data *TokenData) error {
	if err := validateEditionTokenStore(h); err != nil {
		return err
	}
	storeProfile := strings.TrimSpace(profile)
	makeCurrent := false
	if h.TokenStoreV2 != nil {
		var err error
		storeProfile, makeCurrent, err = canonicalEditionProfileForData(configDir, profile, data)
		if err != nil {
			return err
		}
	}
	markerSnapshot, err := snapshotTokenMarker(configDir)
	if err != nil {
		return err
	}
	profilesSnapshot, err := tokenLoadProfiles(configDir)
	if err != nil {
		return err
	}
	profilesSnapshot = cloneProfilesConfig(profilesSnapshot)
	var previous []byte
	previousExists := false
	if loaded, loadErr := loadEditionToken(h, configDir, storeProfile); loadErr == nil {
		previous = append([]byte(nil), loaded...)
		previousExists = true
	} else if !errors.Is(loadErr, ErrTokenDataNotFound) && !errors.Is(loadErr, os.ErrNotExist) {
		return fmt.Errorf("snapshot hook token: %w", loadErr)
	}
	rollback := func(operationErr error) error {
		var rollbackErr error
		if previousExists {
			if restoreErr := saveEditionToken(h, configDir, storeProfile, previous); restoreErr != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore hook token: %w", restoreErr))
			}
		} else if restoreErr := deleteEditionToken(h, configDir, storeProfile); restoreErr != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("remove partially-written hook token: %w", restoreErr))
		}
		if restoreErr := tokenSaveProfiles(configDir, cloneProfilesConfig(profilesSnapshot)); restoreErr != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore profile metadata: %w", restoreErr))
		}
		if restoreErr := restoreTokenMarker(configDir, markerSnapshot); restoreErr != nil {
			rollbackErr = errors.Join(rollbackErr, restoreErr)
		}
		if rollbackErr != nil {
			return errors.Join(operationErr, fmt.Errorf("rollback failed hook token save: %w", rollbackErr))
		}
		return operationErr
	}
	if err := saveTokenViaHook(h, configDir, storeProfile, data); err != nil {
		return rollback(err)
	}
	if h.TokenStoreV2 != nil && storeProfile != "" {
		if err := tokenUpsertProfile(configDir, data, makeCurrent); err != nil {
			return rollback(fmt.Errorf("publish profile metadata: %w", err))
		}
	}
	manualMarker := h.TokenStoreV2 != nil && storeProfile == ""
	if h.TokenStoreV2 != nil && !makeCurrent && markerSnapshot.exists && markerSnapshot.manual {
		manualMarker = true
	}
	if err := tokenWriteMarkerGeneration(configDir, manualMarker, data.Generation); err == nil {
		return nil
	} else {
		return rollback(err)
	}
}

func assignNextTokenGeneration(configDir string, data *TokenData) error {
	markerGeneration, _, err := ReadTokenMarkerGeneration(configDir)
	if err != nil {
		return err
	}
	base := markerGeneration
	if data.Generation > base {
		base = data.Generation
	}
	if base == ^uint64(0) {
		return fmt.Errorf("token generation overflow")
	}
	data.Generation = base + 1
	return nil
}

func saveTokenViaHook(h *edition.Hooks, configDir, profile string, data *TokenData) error {
	jsonData, err := tokenJSONMarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling token data for hook: %w", err)
	}
	return saveEditionToken(h, configDir, profile, jsonData)
}

// LoadTokenData reads TokenData. When an edition hook (LoadToken) is
// registered, it delegates entirely to the hook; otherwise it falls back
// to keychain with legacy .data migration.
func LoadTokenData(configDir string) (*TokenData, error) {
	return LoadTokenDataForProfile(configDir, RuntimeProfile())
}

// LoadTokenDataForProfile reads TokenData for a profile selector without mutating
// currentProfile. Empty selector follows the default resolution chain.
func LoadTokenDataForProfile(configDir, profile string) (*TokenData, error) {
	var result *TokenData
	err := withProfilesLock(configDir, func() error {
		var loadErr error
		if h := edition.Get(); editionTokenStoreConfigured(h) {
			if hookErr := validateEditionTokenStore(h); hookErr != nil {
				return hookErr
			}
			var jsonData []byte
			var hookErr error
			if h.TokenStoreV2 != nil {
				jsonData, hookErr = loadEditionTokenV2Locked(h, configDir, profile)
			} else {
				jsonData, hookErr = loadEditionToken(h, configDir, profile)
			}
			if hookErr != nil {
				return hookErr
			}
			td, hookErr := parseEditionTokenBlob(jsonData)
			if hookErr != nil {
				return hookErr
			}
			result = td
			return nil
		}
		result, loadErr = loadTokenDataForProfileLocked(configDir, profile)
		return loadErr
	})
	return result, err
}

func loadTokenDataForProfileLocked(configDir, profile string) (*TokenData, error) {
	// Default: keychain with legacy .data migration
	if strings.TrimSpace(profile) == "" {
		manual, err := manualTokenMarkerActive(configDir)
		if err != nil {
			return nil, err
		}
		if manual {
			data, loadErr := tokenLoadKeychain()
			if loadErr == nil && data != nil && strings.TrimSpace(data.CorpID) == "" {
				return data, nil
			}
			if loadErr != nil && !errors.Is(loadErr, ErrTokenDataNotFound) {
				return nil, loadErr
			}
		}
	}
	selected, err := tokenResolveProfile(configDir, profile)
	if err != nil {
		return nil, err
	}
	if selected != nil {
		data, err := tokenLoadProfileIdentity(*selected)
		if err == nil {
			return data, nil
		}
		if strings.TrimSpace(profile) != "" || !errors.Is(err, ErrTokenDataNotFound) {
			return nil, err
		}
		// No explicit --profile: `selected` is the resolved current/primary
		// profile. Only fall back to the legacy single slot when it belongs to
		// the SAME org; otherwise surface the error instead of silently acting
		// as a different organization (the legacy mirror may have drifted).
		if legacy, lerr := tokenLoadKeychain(); lerr == nil && legacy != nil &&
			strings.TrimSpace(legacy.CorpID) == strings.TrimSpace(selected.CorpID) &&
			(strings.TrimSpace(selected.UserID) == "" || strings.TrimSpace(legacy.UserID) == strings.TrimSpace(selected.UserID)) {
			return legacy, nil
		} else if lerr != nil && !errors.Is(lerr, ErrTokenDataNotFound) {
			return nil, lerr
		}
		return nil, err
	}
	cfg, err := tokenLoadProfiles(configDir)
	if err != nil {
		return nil, err
	}
	if cfg != nil && cfg.Version >= profilesVersion {
		return nil, ErrTokenDataNotFound
	}
	if tokenKeychainExists() {
		return tokenLoadKeychain()
	}
	data, err := tokenLoadSecure(configDir)
	if err != nil {
		return nil, err
	}
	// One-time legacy secure-store -> keychain migration. This read path may run
	// while the refresh lock is already held, so use the lock-free saver.
	if err := saveTokenDataLockedForProfile(configDir, profile, data); err == nil {
		_ = tokenDeleteSecure(configDir)
	}
	return data, nil
}

func tokenLoadProfileIdentity(profile Profile) (*TokenData, error) {
	if strings.TrimSpace(profile.UserID) == "" {
		return tokenLoadKeychainForCorpID(profile.CorpID)
	}
	data, err := tokenLoadKeychainIdentity(profile.CorpID, profile.UserID)
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, ErrTokenDataNotFound) {
		return nil, err
	}
	orgData, orgErr := tokenLoadKeychainForCorpID(profile.CorpID)
	if orgErr != nil {
		if errors.Is(orgErr, ErrTokenDataNotFound) {
			return nil, err
		}
		return nil, orgErr
	}
	if strings.TrimSpace(orgData.UserID) == "" {
		return nil, fmt.Errorf("organization token mirror for corpId %q has no userId; cannot use it for profile %q", profile.CorpID, ProfileSelector(profile))
	}
	if strings.TrimSpace(orgData.UserID) != strings.TrimSpace(profile.UserID) {
		return nil, err
	}
	if saveErr := tokenSaveKeychainForIdentity(profile.CorpID, profile.UserID, orgData); saveErr != nil {
		return nil, saveErr
	}
	return orgData, nil
}

// DeleteTokenData removes token data. When an edition hook (DeleteToken) is
// registered, it delegates entirely to the hook; otherwise it falls back
// to keychain + legacy cleanup.
func DeleteTokenData(configDir string) error {
	return DeleteTokenDataForProfile(configDir, RuntimeProfile())
}

// DeleteTokenDataForProfile removes one profile's token data. Empty selector
// removes the current/default profile, falling back to legacy single-slot auth.
func DeleteTokenDataForProfile(configDir, profile string) error {
	return withProfilesLock(configDir, func() error {
		if h := edition.Get(); editionTokenStoreConfigured(h) {
			if err := validateEditionTokenStore(h); err != nil {
				return err
			}
			return deleteTokenViaHookTransaction(h, configDir, profile, !editionTokenStoreSupportsProfiles(h))
		}
		return deleteTokenDataForProfileLocked(configDir, profile)
	})
}

func deleteTokenViaHookTransaction(h *edition.Hooks, configDir, profile string, removeMarker bool) error {
	if err := validateEditionTokenStore(h); err != nil {
		return err
	}
	if h.TokenStoreV2 != nil {
		return deleteTokenV2TransactionLocked(h, configDir, profile)
	}
	markerSnapshot, err := snapshotTokenMarker(configDir)
	if err != nil {
		return err
	}
	previous, loadErr := loadEditionToken(h, configDir, profile)
	previousExists := loadErr == nil
	if loadErr != nil && !errors.Is(loadErr, ErrTokenDataNotFound) && !errors.Is(loadErr, os.ErrNotExist) {
		return fmt.Errorf("snapshot hook token for deletion: %w", loadErr)
	}
	if err := deleteEditionToken(h, configDir, profile); err != nil {
		var rollbackErr error
		if previousExists {
			if restoreErr := saveEditionToken(h, configDir, profile, previous); restoreErr != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore hook token: %w", restoreErr))
			}
		}
		if restoreErr := restoreTokenMarker(configDir, markerSnapshot); restoreErr != nil {
			rollbackErr = errors.Join(rollbackErr, restoreErr)
		}
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback failed hook token deletion: %w", rollbackErr))
		}
		return err
	}
	var publishErr error
	if removeMarker {
		publishErr = tokenDeleteMarker(configDir)
	} else {
		publishErr = bumpTokenMarkerGeneration(configDir, false, 0)
	}
	if publishErr == nil {
		return nil
	} else {
		var rollbackErr error
		if previousExists {
			if restoreErr := saveEditionToken(h, configDir, profile, previous); restoreErr != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore hook token: %w", restoreErr))
			}
		}
		if restoreErr := restoreTokenMarker(configDir, markerSnapshot); restoreErr != nil {
			rollbackErr = errors.Join(rollbackErr, restoreErr)
		}
		if rollbackErr != nil {
			return errors.Join(publishErr, fmt.Errorf("rollback hook token deletion: %w", rollbackErr))
		}
		return publishErr
	}
}

type editionBlobSnapshot struct {
	key    string
	blob   []byte
	exists bool
}

func deleteTokenV2TransactionLocked(h *edition.Hooks, configDir, selector string) error {
	selector = strings.TrimSpace(selector)
	cfg, err := tokenLoadProfiles(configDir)
	if err != nil {
		return err
	}
	if err := ensureProfilesWritable(cfg); err != nil {
		return err
	}
	profilesSnapshot := cloneProfilesConfig(cfg)
	markerSnapshot, err := snapshotTokenMarker(configDir)
	if err != nil {
		return err
	}

	keys := make([]string, 0, 2)
	removeSelector := ""
	deletingManual := selector == "" && markerSnapshot.manual
	if deletingManual || (selector == "" && strings.TrimSpace(cfg.CurrentProfile) == "") {
		keys = append(keys, "")
	} else {
		effective := selector
		if effective == "" {
			effective = strings.TrimSpace(cfg.CurrentProfile)
		}
		selected, exact, resolveErr := tokenResolveDeletion(cfg, effective)
		if resolveErr != nil {
			// Compatibility cleanup for a raw-key orphan created by an older V2
			// adapter. It has no reconstructable metadata, so remove only that
			// exact raw slot and leave profiles.json untouched.
			if _, loadErr := loadEditionToken(h, configDir, selector); loadErr == nil {
				keys = append(keys, selector)
			} else {
				return resolveErr
			}
		} else if exact {
			keys = append(keys, ProfileSelector(*selected))
			removeSelector = ProfileSelector(*selected)
		} else {
			for _, candidate := range profilesForCorpID(cfg, selected.CorpID) {
				if strings.TrimSpace(candidate.UserID) == "" {
					return fmt.Errorf("TokenStoreV2 profile %q has no userId", ProfileSelector(*candidate))
				}
				keys = append(keys, ProfileSelector(*candidate))
			}
			removeSelector = selected.CorpID
		}
	}
	if len(keys) == 0 {
		return ErrTokenDataNotFound
	}

	snapshots := make([]editionBlobSnapshot, 0, len(keys))
	for _, key := range keys {
		blob, loadErr := loadEditionToken(h, configDir, key)
		if loadErr == nil {
			snapshots = append(snapshots, editionBlobSnapshot{key: key, blob: append([]byte(nil), blob...), exists: true})
			continue
		}
		if errors.Is(loadErr, ErrTokenDataNotFound) || errors.Is(loadErr, os.ErrNotExist) {
			snapshots = append(snapshots, editionBlobSnapshot{key: key})
			continue
		}
		return fmt.Errorf("snapshot hook token for deletion: %w", loadErr)
	}
	rollback := func(operationErr error) error {
		var rollbackErr error
		for _, snapshot := range snapshots {
			if snapshot.exists {
				rollbackErr = errors.Join(rollbackErr, saveEditionToken(h, configDir, snapshot.key, snapshot.blob))
			} else {
				rollbackErr = errors.Join(rollbackErr, deleteEditionToken(h, configDir, snapshot.key))
			}
		}
		rollbackErr = errors.Join(rollbackErr, tokenSaveProfiles(configDir, cloneProfilesConfig(profilesSnapshot)))
		rollbackErr = errors.Join(rollbackErr, restoreTokenMarker(configDir, markerSnapshot))
		if rollbackErr != nil {
			return errors.Join(operationErr, fmt.Errorf("rollback TokenStoreV2 deletion: %w", rollbackErr))
		}
		return operationErr
	}
	for _, key := range keys {
		if err := deleteEditionToken(h, configDir, key); err != nil {
			return rollback(err)
		}
	}
	if removeSelector != "" {
		if _, err := tokenRemoveProfile(configDir, removeSelector); err != nil {
			return rollback(err)
		}
	}
	updated, err := tokenLoadProfiles(configDir)
	if err != nil {
		return rollback(err)
	}
	if markerSnapshot.manual && !deletingManual {
		if err := tokenBumpMarkerGeneration(configDir, true, markerSnapshot.generation); err != nil {
			return rollback(err)
		}
	} else if len(updated.Profiles) == 0 {
		if err := tokenDeleteMarker(configDir); err != nil {
			return rollback(err)
		}
	} else if err := tokenBumpMarkerGeneration(configDir, false, markerSnapshot.generation); err != nil {
		return rollback(err)
	}
	return nil
}

func deleteTokenDataForProfileLocked(configDir, profile string) error {
	if strings.TrimSpace(profile) == "" {
		manual, err := manualTokenMarkerActive(configDir)
		if err != nil {
			return err
		}
		if manual {
			return deleteManualTokenDataLocked(configDir)
		}
	}
	if err := profilesEnsureMigration(configDir); err != nil {
		return err
	}
	cfg, err := tokenLoadProfiles(configDir)
	if err != nil {
		return err
	}
	effectiveSelector := strings.TrimSpace(profile)
	if effectiveSelector == "" {
		effectiveSelector = strings.TrimSpace(cfg.CurrentProfile)
	}
	var selected *Profile
	exact := false
	if effectiveSelector != "" {
		selected, exact, err = tokenResolveDeletion(cfg, effectiveSelector)
		if err != nil {
			return err
		}
	}
	if selected != nil {
		removed := *selected
		originalCfg := cloneProfilesConfig(cfg)
		identitySnapshots, err := snapshotDeletionIdentities(cfg, removed, exact)
		if err != nil {
			return err
		}
		orgSnapshot := snapshotTokenSlotForDeletion(func() (*TokenData, error) {
			return tokenLoadKeychainForCorpID(removed.CorpID)
		})
		legacySnapshot := snapshotTokenSlotForDeletion(tokenLoadKeychain)
		markerSnapshot := snapshotTokenMarkerForDeletion(configDir)

		// Clean the deprecated secure-store copy before changing the profile
		// transaction. A cleanup failure therefore leaves all current metadata
		// and keychain slots untouched.
		if err := tokenDeleteSecure(configDir); err != nil {
			return err
		}

		removeSelector := removed.CorpID
		orgCurrent := false
		if exact {
			removeSelector = ProfileSelector(removed)
			orgCurrent = exactProfileSelectorForCorp(
				cfg,
				removed.CorpID,
				cfg.OrgCurrentProfiles[removed.CorpID],
			) == ProfileSelector(removed)
		}
		if _, err := tokenRemoveProfile(configDir, removeSelector); err != nil {
			return err
		}
		rollback := func(operationErr error) error {
			if rollbackErr := restoreProfileDeletion(
				configDir,
				originalCfg,
				identitySnapshots,
				removed.CorpID,
				orgSnapshot,
				legacySnapshot,
				markerSnapshot,
			); rollbackErr != nil {
				return errors.Join(operationErr, fmt.Errorf("rollback profile deletion: %w", rollbackErr))
			}
			return operationErr
		}

		if !exact || orgCurrent {
			updated, loadErr := tokenLoadProfiles(configDir)
			if loadErr != nil {
				return rollback(loadErr)
			}
			replacementSelector := updated.OrgCurrentProfiles[removed.CorpID]
			if exact && replacementSelector != "" {
				replacement, _, resolveErr := tokenResolveSelection(configDir, updated, replacementSelector)
				if resolveErr != nil {
					return rollback(resolveErr)
				}
				if err := tokenSyncOrganizationMirror(*replacement); err != nil {
					return rollback(err)
				}
			} else if err := tokenDeleteKeychainForCorpID(removed.CorpID); err != nil {
				return rollback(err)
			}
		}
		preserveManualDefault := markerSnapshot.known &&
			markerSnapshot.exists &&
			markerSnapshot.manual
		if !preserveManualDefault {
			if err := tokenSyncSelectedMirror(configDir); err != nil {
				return rollback(err)
			}
		} else if err := tokenBumpMarkerGeneration(configDir, true, markerSnapshot.generation); err != nil {
			return rollback(err)
		}
		for _, snapshot := range identitySnapshots {
			if err := tokenDeleteKeychainIdentity(snapshot.profile.CorpID, snapshot.profile.UserID); err != nil {
				return rollback(err)
			}
		}
		return nil
	}

	keychainErr := tokenDeleteKeychain()
	legacyErr := tokenDeleteSecure(configDir)
	markerErr := tokenDeleteMarker(configDir)
	if keychainErr != nil {
		return keychainErr
	}
	if legacyErr != nil {
		return legacyErr
	}
	return markerErr
}

func deleteManualTokenDataLocked(configDir string) error {
	legacySnapshot := snapshotTokenSlotForDeletion(tokenLoadKeychain)
	if err := tokenDeleteSecure(configDir); err != nil {
		return err
	}
	if err := tokenDeleteKeychain(); err != nil {
		return err
	}
	if err := tokenDeleteMarker(configDir); err != nil {
		if legacySnapshot.known {
			if rollbackErr := restoreTokenSlot(
				legacySnapshot,
				tokenSaveKeychain,
				tokenDeleteKeychain,
			); rollbackErr != nil {
				return errors.Join(err, fmt.Errorf("rollback manual token deletion: %w", rollbackErr))
			}
		}
		return err
	}
	return nil
}

type deletionIdentitySnapshot struct {
	profile Profile
	token   *TokenData
}

type tokenSlotSnapshot struct {
	token  *TokenData
	known  bool
	exists bool
}

type tokenMarkerSnapshot struct {
	known      bool
	exists     bool
	manual     bool
	generation uint64
}

type tokenPersistenceSnapshot struct {
	profiles *ProfilesConfig
	corpID   string
	userID   string
	identity tokenSlotSnapshot
	org      tokenSlotSnapshot
	legacy   tokenSlotSnapshot
	marker   tokenMarkerSnapshot
}

func cloneProfilesConfig(cfg *ProfilesConfig) *ProfilesConfig {
	if cfg == nil {
		return nil
	}
	cloned := *cfg
	cloned.Profiles = append([]Profile(nil), cfg.Profiles...)
	for i := range cloned.Profiles {
		cloned.Profiles[i].AuthorizedDomains = append(
			[]string(nil),
			cloned.Profiles[i].AuthorizedDomains...,
		)
	}
	if cfg.OrgCurrentProfiles != nil {
		cloned.OrgCurrentProfiles = make(map[string]string, len(cfg.OrgCurrentProfiles))
		for corpID, selector := range cfg.OrgCurrentProfiles {
			cloned.OrgCurrentProfiles[corpID] = selector
		}
	}
	return &cloned
}

func snapshotDeletionIdentities(cfg *ProfilesConfig, removed Profile, exact bool) ([]deletionIdentitySnapshot, error) {
	var profiles []Profile
	if exact {
		profiles = []Profile{removed}
	} else {
		for _, candidate := range cfg.Profiles {
			if strings.TrimSpace(candidate.CorpID) == strings.TrimSpace(removed.CorpID) {
				profiles = append(profiles, candidate)
			}
		}
	}
	snapshots := make([]deletionIdentitySnapshot, 0, len(profiles))
	for _, candidate := range profiles {
		if strings.TrimSpace(candidate.UserID) == "" {
			continue
		}
		data, err := tokenLoadKeychainIdentity(candidate.CorpID, candidate.UserID)
		if err != nil {
			if errors.Is(err, ErrTokenDataNotFound) {
				snapshots = append(snapshots, deletionIdentitySnapshot{profile: candidate})
				continue
			}
			// A damaged target slot must remain removable. It cannot be restored
			// during rollback, but every readable slot in the same transaction
			// still is.
			snapshots = append(snapshots, deletionIdentitySnapshot{profile: candidate})
			continue
		}
		snapshots = append(snapshots, deletionIdentitySnapshot{profile: candidate, token: data})
	}
	return snapshots, nil
}

func snapshotTokenSlot(load func() (*TokenData, error)) (tokenSlotSnapshot, error) {
	data, err := load()
	if err != nil {
		if errors.Is(err, ErrTokenDataNotFound) {
			return tokenSlotSnapshot{known: true}, nil
		}
		return tokenSlotSnapshot{}, err
	}
	return tokenSlotSnapshot{token: data, known: true, exists: data != nil}, nil
}

func snapshotTokenSlotForDeletion(load func() (*TokenData, error)) tokenSlotSnapshot {
	snapshot, err := snapshotTokenSlot(load)
	if err != nil {
		return tokenSlotSnapshot{}
	}
	return snapshot
}

func snapshotTokenMarker(configDir string) (tokenMarkerSnapshot, error) {
	data, err := tokenReadFile(filepath.Join(configDir, tokenJSONFile))
	if err != nil {
		if os.IsNotExist(err) {
			return tokenMarkerSnapshot{known: true}, nil
		}
		return tokenMarkerSnapshot{}, err
	}
	var marker TokenMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return tokenMarkerSnapshot{known: true, exists: true}, nil
	}
	return tokenMarkerSnapshot{known: true, exists: true, manual: marker.ManualToken, generation: marker.Generation}, nil
}

func snapshotTokenMarkerForDeletion(configDir string) tokenMarkerSnapshot {
	snapshot, err := snapshotTokenMarker(configDir)
	if err != nil {
		return tokenMarkerSnapshot{}
	}
	return snapshot
}

func restoreProfileDeletion(
	configDir string,
	cfg *ProfilesConfig,
	identities []deletionIdentitySnapshot,
	corpID string,
	org tokenSlotSnapshot,
	legacy tokenSlotSnapshot,
	marker tokenMarkerSnapshot,
) error {
	var rollbackErr error
	for _, snapshot := range identities {
		if snapshot.token == nil {
			continue
		}
		if err := tokenSaveKeychainForIdentity(
			snapshot.profile.CorpID,
			snapshot.profile.UserID,
			snapshot.token,
		); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	if err := tokenSaveProfiles(configDir, cloneProfilesConfig(cfg)); err != nil {
		rollbackErr = errors.Join(rollbackErr, err)
	}
	if org.known {
		if org.exists {
			if err := tokenSaveKeychainForCorpID(corpID, org.token); err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
			}
		} else if err := tokenDeleteKeychainForCorpID(corpID); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	if legacy.known {
		if legacy.exists {
			if err := tokenSaveKeychain(legacy.token); err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
			}
		} else if err := tokenDeleteKeychain(); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	if marker.known {
		if err := restoreTokenMarker(configDir, marker); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	return rollbackErr
}

func snapshotTokenPersistence(
	configDir string,
	cfg *ProfilesConfig,
	corpID, userID string,
	includeOrganization bool,
) (tokenPersistenceSnapshot, error) {
	snapshot := tokenPersistenceSnapshot{
		profiles: cloneProfilesConfig(cfg),
		corpID:   corpID,
		userID:   userID,
	}
	var err error
	if strings.TrimSpace(userID) != "" {
		snapshot.identity, err = snapshotTokenSlot(func() (*TokenData, error) {
			return tokenLoadKeychainIdentity(corpID, userID)
		})
		if err != nil {
			return tokenPersistenceSnapshot{}, err
		}
	}
	if includeOrganization {
		snapshot.org, err = snapshotTokenSlot(func() (*TokenData, error) {
			return tokenLoadKeychainForCorpID(corpID)
		})
		if err != nil {
			return tokenPersistenceSnapshot{}, err
		}
	}
	snapshot.legacy, err = snapshotTokenSlot(tokenLoadKeychain)
	if err != nil {
		return tokenPersistenceSnapshot{}, err
	}
	snapshot.marker, err = snapshotTokenMarker(configDir)
	if err != nil {
		return tokenPersistenceSnapshot{}, err
	}
	return snapshot, nil
}

func restoreTokenPersistence(configDir string, snapshot tokenPersistenceSnapshot) error {
	var rollbackErr error
	if err := tokenSaveProfiles(configDir, cloneProfilesConfig(snapshot.profiles)); err != nil {
		rollbackErr = errors.Join(rollbackErr, err)
	}
	if strings.TrimSpace(snapshot.userID) != "" && snapshot.identity.known {
		if err := restoreTokenSlot(
			snapshot.identity,
			func(data *TokenData) error {
				return tokenSaveKeychainForIdentity(snapshot.corpID, snapshot.userID, data)
			},
			func() error {
				return tokenDeleteKeychainIdentity(snapshot.corpID, snapshot.userID)
			},
		); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	if snapshot.org.known {
		if err := restoreTokenSlot(
			snapshot.org,
			func(data *TokenData) error {
				return tokenSaveKeychainForCorpID(snapshot.corpID, data)
			},
			func() error {
				return tokenDeleteKeychainForCorpID(snapshot.corpID)
			},
		); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	if snapshot.legacy.known {
		if err := restoreTokenSlot(snapshot.legacy, tokenSaveKeychain, tokenDeleteKeychain); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	if snapshot.marker.known {
		if err := restoreTokenMarker(configDir, snapshot.marker); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	return rollbackErr
}

func restoreTokenSlot(
	snapshot tokenSlotSnapshot,
	save func(*TokenData) error,
	remove func() error,
) error {
	if snapshot.exists {
		return save(snapshot.token)
	}
	return remove()
}

func restoreTokenMarker(configDir string, marker tokenMarkerSnapshot) error {
	switch {
	case !marker.exists:
		return tokenDeleteMarker(configDir)
	case marker.manual:
		return tokenWriteMarkerGeneration(configDir, true, marker.generation)
	default:
		return tokenWriteMarkerGeneration(configDir, false, marker.generation)
	}
}

// DeleteAllTokenData removes all profile-scoped and legacy token data.
func DeleteAllTokenData(configDir string) error {
	return withProfilesLock(configDir, func() error {
		if h := edition.Get(); editionTokenStoreConfigured(h) {
			if err := validateEditionTokenStore(h); err != nil {
				return err
			}
			if h.TokenStoreV2 != nil {
				return deleteAllTokenV2TransactionLocked(h, configDir)
			}
			return deleteTokenViaHookTransaction(h, configDir, "", true)
		}
		var firstErr error
		// Sweep the complete auth-token namespace so orphan identity slots that
		// are not present in profiles.json cannot survive reset/logout --all.
		if e := tokenRemoveAuthTokenEntries(keychain.Service); e != nil {
			firstErr = e
		}
		if e := tokenRemove(ProfilesPath(configDir)); e != nil && !os.IsNotExist(e) && firstErr == nil {
			firstErr = e
		}
		// Sweep any quarantined corrupt-profiles files so they don't accumulate.
		if matches, _ := tokenGlob(ProfilesPath(configDir) + ".corrupt-*"); len(matches) > 0 {
			for _, m := range matches {
				if e := tokenRemove(m); e != nil && !os.IsNotExist(e) && firstErr == nil {
					firstErr = e
				}
			}
		}
		if e := tokenDeleteSecure(configDir); e != nil && firstErr == nil {
			firstErr = e
		}
		if e := tokenDeleteMarker(configDir); e != nil && firstErr == nil {
			firstErr = e
		}
		if firstErr != nil {
			// Preserve an explicit v2 empty registry so any stale mirror that
			// could not be removed is never imported on a later read.
			if e := profilesSave(configDir, &ProfilesConfig{Version: profilesVersion}); e != nil {
				return fmt.Errorf("%v; save logged-out profile tombstone: %w", firstErr, e)
			}
		}
		return firstErr
	})
}

func deleteAllTokenV2TransactionLocked(h *edition.Hooks, configDir string) error {
	cfg, err := tokenLoadProfiles(configDir)
	if err != nil {
		return err
	}
	if err := ensureProfilesWritable(cfg); err != nil {
		return err
	}
	profilesSnapshot := cloneProfilesConfig(cfg)
	markerSnapshot, err := snapshotTokenMarker(configDir)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(cfg.Profiles)+1)
	seen := make(map[string]struct{}, len(cfg.Profiles)+1)
	for _, profile := range cfg.Profiles {
		key := ProfileSelector(profile)
		if strings.TrimSpace(profile.CorpID) == "" || strings.TrimSpace(profile.UserID) == "" {
			return fmt.Errorf("TokenStoreV2 profile %q has no exact identity", key)
		}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}
	// Empty is the historical singleton/raw-current slot. A V2 DeleteAll hook
	// additionally sweeps non-enumerable hashed aliases/orphans.
	keys = append(keys, "")
	snapshots := make([]editionBlobSnapshot, 0, len(keys))
	for _, key := range keys {
		blob, loadErr := loadEditionToken(h, configDir, key)
		snapshot := editionBlobSnapshot{key: key}
		if loadErr == nil {
			snapshot.exists = true
			snapshot.blob = append([]byte(nil), blob...)
		} else if !errors.Is(loadErr, ErrTokenDataNotFound) && !errors.Is(loadErr, os.ErrNotExist) {
			return fmt.Errorf("snapshot TokenStoreV2 key for logout-all: %w", loadErr)
		}
		snapshots = append(snapshots, snapshot)
	}
	rollback := func(operationErr error) error {
		var rollbackErr error
		for _, snapshot := range snapshots {
			if snapshot.exists {
				rollbackErr = errors.Join(rollbackErr, saveEditionToken(h, configDir, snapshot.key, snapshot.blob))
			}
		}
		rollbackErr = errors.Join(rollbackErr, tokenSaveProfiles(configDir, cloneProfilesConfig(profilesSnapshot)))
		rollbackErr = errors.Join(rollbackErr, restoreTokenMarker(configDir, markerSnapshot))
		if rollbackErr != nil {
			return errors.Join(operationErr, fmt.Errorf("rollback TokenStoreV2 logout-all: %w", rollbackErr))
		}
		return operationErr
	}
	if h.TokenStoreV2.DeleteAll != nil {
		if err := h.TokenStoreV2.DeleteAll(configDir); err != nil {
			return rollback(err)
		}
	} else {
		for _, key := range keys {
			if err := deleteEditionToken(h, configDir, key); err != nil {
				return rollback(err)
			}
		}
	}
	if err := tokenSaveProfiles(configDir, &ProfilesConfig{Version: profilesVersion}); err != nil {
		return rollback(err)
	}
	if err := tokenDeleteMarker(configDir); err != nil {
		return rollback(err)
	}
	return nil
}

// RevokeTokenRemote calls the appropriate logout/revoke endpoint to invalidate the access token.
// Uses MCP revoke endpoint when clientID is from MCP, otherwise uses DingTalk logout.
// This should be called before deleting local token data.
// The function is best-effort: errors are returned but callers may choose to ignore them.
func RevokeTokenRemote(ctx context.Context) error {
	tokenData, err := tokenLoadData(tokenDefaultConfigDir())
	if err != nil || tokenData == nil {
		return nil
	}
	// Historical token records may not have Source. Preserve the legacy
	// process-wide MCP decision only for those records.
	if strings.TrimSpace(tokenData.Source) == "" && IsClientIDFromMCP() {
		copy := *tokenData
		copy.Source = "mcp"
		tokenData = &copy
	}
	return RevokeTokenRemoteForData(ctx, tokenData)
}

// RevokeTokenRemoteForData revokes the supplied account token using the
// credential source and client ID persisted with that exact identity.
func RevokeTokenRemoteForData(ctx context.Context, tokenData *TokenData) error {
	if tokenData == nil {
		return nil
	}
	clientID := strings.TrimSpace(tokenData.ClientID)
	if clientID == "" {
		clientID = ClientID()
	}
	if strings.EqualFold(strings.TrimSpace(tokenData.Source), "mcp") {
		return revokeTokenViaMCP(ctx, tokenData, clientID)
	}

	// Direct mode: use DingTalk logout endpoint.
	logoutURL, err := tokenParseURL(tokenLogoutURL)
	if err != nil {
		return fmt.Errorf("parsing logout URL: %w", err)
	}

	q := logoutURL.Query()
	q.Set("client_id", clientID)
	q.Set("continue", tokenLogoutContinueURL)
	logoutURL.RawQuery = q.Encode()

	req, err := tokenNewRequest(ctx, http.MethodGet, logoutURL.String(), nil)
	if err != nil {
		return fmt.Errorf("creating logout request: %w", err)
	}

	resp, err := tokenLogoutHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling logout endpoint: %w", err)
	}
	defer resp.Body.Close()

	// Accept 200 OK or 302 redirect as success.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return fmt.Errorf("logout endpoint returned status %d", resp.StatusCode)
	}

	return nil
}

// revokeTokenViaMCP revokes token via MCP endpoint.
func revokeTokenViaMCP(ctx context.Context, tokenData *TokenData, clientID string) error {
	revokeURL := tokenMCPBaseURL() + MCPRevokeTokenPath
	body := map[string]string{
		"clientId":    clientID,
		"accessToken": tokenData.AccessToken,
	}
	bodyBytes, err := tokenJSONMarshal(body)
	if err != nil {
		return fmt.Errorf("marshaling revoke request: %w", err)
	}

	req, err := tokenNewRequest(ctx, http.MethodPost, revokeURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("creating revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tokenRevokeHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling revoke endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke endpoint returned status %d", resp.StatusCode)
	}

	return nil
}

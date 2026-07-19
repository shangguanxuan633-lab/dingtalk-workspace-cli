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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

type legacyTokenGetter interface {
	GetToken() (string, string, error)
}

type accessTokenSnapshotGetter interface {
	GetTokenSnapshot(context.Context) (*authpkg.TokenData, error)
}

// AccessTokenSnapshot is the runtime-safe view of a credential. Refresh token
// material is intentionally excluded. ExpiresAt is required for process
// caching; sources without lifetime metadata are resolved on every request.
type AccessTokenSnapshot struct {
	AccessToken        string
	ExpiresAt          time.Time
	Source             string
	Generation         uint64
	ObservedGeneration uint64
	ProfileFingerprint string
	UpdatedAt          string
	// profile is the exact selector captured when this snapshot's cache key was
	// chosen. It is intentionally unexported: callers receive only the
	// non-reversible ProfileFingerprint, while auth recovery can keep its CAS
	// refresh bound to the original request profile.
	profile       string
	profilePinned bool
}

const accessTokenRefreshWindow = 5 * time.Minute

const (
	tokenFailureInitialBackoff = time.Second
	tokenFailureMaxBackoff     = 30 * time.Second
)

type tokenManagerKey struct {
	configDir string
	profile   string
}

type tokenManagerEntry struct {
	mu       sync.Mutex
	snapshot AccessTokenSnapshot
	failure  tokenManagerFailure
}

type tokenManagerFailure struct {
	err              error
	class            authpkg.RefreshFailureClass
	markerGeneration uint64
	markerPresent    bool
	retryAt          time.Time
	backoff          time.Duration
}

type tokenManagerTransientFailureError struct {
	cause error
}

func (e *tokenManagerTransientFailureError) Error() string {
	return "access token resolution temporarily failed"
}

func (e *tokenManagerTransientFailureError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// TokenManager is the single runtime entry point for OAuth, legacy, explicit,
// and edition-provided access tokens. Entries are isolated by canonical
// configDir and runtime profile.
type TokenManager struct {
	mu      sync.Mutex
	entries map[tokenManagerKey]*tokenManagerEntry
	now     func() time.Time
}

func NewTokenManager() *TokenManager {
	return &TokenManager{entries: make(map[tokenManagerKey]*tokenManagerEntry), now: time.Now}
}

var runtimeTokenManager = NewTokenManager()

var (
	newAccessTokenProvider = func(configDir, profile string) accessTokenGetter {
		disc := slog.New(slog.NewTextHandler(io.Discard, nil))
		provider := authpkg.NewOAuthProviderForProfile(configDir, disc, profile)
		configureOAuthProviderCompatibility(provider, configDir)
		return provider
	}
	newLegacyTokenManager = func(configDir string) legacyTokenGetter {
		manager := authpkg.NewManager(configDir, nil)
		configureLegacyAuthManagerCompatibility(manager)
		return manager
	}
)

// resolveAccessTokenFromDir loads OAuth then legacy token from configDir, applying
// the same host compatibility hooks as MCP. It mirrors the former body of
// getCachedRuntimeToken (excluding process-level cache and timing).
func resolveAccessTokenSnapshotFromDir(ctx context.Context, configDir, profile string) (AccessTokenSnapshot, error) {
	profile = strings.TrimSpace(profile)
	provider := newAccessTokenProvider(configDir, profile)
	if snapshotProvider, ok := provider.(accessTokenSnapshotGetter); ok {
		data, tokenErr := snapshotProvider.GetTokenSnapshot(ctx)
		if tokenErr == nil && data != nil && strings.TrimSpace(data.AccessToken) != "" {
			return AccessTokenSnapshot{
				AccessToken: strings.TrimSpace(data.AccessToken),
				ExpiresAt:   data.ExpiresAt,
				Source:      "oauth",
				Generation:  data.Generation,
				UpdatedAt:   data.UpdatedAt,
			}, nil
		}
		if tokenErr != nil && !errors.Is(tokenErr, authpkg.ErrTokenDataNotFound) {
			return AccessTokenSnapshot{}, tokenErr
		}
		if profile != "" {
			if tokenErr != nil {
				return AccessTokenSnapshot{}, tokenErr
			}
			return AccessTokenSnapshot{}, authpkg.ErrTokenDataNotFound
		}
		return resolveLegacyToken(configDir, tokenErr)
	}

	token, tokenErr := provider.GetAccessToken(ctx)
	if tokenErr == nil && strings.TrimSpace(token) != "" {
		return AccessTokenSnapshot{AccessToken: strings.TrimSpace(token), Source: "oauth_compat"}, nil
	}
	if tokenErr != nil && !errors.Is(tokenErr, authpkg.ErrTokenDataNotFound) {
		return AccessTokenSnapshot{}, tokenErr
	}
	if profile != "" {
		if tokenErr != nil {
			return AccessTokenSnapshot{}, tokenErr
		}
		return AccessTokenSnapshot{}, authpkg.ErrTokenDataNotFound
	}
	return resolveLegacyToken(configDir, tokenErr)
}

func resolveLegacyToken(configDir string, oauthErr error) (AccessTokenSnapshot, error) {
	manager := newLegacyTokenManager(configDir)
	leg, source, legacyErr := manager.GetToken()
	if legacyErr == nil && strings.TrimSpace(leg) != "" {
		return AccessTokenSnapshot{AccessToken: strings.TrimSpace(leg), Source: source}, nil
	}
	if legacyErr != nil && !errors.Is(legacyErr, os.ErrNotExist) {
		return AccessTokenSnapshot{}, legacyErr
	}
	if oauthErr != nil {
		return AccessTokenSnapshot{}, oauthErr
	}
	return AccessTokenSnapshot{}, authpkg.ErrTokenDataNotFound
}

func resolveAccessTokenFromDir(ctx context.Context, configDir string) (string, error) {
	snapshot, err := resolveAccessTokenSnapshotFromDir(ctx, configDir, strings.TrimSpace(authpkg.RuntimeProfile()))
	if err != nil {
		return "", err
	}
	return snapshot.AccessToken, nil
}

// ResolveAuxiliaryAccessToken resolves a bearer token for HTTP clients that should
// align with MCP tool calls. Non-empty explicitToken wins. When configDir matches
// the active edition config directory, the same process-cached path as MCP is used.
// Otherwise tokens are loaded from configDir with host compatibility hooks applied.
func ResolveAuxiliaryAccessToken(ctx context.Context, configDir, explicitToken string) (string, error) {
	snapshot, err := ResolveAuxiliaryAccessTokenSnapshot(ctx, configDir, explicitToken)
	if err != nil {
		return "", err
	}
	return snapshot.AccessToken, nil
}

// ResolveAuxiliaryAccessTokenForProfile resolves a token under an immutable
// logical profile lease. The selector is canonicalized once to corpId:userId;
// later process-wide profile switches cannot redirect this operation.
func ResolveAuxiliaryAccessTokenForProfile(ctx context.Context, configDir, explicitToken, profile string) (string, error) {
	snapshot, err := ResolveAuxiliaryAccessTokenSnapshotForProfile(ctx, configDir, explicitToken, profile)
	if err != nil {
		return "", err
	}
	return snapshot.AccessToken, nil
}

// ResolveAuxiliaryAccessTokenSnapshot exposes the same TokenManager used by
// MCP calls to auxiliary HTTP/event clients.
func ResolveAuxiliaryAccessTokenSnapshot(ctx context.Context, configDir, explicitToken string) (AccessTokenSnapshot, error) {
	return runtimeTokenManager.Get(ctx, configDir, explicitToken)
}

// ResolveAuxiliaryAccessTokenSnapshotForProfile is the profile-pinned public
// facade used by long-running event, PAT, A2A, and skill clients.
func ResolveAuxiliaryAccessTokenSnapshotForProfile(ctx context.Context, configDir, explicitToken, profile string) (AccessTokenSnapshot, error) {
	return runtimeTokenManager.GetForProfile(ctx, configDir, explicitToken, profile)
}

func (m *TokenManager) Get(ctx context.Context, configDir, explicitToken string) (AccessTokenSnapshot, error) {
	if token := strings.TrimSpace(explicitToken); token != "" {
		return AccessTokenSnapshot{AccessToken: token, Source: "explicit"}, nil
	}
	return m.GetForProfile(ctx, configDir, "", authpkg.RuntimeProfile())
}

// GetForProfile resolves any user-facing selector to one exact identity before
// choosing the cache key. It is safe to retain for a complete logical request.
func (m *TokenManager) GetForProfile(ctx context.Context, configDir, explicitToken, profile string) (AccessTokenSnapshot, error) {
	if token := strings.TrimSpace(explicitToken); token != "" {
		return AccessTokenSnapshot{AccessToken: token, Source: "explicit"}, nil
	}
	if strings.TrimSpace(configDir) == "" {
		return AccessTokenSnapshot{}, fmt.Errorf("config directory is empty")
	}
	profile = strings.TrimSpace(profile)
	if profile == "" {
		manual, err := authpkg.ManualTokenMarkerActive(configDir)
		if err != nil {
			return AccessTokenSnapshot{}, fmt.Errorf("resolve manual token override: %w", err)
		}
		if manual {
			return m.getForProfile(ctx, configDir, "", "")
		}
	}
	selected, err := authpkg.ResolveProfile(configDir, profile)
	if err != nil {
		label := "selected"
		if profile == "" {
			label = "default"
		}
		return AccessTokenSnapshot{}, fmt.Errorf("resolve %s token profile: %w", label, err)
	}
	if selected != nil {
		profile = authpkg.ProfileSelector(*selected)
	} else if profile != "" {
		return AccessTokenSnapshot{}, authpkg.ErrTokenDataNotFound
	}
	return m.getForProfile(ctx, configDir, "", profile)
}

func (m *TokenManager) getForProfile(ctx context.Context, configDir, explicitToken, profile string) (AccessTokenSnapshot, error) {
	if token := strings.TrimSpace(explicitToken); token != "" {
		return AccessTokenSnapshot{AccessToken: token, Source: "explicit"}, nil
	}
	if strings.TrimSpace(configDir) == "" {
		return AccessTokenSnapshot{}, fmt.Errorf("config directory is empty")
	}
	key := tokenManagerKey{configDir: canonicalTokenConfigDir(configDir), profile: strings.TrimSpace(profile)}
	entry := m.entry(key)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()
	if m != nil && m.now != nil {
		now = m.now()
	}
	if entry.failure.err != nil {
		markerGeneration, markerPresent, markerErr := authpkg.ReadTokenMarkerGeneration(configDir)
		if markerErr != nil {
			return AccessTokenSnapshot{}, fmt.Errorf("read token publication marker: %w", markerErr)
		}
		if markerPresent != entry.failure.markerPresent || markerGeneration != entry.failure.markerGeneration {
			entry.failure = tokenManagerFailure{}
		} else if now.Before(entry.failure.retryAt) {
			if ctx != nil && ctx.Err() != nil {
				return AccessTokenSnapshot{}, ctx.Err()
			}
			slog.Debug("auth.token.resolve", tokenResolutionFailureLogAttrs(ctx, key, entry.failure, "failure_cooldown")...)
			return AccessTokenSnapshot{}, entry.failure.err
		}
	}
	if tokenSnapshotUsable(entry.snapshot, now) {
		markerGeneration, markerPresent, markerErr := authpkg.ReadTokenMarkerGeneration(configDir)
		if markerErr != nil {
			return AccessTokenSnapshot{}, fmt.Errorf("read token publication marker: %w", markerErr)
		}
		if markerPresent && markerGeneration == entry.snapshot.ObservedGeneration {
			slog.Debug("auth.token.resolve", tokenResolutionLogAttrs(ctx, key, entry.snapshot, "cache_hit", true)...)
			return entry.snapshot, nil
		}
	}

	// A credential read and its publication marker form one optimistic
	// snapshot. Reading the marker both before and after resolution prevents a
	// writer from advancing the marker between blob load and cache publication
	// (which would otherwise cache old token A under generation B).
	for attempt := 0; attempt < 4; attempt++ {
		beforeGeneration, beforePresent, markerErr := authpkg.ReadTokenMarkerGeneration(configDir)
		if markerErr != nil {
			return AccessTokenSnapshot{}, fmt.Errorf("read token publication marker: %w", markerErr)
		}
		snapshot, err := resolveTokenSnapshotWithEdition(ctx, configDir, key.profile)
		if err != nil {
			returnErr := err
			if shouldCacheTokenManagerFailure(ctx, err) {
				afterGeneration, afterPresent, afterErr := authpkg.ReadTokenMarkerGeneration(configDir)
				if afterErr != nil {
					return AccessTokenSnapshot{}, fmt.Errorf("verify token publication marker after refresh failure: %w", afterErr)
				}
				if beforePresent != afterPresent || beforeGeneration != afterGeneration {
					entry.failure = tokenManagerFailure{}
					continue
				}
				backoff := nextTokenManagerFailureBackoff(entry.failure, beforeGeneration, beforePresent)
				returnErr = &tokenManagerTransientFailureError{cause: err}
				entry.failure = tokenManagerFailure{
					err:              returnErr,
					class:            authpkg.ClassifyRefreshFailure(err),
					markerGeneration: beforeGeneration,
					markerPresent:    beforePresent,
					retryAt:          now.Add(backoff),
					backoff:          backoff,
				}
			} else {
				entry.failure = tokenManagerFailure{}
			}
			attrs := auxiliaryAuthDiagnosticAttrs("token_resolve", err)
			attrs = append(attrs, tokenResolutionLogAttrs(ctx, key, AccessTokenSnapshot{}, "failed", false)...)
			slog.Warn("auth.token.resolve", attrs...)
			return AccessTokenSnapshot{}, returnErr
		}
		if strings.TrimSpace(snapshot.AccessToken) == "" {
			entry.failure = tokenManagerFailure{}
			return AccessTokenSnapshot{}, noCredentialsError()
		}
		entry.failure = tokenManagerFailure{}
		snapshot.ProfileFingerprint = tokenProfileFingerprint(key)
		snapshot.profile = key.profile
		snapshot.profilePinned = true
		if !tokenSnapshotUsable(snapshot, now) {
			entry.snapshot = AccessTokenSnapshot{}
			slog.Debug("auth.token.resolve", tokenResolutionLogAttrs(ctx, key, snapshot, "resolved", false)...)
			return snapshot, nil
		}

		afterGeneration, afterPresent, markerErr := authpkg.ReadTokenMarkerGeneration(configDir)
		if markerErr != nil {
			return AccessTokenSnapshot{}, fmt.Errorf("verify token publication marker: %w", markerErr)
		}
		if !afterPresent {
			return AccessTokenSnapshot{}, fmt.Errorf("token publication marker is missing")
		}
		if beforePresent != afterPresent || beforeGeneration != afterGeneration {
			continue
		}
		// Marker generation is store-global; a different profile may have
		// advanced it since this token's own generation was written. Publishing
		// the observed marker generation avoids permanent cache misses while the
		// next fast path still detects every subsequent store commit.
		snapshot.ObservedGeneration = afterGeneration
		entry.snapshot = snapshot
		slog.Debug("auth.token.resolve", tokenResolutionLogAttrs(ctx, key, snapshot, "resolved", true)...)
		return snapshot, nil
	}
	return AccessTokenSnapshot{}, fmt.Errorf("token publication changed repeatedly while resolving credentials")
}

func shouldCacheTokenManagerFailure(ctx context.Context, err error) bool {
	if err == nil || (ctx != nil && ctx.Err() != nil) || errors.Is(err, context.Canceled) {
		return false
	}
	return authpkg.ClassifyRefreshFailure(err) == authpkg.RefreshFailureTransient
}

func nextTokenManagerFailureBackoff(previous tokenManagerFailure, markerGeneration uint64, markerPresent bool) time.Duration {
	if previous.err == nil || previous.markerGeneration != markerGeneration || previous.markerPresent != markerPresent || previous.backoff <= 0 {
		return tokenFailureInitialBackoff
	}
	next := previous.backoff * 2
	if next > tokenFailureMaxBackoff {
		return tokenFailureMaxBackoff
	}
	return next
}

func tokenResolutionFailureLogAttrs(ctx context.Context, key tokenManagerKey, failure tokenManagerFailure, outcome string) []any {
	execID, _ := logicalExecutionID(ctx)
	return []any{
		"outcome", outcome,
		"exec_id", execID,
		"profile_hash", tokenProfileFingerprint(key),
		"profile_selected", key.profile != "",
		"observed_generation", failure.markerGeneration,
		"failure_class", string(failure.class),
		"failure_backoff_ms", failure.backoff.Milliseconds(),
	}
}

func tokenResolutionLogAttrs(ctx context.Context, key tokenManagerKey, snapshot AccessTokenSnapshot, outcome string, cacheable bool) []any {
	execID, _ := logicalExecutionID(ctx)
	profileHash := snapshot.ProfileFingerprint
	if profileHash == "" {
		profileHash = tokenProfileFingerprint(key)
	}
	return []any{
		"outcome", outcome,
		"exec_id", execID,
		"source", snapshot.Source,
		"profile_hash", profileHash,
		"profile_selected", key.profile != "",
		"credential_generation", snapshot.Generation,
		"observed_generation", snapshot.ObservedGeneration,
		"expires_bucket", tokenExpiryBucket(snapshot.ExpiresAt, time.Now()),
		"cacheable", cacheable,
	}
}

// RefreshRejectedAccessTokenSnapshot performs a profile-pinned CAS refresh for
// a snapshot returned by TokenManager, then resolves the committed replacement
// under the same opaque profile. This is used by runtimes that bypass the MCP
// runner without exposing the raw profile selector across package boundaries.
func RefreshRejectedAccessTokenSnapshot(ctx context.Context, configDir string, rejected AccessTokenSnapshot) (AccessTokenSnapshot, error) {
	if !rejected.profilePinned || strings.TrimSpace(rejected.AccessToken) == "" {
		return AccessTokenSnapshot{}, fmt.Errorf("rejected token snapshot is not managed by TokenManager")
	}
	if _, err := forceRefreshRejectedTokenForProfileFunc(ctx, configDir, rejected.profile, rejected.AccessToken, rejected.Generation); err != nil {
		if authpkg.ClassifyRefreshFailure(err) == authpkg.RefreshFailureTerminal {
			_, cleanupErr := authpkg.DeleteTokenDataIfAccessTokenMatchesForProfile(
				ctx, configDir, rejected.profile, rejected.AccessToken, rejected.Generation,
			)
			if cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("cleanup terminal rejected credential: %w", cleanupErr))
			}
		}
		runtimeTokenManager.Invalidate()
		return AccessTokenSnapshot{}, err
	}
	runtimeTokenManager.Invalidate()
	return runtimeTokenManager.getForProfile(ctx, configDir, "", rejected.profile)
}

func (m *TokenManager) entry(key tokenManagerKey) *tokenManagerEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[tokenManagerKey]*tokenManagerEntry)
	}
	entry := m.entries[key]
	if entry == nil {
		entry = &tokenManagerEntry{}
		m.entries[key] = entry
	}
	return entry
}

func (m *TokenManager) Invalidate() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.entries = make(map[tokenManagerKey]*tokenManagerEntry)
	m.mu.Unlock()
}

func resolveTokenSnapshotWithEdition(ctx context.Context, configDir, profile string) (AccessTokenSnapshot, error) {
	provider := edition.Get().TokenProvider
	if provider == nil {
		return resolveAccessTokenSnapshotFromDir(ctx, configDir, profile)
	}
	var fallbackSnapshot AccessTokenSnapshot
	var fallbackCalled bool
	token, err := provider(ctx, func() (string, error) {
		fallbackCalled = true
		var fallbackErr error
		fallbackSnapshot, fallbackErr = resolveAccessTokenSnapshotFromDir(ctx, configDir, profile)
		if fallbackErr != nil {
			return "", fallbackErr
		}
		return fallbackSnapshot.AccessToken, nil
	})
	if err != nil {
		return AccessTokenSnapshot{}, fmt.Errorf("edition token provider: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return AccessTokenSnapshot{}, noCredentialsError()
	}
	if fallbackCalled && token == fallbackSnapshot.AccessToken {
		return fallbackSnapshot, nil
	}
	// The compatibility hook returns no expiry metadata. Resolve it dynamically
	// on every request rather than recreating the process-lifetime string cache.
	return AccessTokenSnapshot{AccessToken: token, Source: "edition"}, nil
}

func tokenSnapshotUsable(snapshot AccessTokenSnapshot, now time.Time) bool {
	return strings.TrimSpace(snapshot.AccessToken) != "" &&
		!snapshot.ExpiresAt.IsZero() &&
		now.Before(snapshot.ExpiresAt.Add(-accessTokenRefreshWindow))
}

func canonicalTokenConfigDir(configDir string) string {
	if absolute, err := filepath.Abs(configDir); err == nil {
		return filepath.Clean(absolute)
	}
	return filepath.Clean(configDir)
}

func tokenProfileFingerprint(key tokenManagerKey) string {
	sum := sha256.Sum256([]byte(key.configDir + "\x00" + key.profile))
	return hex.EncodeToString(sum[:8])
}

func noCredentialsError() error {
	if edition.Get().IsEmbedded {
		return fmt.Errorf("认证信息已失效，请重新认证: %w", authpkg.ErrTokenDataNotFound)
	}
	return fmt.Errorf("no credentials found, run: dws auth login: %w", authpkg.ErrTokenDataNotFound)
}

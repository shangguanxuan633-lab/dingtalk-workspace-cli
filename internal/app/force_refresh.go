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
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
)

type accessTokenGetter interface {
	GetAccessToken(context.Context) (string, error)
}

type rejectedTokenRefresher interface {
	ForceRefreshRejectedToken(context.Context, string, ...uint64) (string, error)
}

var (
	newRejectedTokenRefresher = func(configDir, profile string) rejectedTokenRefresher {
		disc := slog.New(slog.NewTextHandler(io.Discard, nil))
		provider := authpkg.NewOAuthProviderForProfile(configDir, disc, profile)
		configureOAuthProviderCompatibility(provider, configDir)
		return provider
	}
	runtimeRejectedRefreshCoordinator = newRejectedRefreshCoordinator()
)

type rejectedRefreshKey struct {
	configDir        string
	profile          string
	generation       uint64
	tokenFingerprint [8]byte
}

type rejectedRefreshEntry struct {
	mu      sync.Mutex
	failure tokenManagerFailure
}

type rejectedRefreshCoordinator struct {
	mu      sync.Mutex
	entries map[rejectedRefreshKey]*rejectedRefreshEntry
	now     func() time.Time
}

func newRejectedRefreshCoordinator() *rejectedRefreshCoordinator {
	return &rejectedRefreshCoordinator{entries: make(map[rejectedRefreshKey]*rejectedRefreshEntry), now: time.Now}
}

func (c *rejectedRefreshCoordinator) entry(key rejectedRefreshKey) *rejectedRefreshEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	if entry == nil {
		entry = &rejectedRefreshEntry{}
		c.entries[key] = entry
	}
	return entry
}

func (c *rejectedRefreshCoordinator) forget(key rejectedRefreshKey, entry *rejectedRefreshEntry) {
	c.mu.Lock()
	if c.entries[key] == entry {
		delete(c.entries, key)
	}
	c.mu.Unlock()
}

func rejectedRefreshCacheKey(configDir, profile, token string, generation []uint64) rejectedRefreshKey {
	digest := sha256.Sum256([]byte(strings.TrimSpace(token)))
	key := rejectedRefreshKey{
		configDir: canonicalTokenConfigDir(configDir),
		profile:   strings.TrimSpace(profile),
	}
	copy(key.tokenFingerprint[:], digest[:8])
	if len(generation) > 0 {
		key.generation = generation[0]
	}
	return key
}

func (c *rejectedRefreshCoordinator) refresh(
	ctx context.Context,
	configDir string,
	key rejectedRefreshKey,
	refresh func() (string, error),
) (string, error) {
	entry := c.entry(key)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	now := time.Now()
	if c != nil && c.now != nil {
		now = c.now()
	}
	markerGeneration, markerPresent, markerErr := authpkg.ReadTokenMarkerGeneration(configDir)
	if entry.failure.err != nil {
		if markerErr == nil && markerGeneration == entry.failure.markerGeneration && markerPresent == entry.failure.markerPresent {
			if ctx != nil && ctx.Err() != nil {
				return "", ctx.Err()
			}
			if now.Before(entry.failure.retryAt) {
				return "", entry.failure.err
			}
		} else {
			entry.failure = tokenManagerFailure{}
		}
	}
	if ctx != nil && ctx.Err() != nil {
		return "", ctx.Err()
	}
	token, err := refresh()
	if err == nil {
		entry.failure = tokenManagerFailure{}
		c.forget(key, entry)
		return token, nil
	}
	if markerErr == nil && shouldCacheTokenManagerFailure(ctx, err) {
		afterGeneration, afterPresent, afterErr := authpkg.ReadTokenMarkerGeneration(configDir)
		if afterErr == nil && afterGeneration == markerGeneration && afterPresent == markerPresent {
			backoff := nextTokenManagerFailureBackoff(entry.failure, markerGeneration, markerPresent)
			safeErr := &tokenManagerTransientFailureError{cause: err}
			entry.failure = tokenManagerFailure{
				err:              safeErr,
				class:            authpkg.ClassifyRefreshFailure(err),
				markerGeneration: markerGeneration,
				markerPresent:    markerPresent,
				retryAt:          now.Add(backoff),
				backoff:          backoff,
			}
			return "", safeErr
		}
	}
	entry.failure = tokenManagerFailure{}
	c.forget(key, entry)
	return "", err
}

// ForceRefreshAccessToken forces a single refresh_token exchange and returns
// the new access_token. It is intended for callers that have observed a
// server-side rejection (HTTP 401 or business code such as
// TOKEN_VERIFIED_FAILED) on what locally appeared to be a still-valid token.
//
// It snapshots token+generation, then delegates to the same dual-locked CAS
// refresh used by the runner. A concurrent rotation is reused rather than
// overwritten, and ResetRuntimeTokenCache publishes the committed snapshot.
func ForceRefreshAccessToken(ctx context.Context, configDir string) (string, error) {
	if strings.TrimSpace(configDir) == "" {
		return "", fmt.Errorf("config directory is empty")
	}
	profile := strings.TrimSpace(authpkg.RuntimeProfile())
	data, err := authpkg.LoadTokenDataForProfile(configDir, profile)
	if err != nil {
		return "", err
	}
	return forceRefreshRejectedTokenForProfile(ctx, configDir, profile, data.AccessToken, data.Generation)
}

// ForceRefreshRejectedToken refreshes only if the rejected token/generation is
// still current; concurrent rotations are reused.
func ForceRefreshRejectedToken(ctx context.Context, configDir, rejectedAccessToken string, generation ...uint64) (string, error) {
	return forceRefreshRejectedTokenForProfile(ctx, configDir, strings.TrimSpace(authpkg.RuntimeProfile()), rejectedAccessToken, generation...)
}

func forceRefreshRejectedTokenForProfile(ctx context.Context, configDir, profile, rejectedAccessToken string, generation ...uint64) (string, error) {
	if strings.TrimSpace(configDir) == "" {
		return "", fmt.Errorf("config directory is empty")
	}
	profile = strings.TrimSpace(profile)
	key := rejectedRefreshCacheKey(configDir, profile, rejectedAccessToken, generation)
	tok, err := runtimeRejectedRefreshCoordinator.refresh(ctx, configDir, key, func() (string, error) {
		provider := newRejectedTokenRefresher(configDir, profile)
		return provider.ForceRefreshRejectedToken(ctx, rejectedAccessToken, generation...)
	})
	if err != nil {
		return "", err
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", fmt.Errorf("force refresh returned empty access token")
	}
	ResetRuntimeTokenCache()
	return tok, nil
}

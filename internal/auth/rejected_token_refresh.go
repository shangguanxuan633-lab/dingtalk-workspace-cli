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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

// ForceRefreshRejectedToken performs rejected-token compare-and-refresh under
// the same process+file lock as ordinary expiry refresh. generation is
// optional for source compatibility; when present it also prevents ABA reuse.
func (p *OAuthProvider) ForceRefreshRejectedToken(ctx context.Context, rejectedAccessToken string, generation ...uint64) (string, error) {
	if p == nil || strings.TrimSpace(p.configDir) == "" {
		return "", fmt.Errorf("config directory is empty")
	}
	rejectedAccessToken = strings.TrimSpace(rejectedAccessToken)
	if rejectedAccessToken == "" {
		return "", fmt.Errorf("rejected access token is empty")
	}

	lock, err := oauthAcquireLock(ctx, p.configDir)
	if err != nil {
		return "", fmt.Errorf("acquiring dual lock: %w", err)
	}
	defer lock.Release()

	data, err := loadTokenDataUnderHeldLock(p.configDir, p.runtimeProfile())
	if err != nil {
		return "", fmt.Errorf("reload rejected token: %w", err)
	}
	if data == nil || strings.TrimSpace(data.AccessToken) == "" {
		return "", fmt.Errorf("stored access token is empty")
	}
	if data.AccessToken != rejectedAccessToken || !generationMatches(data.Generation, generation) {
		return strings.TrimSpace(data.AccessToken), nil
	}
	if !data.IsRefreshTokenValid() {
		return "", fmt.Errorf("refresh_token 已过期: %w", ErrRefreshTokenExpired)
	}
	if err := preflightTokenRefreshPersistence(p.configDir, data); err != nil {
		return "", fmt.Errorf("本地登录态无法安全更新: %w", err)
	}
	refreshed, err := oauthRefreshToken(p, ctx, data)
	if err != nil {
		return "", err
	}
	if refreshed == nil || strings.TrimSpace(refreshed.AccessToken) == "" {
		return "", fmt.Errorf("force refresh returned empty access token")
	}
	return strings.TrimSpace(refreshed.AccessToken), nil
}

// DeleteTokenDataIfAccessTokenMatches removes only an explicitly terminal
// credential, and only if token+optional generation still match under lock.
func DeleteTokenDataIfAccessTokenMatches(ctx context.Context, configDir, expectedAccessToken string, generation ...uint64) (bool, error) {
	return DeleteTokenDataIfAccessTokenMatchesForProfile(ctx, configDir, RuntimeProfile(), expectedAccessToken, generation...)
}

// DeleteTokenDataIfAccessTokenMatchesForProfile is the profile-pinned form of
// DeleteTokenDataIfAccessTokenMatches. It keeps the CAS read and deletion bound
// to the same selector even if RuntimeProfile changes concurrently.
func DeleteTokenDataIfAccessTokenMatchesForProfile(ctx context.Context, configDir, profile, expectedAccessToken string, generation ...uint64) (bool, error) {
	if strings.TrimSpace(configDir) == "" {
		return false, fmt.Errorf("config directory is empty")
	}
	expectedAccessToken = strings.TrimSpace(expectedAccessToken)
	if expectedAccessToken == "" {
		return false, fmt.Errorf("expected access token is empty")
	}
	profile = strings.TrimSpace(profile)
	lock, err := oauthAcquireLock(ctx, configDir)
	if err != nil {
		return false, fmt.Errorf("acquiring dual lock: %w", err)
	}
	defer lock.Release()

	data, err := loadTokenDataUnderHeldLock(configDir, profile)
	if err != nil {
		if errors.Is(err, ErrTokenDataNotFound) || errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if data == nil || data.AccessToken != expectedAccessToken || !generationMatches(data.Generation, generation) {
		return false, nil
	}
	hooks := edition.Get()
	if editionTokenStoreConfigured(hooks) {
		if err := validateEditionTokenStore(hooks); err != nil {
			return false, err
		}
		if profile != "" {
			return false, fmt.Errorf("profile selection is not supported by the current auth backend")
		}
		if err := deleteTokenViaHookTransaction(hooks, configDir); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := deleteTokenDataForProfileLocked(configDir, profile); err != nil {
		return false, err
	}
	return true, nil
}

// MarkProfileExpiredIfAccessTokenMatches updates profile metadata only when
// the rejected token+generation are still current under the auth dual lock.
// It is the non-destructive counterpart of DeleteTokenDataIfAccessTokenMatches
// for editions that retain expired profiles for diagnostics.
func MarkProfileExpiredIfAccessTokenMatches(ctx context.Context, configDir, expectedAccessToken string, generation ...uint64) (bool, error) {
	if strings.TrimSpace(configDir) == "" {
		return false, fmt.Errorf("config directory is empty")
	}
	expectedAccessToken = strings.TrimSpace(expectedAccessToken)
	if expectedAccessToken == "" {
		return false, fmt.Errorf("expected access token is empty")
	}
	profile := strings.TrimSpace(RuntimeProfile())
	lock, err := oauthAcquireLock(ctx, configDir)
	if err != nil {
		return false, fmt.Errorf("acquiring dual lock: %w", err)
	}
	defer lock.Release()

	data, err := loadTokenDataUnderHeldLock(configDir, profile)
	if err != nil {
		if errors.Is(err, ErrTokenDataNotFound) || errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if data == nil || data.AccessToken != expectedAccessToken || !generationMatches(data.Generation, generation) {
		return false, nil
	}
	selector := strings.TrimSpace(TokenProfileSelector(data))
	if selector == "" || edition.Get().LoadToken != nil {
		return false, nil
	}
	if err := markProfileStatusLocked(configDir, selector, ProfileStatusExpired); err != nil {
		return false, err
	}
	return true, nil
}

func loadTokenDataUnderHeldLock(configDir, profile string) (*TokenData, error) {
	hooks := edition.Get()
	if editionTokenStoreConfigured(hooks) {
		if err := validateEditionTokenStore(hooks); err != nil {
			return nil, err
		}
		if strings.TrimSpace(profile) != "" {
			return nil, fmt.Errorf("profile selection is not supported by the current auth backend")
		}
		blob, err := hooks.LoadToken(configDir)
		if err != nil {
			return nil, err
		}
		var data TokenData
		if err := json.Unmarshal(blob, &data); err != nil {
			return nil, fmt.Errorf("parse token data from hook: %w", err)
		}
		return &data, nil
	}
	return loadTokenDataForProfileLocked(configDir, profile)
}

func generationMatches(actual uint64, expected []uint64) bool {
	return len(expected) == 0 || expected[0] == 0 || actual == expected[0]
}

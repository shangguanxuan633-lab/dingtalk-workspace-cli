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
	"fmt"
	"io"
	"log/slog"
	"strings"

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
)

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
	provider := newRejectedTokenRefresher(configDir, strings.TrimSpace(profile))
	tok, err := provider.ForceRefreshRejectedToken(ctx, rejectedAccessToken, generation...)
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

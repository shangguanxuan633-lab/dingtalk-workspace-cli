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

// Package runtimetoken resolves API bearer tokens for features that bypass
// the MCP runner (e.g. A2A gateway) but should behave like tool calls.
package runtimetoken

import (
	"context"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/app"
)

// TokenSnapshot is the public, refresh-token-free view of the unified runtime
// token manager. Generation changes whenever the credential store publishes a
// new state; ProfileFingerprint is a non-reversible diagnostic identifier.
type TokenSnapshot struct {
	AccessToken        string
	ExpiresAt          time.Time
	Generation         uint64
	ObservedGeneration uint64
	Source             string
	ProfileFingerprint string
	UpdatedAt          string
}

// ResolveAccessToken returns a non-empty bearer token using the same sources
// and caching rules as MCP when configDir matches the active edition directory;
// see app.ResolveAuxiliaryAccessToken.
func ResolveAccessToken(ctx context.Context, configDir, explicitToken string) (string, error) {
	snapshot, err := ResolveSnapshot(ctx, configDir, explicitToken)
	if err != nil {
		return "", err
	}
	return snapshot.AccessToken, nil
}

// ResolveSnapshot resolves through the same expiry/generation-aware manager as
// MCP tool calls. Callers should invoke it for every logical request rather
// than retaining AccessToken for a process lifetime.
func ResolveSnapshot(ctx context.Context, configDir, explicitToken string) (TokenSnapshot, error) {
	snapshot, err := app.ResolveAuxiliaryAccessTokenSnapshot(ctx, configDir, explicitToken)
	if err != nil {
		return TokenSnapshot{}, err
	}
	return TokenSnapshot{
		AccessToken:        snapshot.AccessToken,
		ExpiresAt:          snapshot.ExpiresAt,
		Generation:         snapshot.Generation,
		ObservedGeneration: snapshot.ObservedGeneration,
		Source:             snapshot.Source,
		ProfileFingerprint: snapshot.ProfileFingerprint,
		UpdatedAt:          snapshot.UpdatedAt,
	}, nil
}

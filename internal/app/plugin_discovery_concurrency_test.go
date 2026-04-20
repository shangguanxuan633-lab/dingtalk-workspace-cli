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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/cache"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/cli"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/market"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/transport"
)

// TestSharedCacheStoreConcurrentSaveTools verifies that a single *cache.Store
// instance is safe for goroutines saving tool snapshots concurrently, as long
// as each goroutine targets a distinct (partition, serverKey). This mirrors
// the real plugin discovery path where each goroutine owns one plugin/server.
//
// Each call serializes to its own "<key>.json.tmp" file followed by a
// rename(2) to the final path, so concurrent writers targeting distinct keys
// never collide. The invariant asserted here: after N parallel writes, the
// Store returns each written snapshot intact under LoadTools.
func TestSharedCacheStoreConcurrentSaveTools(t *testing.T) {
	const (
		partition = "default/default"
		writers   = 16
	)

	store := cache.NewStore(t.TempDir())

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("plugin:concurrent:%d", idx)
			if err := store.SaveTools(partition, key, cache.ToolsSnapshot{
				ServerKey: key,
			}); err != nil {
				t.Errorf("SaveTools(%s): %v", key, err)
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < writers; i++ {
		key := fmt.Sprintf("plugin:concurrent:%d", i)
		snapshot, _, err := store.LoadTools(partition, key)
		if err != nil {
			t.Fatalf("LoadTools(%s): %v", key, err)
		}
		if snapshot.ServerKey != key {
			t.Errorf("LoadTools(%s) returned ServerKey %q", key, snapshot.ServerKey)
		}
	}
}

// TestAppendDynamicServerConcurrent exercises the dynamicMu mutex on the
// write path by spraying distinct server descriptors in parallel. Afterwards
// every injected product ID must be resolvable — a missing entry would
// indicate a lost write through an un-synchronized map update.
func TestAppendDynamicServerConcurrent(t *testing.T) {
	dynamicMu.Lock()
	prev := struct {
		endpoints     map[string]string
		products      map[string]bool
		aliases       map[string]string
		toolEndpoints map[string]string
	}{dynamicEndpoints, dynamicProducts, dynamicAliases, dynamicToolEndpoints}
	dynamicEndpoints = nil
	dynamicProducts = nil
	dynamicAliases = nil
	dynamicToolEndpoints = nil
	dynamicMu.Unlock()
	t.Cleanup(func() {
		dynamicMu.Lock()
		dynamicEndpoints = prev.endpoints
		dynamicProducts = prev.products
		dynamicAliases = prev.aliases
		dynamicToolEndpoints = prev.toolEndpoints
		dynamicMu.Unlock()
	})

	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("plugin-id-%d", idx)
			endpoint := fmt.Sprintf("https://example.test/%d", idx)
			AppendDynamicServer(market.ServerDescriptor{
				Endpoint: endpoint,
				CLI: market.CLIOverlay{
					ID:      id,
					Command: id,
				},
			})
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		id := fmt.Sprintf("plugin-id-%d", i)
		if endpoint, ok := directRuntimeEndpoint(id, ""); !ok || endpoint == "" {
			t.Errorf("directRuntimeEndpoint(%q) = (%q, %v), want non-empty", id, endpoint, ok)
		}
	}
}

// TestRegisterStdioClientConcurrent verifies the stdioMu-protected registry
// survives concurrent writers — every registered client must be looked up
// afterwards. Uses nil client pointers since LookupStdioClient only compares
// keys, not values.
func TestRegisterStdioClientConcurrent(t *testing.T) {
	stdioMu.Lock()
	prev := stdioClients
	stdioClients = make(map[string]*transport.StdioClient)
	stdioMu.Unlock()
	t.Cleanup(func() {
		stdioMu.Lock()
		stdioClients = prev
		stdioMu.Unlock()
	})

	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			RegisterStdioClient(fmt.Sprintf("plugin/%d", idx), nil)
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		key := fmt.Sprintf("plugin/%d", i)
		if _, ok := LookupStdioClient(key); !ok {
			t.Errorf("LookupStdioClient(%q) missing after concurrent registration", key)
		}
	}
}

// TestResolvePluginColdTimeouts covers the three code paths of the env
// parser: unset (defaults), valid duration (applied to all three slots),
// and invalid duration (logged and ignored, defaults returned).
func TestResolvePluginColdTimeouts(t *testing.T) {
	t.Run("defaults when env unset", func(t *testing.T) {
		t.Setenv(cli.PluginColdTimeoutEnv, "")
		got := resolvePluginColdTimeouts()
		if got.httpNoAuth != 1*time.Second {
			t.Errorf("httpNoAuth = %v, want 1s", got.httpNoAuth)
		}
		if got.httpAuth != 1500*time.Millisecond {
			t.Errorf("httpAuth = %v, want 1.5s", got.httpAuth)
		}
		if got.stdio != 2*time.Second {
			t.Errorf("stdio = %v, want 2s", got.stdio)
		}
	})
	t.Run("env override applies to all slots", func(t *testing.T) {
		t.Setenv(cli.PluginColdTimeoutEnv, "3500ms")
		got := resolvePluginColdTimeouts()
		want := 3500 * time.Millisecond
		if got.httpNoAuth != want || got.httpAuth != want || got.stdio != want {
			t.Errorf("override not propagated: %+v", got)
		}
	})
	t.Run("invalid env falls back to defaults", func(t *testing.T) {
		t.Setenv(cli.PluginColdTimeoutEnv, "not-a-duration")
		got := resolvePluginColdTimeouts()
		if got.httpNoAuth != 1*time.Second || got.stdio != 2*time.Second {
			t.Errorf("invalid env should not override defaults: %+v", got)
		}
	})
	t.Run("non-positive env falls back to defaults", func(t *testing.T) {
		t.Setenv(cli.PluginColdTimeoutEnv, "0")
		got := resolvePluginColdTimeouts()
		if got.httpNoAuth != 1*time.Second {
			t.Errorf("zero duration should not override defaults, got %v", got.httpNoAuth)
		}
	})
}

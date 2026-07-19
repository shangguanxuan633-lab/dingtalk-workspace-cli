// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logging

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestAuthDebugDisabledByDefault(t *testing.T) {
	t.Setenv(AuthDebugEnv, "")
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	AuthDebug("auth.test", "user_id", "user")
	if output.Len() != 0 {
		t.Fatalf("AuthDebug() logged without %s=1: %s", AuthDebugEnv, output.String())
	}
}

func TestAuthDebugRedactsKeyVariantsAndRawErrors(t *testing.T) {
	t.Setenv(AuthDebugEnv, "1")
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	AuthDebug("auth.variants",
		"accessToken", "access-secret",
		"refresh-token", "refresh-secret",
		"authCode", "code-secret",
		"clientSecret", "client-secret",
		"persistentCode", "persistent-secret",
		"uid", "uid-4496576595",
		"corpId", "corp-secret",
		"staff_id", "staff-secret",
		"error", errors.New("server echoed access-secret"),
		slog.Group("identity", slog.String("unionId", "union-secret"), slog.String("open_id", "open-secret")),
		"stage", "refresh",
	)
	got := output.String()
	for _, secret := range []string{"access-secret", "refresh-secret", "code-secret", "client-secret", "persistent-secret", "uid-4496576595", "corp-secret", "staff-secret", "union-secret", "open-secret", "server echoed"} {
		if strings.Contains(got, secret) {
			t.Fatalf("AuthDebug leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, `"stage":"refresh"`) || !strings.Contains(got, `"uid_hash":`) || !strings.Contains(got, `"error_type":`) {
		t.Fatalf("AuthDebug omitted safe diagnostics: %s", got)
	}
}

func TestAuthDebugEnabledOnlyByExplicitOne(t *testing.T) {
	for _, value := range []string{"0", "true", "yes"} {
		t.Run("disabled_"+value, func(t *testing.T) {
			t.Setenv(AuthDebugEnv, value)
			var output bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(previous) })

			AuthDebug("auth.test")
			if output.Len() != 0 {
				t.Fatalf("AuthDebug() logged with %s=%q: %s", AuthDebugEnv, value, output.String())
			}
		})
	}

	t.Run("enabled", func(t *testing.T) {
		t.Setenv(AuthDebugEnv, "1")
		var output bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
		t.Cleanup(func() { slog.SetDefault(previous) })

		AuthDebug("auth.test", "user_id", "user")
		got := output.String()
		if !strings.Contains(got, `"msg":"auth.test"`) || !strings.Contains(got, `"user_id_hash":`) || strings.Contains(got, `"user_id":"user"`) {
			t.Fatalf("AuthDebug() output = %s", got)
		}
	})
}

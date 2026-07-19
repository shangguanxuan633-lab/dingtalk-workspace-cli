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

package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// AuthDebugEnv enables detailed authentication diagnostics when set to "1".
const AuthDebugEnv = "DWS_DEBUG_AUTH"

// AuthDebug writes detailed authentication diagnostics only when explicitly enabled.
func AuthDebug(message string, args ...any) {
	if os.Getenv(AuthDebugEnv) != "1" {
		return
	}
	slog.Debug(message, redactAuthDebugArgs(args)...)
}

func redactAuthDebugArgs(args []any) []any {
	out := make([]any, 0, len(args))
	for i := 0; i < len(args); i++ {
		if attr, ok := args[i].(slog.Attr); ok {
			out = append(out, redactAuthDebugAttr(attr))
			continue
		}
		key, ok := args[i].(string)
		if !ok || i+1 >= len(args) {
			out = append(out, args[i])
			continue
		}
		value := args[i+1]
		i++
		key, value = redactAuthDebugPair(key, value)
		out = append(out, key, value)
	}
	return out
}

func redactAuthDebugAttr(attr slog.Attr) slog.Attr {
	if attr.Value.Kind() == slog.KindGroup {
		group := attr.Value.Group()
		args := make([]any, 0, len(group))
		for _, child := range group {
			args = append(args, redactAuthDebugAttr(child))
		}
		return slog.Group(attr.Key, args...)
	}
	key, value := redactAuthDebugPair(attr.Key, attr.Value.Any())
	return slog.Any(key, value)
}

func redactAuthDebugPair(key string, value any) (string, any) {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "error" || normalized == "err" {
		if err, ok := value.(error); ok {
			return "error_type", fmt.Sprintf("%T", err)
		}
		return "error_present", value != nil
	}
	if authDebugSecretKey(normalized) {
		return normalized + "_present", strings.TrimSpace(fmt.Sprint(value)) != ""
	}
	if authDebugIdentityKey(normalized) {
		raw := strings.TrimSpace(fmt.Sprint(value))
		if raw == "" {
			return normalized + "_present", false
		}
		sum := sha256.Sum256([]byte(normalized + "\x00" + raw))
		return normalized + "_hash", hex.EncodeToString(sum[:8])
	}
	return key, value
}

func authDebugSecretKey(key string) bool {
	compact := compactAuthDebugKey(key)
	return strings.Contains(compact, "token") || strings.Contains(compact, "authcode") ||
		strings.Contains(compact, "authorization") || strings.Contains(compact, "clientsecret") ||
		strings.Contains(compact, "persistentcode")
}

func authDebugIdentityKey(key string) bool {
	switch compactAuthDebugKey(key) {
	case "uid", "userid", "username", "corpid", "corpname", "staffid", "unionid", "openid", "tenantid", "localsubject",
		"identityselector", "runtimeprofile", "targetcorpid", "profile":
		return true
	default:
		return false
	}
}

func compactAuthDebugKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	replacer := strings.NewReplacer("_", "", "-", "", ".", "", " ", "")
	return replacer.Replace(key)
}

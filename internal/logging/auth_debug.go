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
	return strings.Contains(key, "access_token") || strings.Contains(key, "refresh_token") ||
		strings.Contains(key, "client_secret") || strings.Contains(key, "authorization") ||
		strings.Contains(key, "persistent_code")
}

func authDebugIdentityKey(key string) bool {
	switch key {
	case "corp_id", "corp_name", "user_id", "user_name", "identity_selector", "runtime_profile", "target_corp_id", "profile":
		return true
	default:
		return false
	}
}

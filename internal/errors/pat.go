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

package errors

import (
	"bytes"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// hostControlProvider returns the host-owned clawType for the current
// process, or empty string when CLI is in default (CLI-owned) mode.
// Injected lazily via SetHostControlProvider to avoid an
// internal/errors → internal/auth import cycle.
//
// Access is serialized by hostControlMu so that tests can swap the provider
// without triggering the race detector against parallel classifier callers.
var (
	hostControlMu       sync.RWMutex
	hostControlProvider func() string
	patBrowserMu        sync.RWMutex
	patBrowserProvider  func() bool
)

// SetHostControlProvider wires up the classifier's hostControl injection.
// It MUST be called once during CLI bootstrap (e.g. from internal/app
// init()) so that the first cleanPATJSON call observes a valid provider.
// Passing nil disables injection (useful for isolated tests).
func SetHostControlProvider(fn func() string) {
	hostControlMu.Lock()
	defer hostControlMu.Unlock()
	hostControlProvider = fn
}

// SetPATOpenBrowserProvider wires the PAT JSON serializer to the current
// browser policy. Passing nil restores the open-source fallback (true).
func SetPATOpenBrowserProvider(fn func() bool) {
	patBrowserMu.Lock()
	defer patBrowserMu.Unlock()
	patBrowserProvider = fn
}

// PATOpenBrowserValue returns the effective browser-open recommendation to
// embed in PAT JSON payloads. The open-source fallback is true to preserve
// historical behavior when no provider is wired.
func PATOpenBrowserValue() bool {
	patBrowserMu.RLock()
	provider := patBrowserProvider
	patBrowserMu.RUnlock()
	if provider == nil {
		return true
	}
	return provider()
}

// HostControlBlock returns the canonical hostControl map injected into
// PAT stderr JSON when the CLI is operating in host-owned mode, or nil
// when it is not. The returned map is safe for the caller to mutate
// because a new map is constructed on each call.
//
// callbackOwner is kept as a legacy compatibility key for hosts that adopted
// it before the contract converged on the hostControl single injection point.
func HostControlBlock() map[string]any {
	hostControlMu.RLock()
	provider := hostControlProvider
	hostControlMu.RUnlock()
	if provider == nil {
		return nil
	}
	claw := provider()
	if claw == "" {
		return nil
	}
	return map[string]any{
		"clawType":      claw,
		"callbackOwner": "host",
		"mode":          "host",
		"pollingOwner":  "host",
		"retryOwner":    "host",
	}
}

// ExitCodePermission is the process exit code for PAT authorisation failures.
const ExitCodePermission = 4

// PATError represents a PAT (Personal Action Token) authorization failure
// that should be passed through to stderr as raw JSON without any CLI-layer
// wrapping. The host application parses the JSON to display its own
// authorization UI. The wire schema is fixed: a single-line, directly
// json.Unmarshal-able payload of the form
// {"success":false,"code":<frozen enum>,"data":{...}}.
//
// When the payload includes data.uri/authUrl/authorizationUrl, that value is
// the authoritative server-provided authorization link. The CLI accepts all
// legacy aliases, normalizes the known DingTalk hash-route variant, and emits a
// single data.uri field so terminals and hosts do not need to deduplicate links.
type PATError struct {
	RawJSON string

	// authorizationFlow is a narrow, typed in-process capability. Keeping only
	// the fields required by the device flow prevents arbitrary server JSON from
	// crossing the public/private boundary by convention alone.
	authorizationFlow    PATAuthorizationFlow
	authorizationFlowSet bool
	canonicalCode        string
}

// PATAuthorizationFlow is the minimal private state required to complete an
// interactive PAT flow. Callers must never log ClientSecret.
type PATAuthorizationFlow struct {
	CanonicalCode       string
	FlowID              string
	AuthorizationURI    string
	ClientID            string
	ClientSecret        string
	PollIntervalSeconds int
}

func (e *PATError) Error() string { return e.RawJSON }

// ExitCode returns the documented exit code for PAT permission errors (4).
func (e *PATError) ExitCode() int { return ExitCodePermission }

// RawStderr returns the raw JSON to be written directly to stderr.
func (e *PATError) RawStderr() string { return e.RawJSON }

// AuthorizationFlow returns the narrow private capability captured by the
// classifier. It deliberately never reconstructs state from RawJSON.
func (e *PATError) AuthorizationFlow() (PATAuthorizationFlow, bool) {
	if e == nil || !e.authorizationFlowSet {
		return PATAuthorizationFlow{}, false
	}
	return e.authorizationFlow, true
}

// CanonicalCode returns the PAT selector chosen by the classifier. It is
// intentionally independent of the upstream field alias (code, errorCode, or
// error_code), so policy denials cannot accidentally enter an active flow.
func (e *PATError) CanonicalCode() string {
	if e == nil {
		return ""
	}
	if e.canonicalCode != "" {
		return e.canonicalCode
	}
	var envelope struct {
		Code string `json:"code"`
	}
	if json.Unmarshal([]byte(e.RawJSON), &envelope) != nil {
		return ""
	}
	return strings.TrimSpace(envelope.Code)
}

func newPATError(body map[string]any, code string) *PATError {
	return &PATError{
		RawJSON:              cleanPATJSON(body, code),
		authorizationFlow:    extractPATAuthorizationFlow(body, code),
		authorizationFlowSet: true,
		canonicalCode:        code,
	}
}

// NewPATAuthorizationError constructs a PAT error without accepting arbitrary
// raw server JSON. It is primarily useful to internal adapters and tests.
func NewPATAuthorizationError(flow PATAuthorizationFlow) *PATError {
	data := map[string]any{}
	if flow.FlowID != "" {
		data["flowId"] = flow.FlowID
	}
	if flow.AuthorizationURI != "" {
		data["uri"] = flow.AuthorizationURI
	}
	if flow.ClientID != "" {
		data["clientId"] = flow.ClientID
	}
	if flow.ClientSecret != "" {
		data["clientSecret"] = flow.ClientSecret
	}
	if flow.PollIntervalSeconds != 0 {
		data["pollIntervalSeconds"] = flow.PollIntervalSeconds
	}
	body := map[string]any{"code": flow.CanonicalCode, "data": data}
	return newPATError(body, flow.CanonicalCode)
}

func extractPATAuthorizationFlow(body map[string]any, code string) PATAuthorizationFlow {
	data := body
	if nested, ok := body["data"].(map[string]any); ok {
		data = nested
	}
	uri := ""
	for _, key := range []string{"uri", "authUrl", "authorizationUrl"} {
		if value, ok := data[key].(string); ok && strings.TrimSpace(value) != "" {
			uri = TrustedPATAuthorizationURL(value)
			break
		}
	}
	interval := 0
	if sanitized := sanitizePATPollInterval(data["pollIntervalSeconds"]); sanitized != nil {
		interval, _ = sanitized.(int)
	}
	return PATAuthorizationFlow{
		CanonicalCode:       strings.TrimSpace(code),
		FlowID:              boundedPrivatePATString(data["flowId"], 512),
		AuthorizationURI:    uri,
		ClientID:            boundedPrivatePATString(data["clientId"], 512),
		ClientSecret:        boundedPrivatePATString(data["clientSecret"], 4096),
		PollIntervalSeconds: interval,
	}
}

func boundedPrivatePATString(value any, maxLength int) string {
	raw, ok := value.(string)
	if !ok {
		return ""
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxLength {
		return ""
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return raw
}

// patNoPermissionCodes are PAT error codes that should be passed through
// as transparent PATError without CLI-level wrapping. Some of these are
// grantable by user authorization; PAT_ORG_POLICY_DENIED is terminal until an
// org admin changes the policy, but it still belongs to the PAT permission
// channel so hosts see exit=4 and the raw PAT JSON contract.
var patNoPermissionCodes = map[string]bool{
	"PAT_NO_PERMISSION":             true,
	"PAT_LOW_RISK_NO_PERMISSION":    true,
	"PAT_MEDIUM_RISK_NO_PERMISSION": true,
	"PAT_HIGH_RISK_NO_PERMISSION":   true,
	"PAT_ORG_POLICY_DENIED":         true,
}

// patAuthRequiredCodes are error codes that trigger the PAT authorization
// flow (e.g. the server auto-created a CLI app and returned auth details,
// or the caller's OAuth token lacks a scope that must be re-acquired via
// `dws auth login --scope <missing>`).
//
// Keep keys in alphabetical order so diffs are stable. Both codes below are
// part of the frozen PAT-family selector and MUST be surfaced as *PATError
// (exit=4) so hosts can act on them:
//   - AGENT_CODE_NOT_EXISTS: data.agentCode tells the host which agent
//     registration is missing.
//   - PAT_SCOPE_AUTH_REQUIRED: data.missingScope tells the host which
//     OAuth scope to re-acquire via
//     `dws auth login --scope <data.missingScope>`.
var patAuthRequiredCodes = map[string]bool{
	"AGENT_CODE_NOT_EXISTS":   true,
	"PAT_BATCH_AUTH_PENDING":  true,
	"PAT_SCOPE_AUTH_REQUIRED": true,
}

// IsPATError reports whether err is a *PATError.
func IsPATError(err error) bool {
	_, ok := err.(*PATError)
	return ok
}

// IsPATNoPermissionCode reports whether code is a known PAT permission error code.
func IsPATNoPermissionCode(code string) bool {
	return patNoPermissionCodes[code]
}

// errCodeKeys is the canonical priority order in which we look up
// upstream error code fields. Servers historically rotated between camel
// and snake case; we accept all three and pick the first that resolves to
// a recognised value.
var errCodeKeys = []string{"code", "errorCode", "error_code"}

// lookupCodeIn returns the first value in body[errCodeKeys] that is a
// non-empty string AND is a member of accept. Used by the PAT and DWS
// gateway classifiers, which differ only in their accept-set.
func lookupCodeIn(body map[string]any, accept map[string]bool) (string, bool) {
	for _, key := range errCodeKeys {
		if code, ok := body[key].(string); ok && accept[code] {
			return code, true
		}
	}
	return "", false
}

// getPATErrorCode extracts any PAT-intercept code from a map. PAT
// intercepts include both permission denials and auth-required selectors:
// callers on the text/tool-result path must preserve both families as
// *PATError so exit=4 + raw stderr JSON survives all the way to the host/CLI.
func getPATErrorCode(body map[string]any) (string, bool) {
	if code, ok := lookupCodeIn(body, patNoPermissionCodes); ok {
		return code, true
	}
	return lookupCodeIn(body, patAuthRequiredCodes)
}

func findPATErrorBody(value any, depth int) (string, map[string]any, bool) {
	// A terminal policy/permission denial must always win over a grantable
	// authorization flow, even when the two signals live in different nested
	// branches. A single recursive map walk is not sufficient because Go map
	// iteration order is intentionally random and could otherwise make the
	// selected PAT action nondeterministic.
	if code, source, ok := findPATErrorBodyIn(value, depth, patNoPermissionCodes); ok {
		return code, source, true
	}
	return findPATErrorBodyIn(value, depth, patAuthRequiredCodes)
}

func findPATErrorBodyIn(value any, depth int, accept map[string]bool) (string, map[string]any, bool) {
	if depth > 8 {
		return "", nil, false
	}
	switch current := value.(type) {
	case map[string]any:
		if code, ok := lookupCodeIn(current, accept); ok {
			return code, current, true
		}
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if code, source, ok := findPATErrorBodyIn(current[key], depth+1, accept); ok {
				return code, source, true
			}
		}
	case []any:
		for _, child := range current {
			if code, source, ok := findPATErrorBodyIn(child, depth+1, accept); ok {
				return code, source, true
			}
		}
	}
	return "", nil, false
}

// ---- DWS gateway auth errors (shared between PAT & general auth) ----------

// dwsGatewayErrors is the set of DWS gateway-level auth error codes.
var dwsGatewayErrors = map[string]bool{
	"DWS_SERVICE_UNAUTHORIZED": true,
	"DWS_AUTH_SERVICE_FAILED":  true,
}

// getDWSGatewayErrorCode extracts a DWS gateway error code from errBody.
func getDWSGatewayErrorCode(errBody map[string]any) (string, bool) {
	return lookupCodeIn(errBody, dwsGatewayErrors)
}

// isNotLoggedInError checks if the error body indicates missing authentication.
func isNotLoggedInError(body map[string]any) bool {
	for _, key := range []string{"error", "message", "errorMsg"} {
		errMsg, ok := body[key].(string)
		if !ok {
			continue
		}
		if strings.Contains(errMsg, "Missing service_id or access_key") {
			return true
		}
	}
	return false
}

// isBusinessError checks if a parsed JSON body represents a business-level error.
func isBusinessError(body map[string]any) bool {
	if _, ok := body["error"].(string); ok {
		return true
	}
	if v, ok := body["success"].(bool); ok && !v {
		return true
	}
	if v, ok := body["success"].(string); ok && strings.EqualFold(v, "false") {
		return true
	}
	return false
}

// IsExplicitSuccessEnvelope reports whether the upstream explicitly marked a
// payload successful. Success wins over nested permission-looking metadata:
// business responses may legitimately contain status enums or required-scope
// descriptions that are not authentication failures.
func IsExplicitSuccessEnvelope(body map[string]any) bool {
	for _, key := range []string{"success", "ok"} {
		switch value := body[key].(type) {
		case bool:
			if value {
				return true
			}
		case string:
			if strings.EqualFold(strings.TrimSpace(value), "true") {
				return true
			}
		}
	}
	return false
}

// IsExplicitErrorEnvelope requires positive evidence that a payload represents
// an error before recursively interpreting generic permission fields.
func IsExplicitErrorEnvelope(body map[string]any) bool {
	if len(body) == 0 || IsExplicitSuccessEnvelope(body) {
		return false
	}
	for _, key := range []string{"success", "ok"} {
		switch value := body[key].(type) {
		case bool:
			if !value {
				return true
			}
		case string:
			if strings.EqualFold(strings.TrimSpace(value), "false") {
				return true
			}
		}
	}
	if value, ok := body["isError"].(bool); ok && value {
		return true
	}
	if errorValue, ok := body["error"]; ok && hasPATData(errorValue) {
		return true
	}
	if _, _, ok := findPATErrorBody(body, 0); ok {
		return true
	}
	if _, ok := getDWSGatewayErrorCode(body); ok {
		return true
	}
	if containsExactTokenErrorEvidence(body, 0) {
		return true
	}
	for _, key := range errCodeKeys {
		value, exists := body[key]
		if !exists {
			continue
		}
		if permissionStatusForbidden(value) {
			return true
		}
		if code, ok := value.(string); ok && isPermissionVetoCode(code) {
			return true
		}
	}
	return false
}

func containsExactTokenErrorEvidence(value any, depth int) bool {
	if depth > 8 {
		return false
	}
	switch current := value.(type) {
	case map[string]any:
		for _, key := range []string{"code", "errorCode", "error_code", "errCode", "errcode", "serverErrorCode", "server_error_code"} {
			if exactTokenErrorValue(current[key]) {
				return true
			}
		}
		for _, key := range []string{"error", "data", "result", "details", "content"} {
			if child, ok := current[key]; ok && containsExactTokenErrorEvidence(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if containsExactTokenErrorEvidence(child, depth+1) {
				return true
			}
		}
	}
	return false
}

func exactTokenErrorValue(value any) bool {
	switch current := value.(type) {
	case string:
		switch strings.ToUpper(strings.TrimSpace(current)) {
		case "40014", "TOKEN_VERIFIED_FAILED", "USER_TOKEN_ILLEGAL", "ACCESS_TOKEN_EXPIRED", "DWS_SERVICE_UNAUTHORIZED":
			return true
		}
	case int:
		return current == 40014
	case int64:
		return current == 40014
	case float64:
		return current == 40014
	case json.Number:
		return string(current) == "40014"
	}
	return false
}

// ---- Classification functions -----------------------------------------------

// ClassifyToolResultContent checks a raw MCP tool result content map for
// DWS gateway auth errors and PAT permission error codes.  This is intended
// for use as the edition.Hooks.ClassifyToolResult callback so the framework's
// runner returns a typed error before its generic business-error classification.
//
// Check order: PAT/permission veto > DWS gateway auth. Permission evidence
// must win when a mixed response also carries a token-rejection code.
func ClassifyToolResultContent(content map[string]any) error {
	if IsExplicitSuccessEnvelope(content) {
		return nil
	}
	if code, source, ok := findPATErrorBody(content, 0); ok {
		return newPATError(source, code)
	}
	if IsExplicitErrorEnvelope(content) && hasAuthPermissionVeto(content, 0) {
		return permissionVetoError(content)
	}
	if code, ok := getDWSGatewayErrorCode(content); ok {
		return NewAuth("DWS gateway rejected the current login state",
			WithReason("gateway_auth_expired"),
			WithHint(authExpiredHint()),
			WithServerDiag(ServerDiagnostics{ServerErrorCode: code}),
		)
	}
	return nil
}

// ClassifyMCPResponseText classifies a text response returned by an MCP tool call.
// Returns a typed error for known gateway auth failures, PAT interceptions,
// and business-level errors embedded in HTTP-200 JSON bodies.
//
// Check order: PAT/permission veto > DWS gateway > generic business error.
func ClassifyMCPResponseText(text string) error {
	var body map[string]any
	if json.Unmarshal([]byte(text), &body) != nil {
		return nil
	}
	if IsExplicitSuccessEnvelope(body) {
		return nil
	}

	if code, source, ok := findPATErrorBody(body, 0); ok {
		return newPATError(source, code)
	}
	if IsExplicitErrorEnvelope(body) && hasAuthPermissionVeto(body, 0) {
		return permissionVetoError(body)
	}
	if code, ok := getDWSGatewayErrorCode(body); ok {
		return NewAuth("DWS gateway rejected the current login state",
			WithReason("gateway_auth_expired"),
			WithHint(authExpiredHint()),
			WithServerDiag(ServerDiagnostics{ServerErrorCode: code}),
		)
	}

	if isNotLoggedInError(body) {
		return NewAuth("当前未登录",
			WithReason("not_configured"),
			WithHint(notLoggedInHint()),
			WithActions("dws auth login"),
		)
	}

	if isBusinessError(body) {
		return NewAPI(text,
			WithReason("business_error"),
			WithHint(suggestForBusinessErrorText(body)),
		)
	}

	return nil
}

// ---- Hints -----------------------------------------------------------------

func authExpiredHint() string {
	return "Re-authenticate: dws auth login"
}

func notLoggedInHint() string {
	return "请先登录：dws auth login"
}

func permissionVetoError(payload any) error {
	code := permissionDiagnosticCode(payload, 0)
	opts := []Option{
		WithReason("permission_denied"),
		WithHint("确认当前组织，并授予操作所需的权限或 scope 后重试"),
	}
	if code != "" {
		opts = append(opts, WithServerDiag(ServerDiagnostics{ServerErrorCode: code}))
	}
	return NewAuth("Permission or scope authorization is required", opts...)
}

func hasAuthPermissionVeto(value any, depth int) bool {
	return permissionDiagnosticCode(value, depth) != ""
}

func permissionDiagnosticCode(value any, depth int) string {
	if depth > 8 {
		return ""
	}
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			compactKey := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
			switch compactKey {
			case "httpstatus", "status", "statuscode", "rpcstatus":
				if permissionStatusForbidden(child) {
					return "http_403"
				}
			case "code", "errorcode", "errcode", "servererrorcode":
				if permissionStatusForbidden(child) {
					return "http_403"
				}
				if code, ok := child.(string); ok && isPermissionVetoCode(code) {
					return strings.ToUpper(strings.TrimSpace(code))
				}
			case "missingscope", "missingscopes", "requiredscope", "requiredscopes":
				if hasPermissionScopeEvidence(child) {
					return "scope_required"
				}
			}
			if code := permissionDiagnosticCode(child, depth+1); code != "" {
				return code
			}
		}
	case []any:
		for _, child := range current {
			if code := permissionDiagnosticCode(child, depth+1); code != "" {
				return code
			}
		}
	case string:
		if isPermissionVetoCode(current) {
			return strings.ToUpper(strings.TrimSpace(current))
		}
	}
	return ""
}

func hasPermissionScopeEvidence(value any) bool {
	switch current := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(current) != ""
	case []any:
		return len(current) > 0
	case []string:
		return len(current) > 0
	case map[string]any:
		return len(current) > 0
	case bool:
		return current
	default:
		return strings.TrimSpace(fmt.Sprint(current)) != ""
	}
}

func permissionStatusForbidden(value any) bool {
	switch current := value.(type) {
	case int:
		return current == 403
	case int32:
		return current == 403
	case int64:
		return current == 403
	case uint:
		return current == 403
	case uint32:
		return current == 403
	case uint64:
		return current == 403
	case float64:
		return current == 403
	case string:
		return strings.TrimSpace(current) == "403"
	default:
		return false
	}
}

func isPermissionVetoCode(code string) bool {
	code = strings.ToUpper(strings.TrimSpace(code))
	if patNoPermissionCodes[code] || patAuthRequiredCodes[code] {
		return true
	}
	switch code {
	case "CLI_ORG_NOT_AUTHORIZED", "AUTH_PERMISSION_DENIED", "PERMISSION_DENIED", "FORBIDDEN", "ORG_DOC_TOKEN_MISMATCH":
		return true
	default:
		return false
	}
}

func suggestForBusinessErrorText(body map[string]any) string {
	msg := ""
	if v, ok := body["errorMsg"].(string); ok {
		msg = v
	} else if v, ok := body["message"].(string); ok {
		msg = v
	} else if v, ok := body["error"].(string); ok {
		msg = v
	}
	switch {
	case strings.Contains(msg, "搜索内容不能为空"):
		return "请提供非空搜索关键词: dws doc search --query \"关键词\""
	case strings.Contains(msg, "User has no permission to access this email"):
		return "请确认邮箱地址正确，查看可用邮箱: dws mail mailbox list"
	case strings.Contains(msg, "频率超限") || strings.Contains(msg, "rate limit"):
		return "API rate limit exceeded, wait a moment and retry"
	case strings.Contains(msg, "参数错误") || strings.Contains(msg, "param error"):
		return "Check input parameters. Use --help for available flags"
	default:
		return "MCP tool returned a business error; check parameters and refer to skill documentation."
	}
}

// ---- PAT JSON helpers ------------------------------------------------------

var patAllowedDataKeys = map[string]bool{
	"agentCode":           true,
	"authRequestId":       true,
	"authUrl":             true,
	"authorizationUrl":    true,
	"clientId":            true,
	"errorType":           true,
	"flowId":              true,
	"grantOptions":        true,
	"grantType":           true,
	"grantTypes":          true,
	"missingScope":        true,
	"missingScopes":       true,
	"policy":              true,
	"pollIntervalSeconds": true,
	"productCode":         true,
	"requestId":           true,
	"requiredScope":       true,
	"requiredScopes":      true,
	"riskLevel":           true,
	"scope":               true,
	"scopes":              true,
	"uri":                 true,
}

// ApplyHostMutations writes the two stderr-JSON fields the host integration
// contract requires onto out["data"]:
//   - data.hostControl: present iff the CLI is in host-owned mode (i.e.
//     HostControlBlock returns non-nil); legacy data.callbacks is stripped
//     in the same pass so passive classifier and active retry paths stay
//     byte-for-byte aligned.
//   - data.openBrowser: always present; reflects the user's PAT browser
//     policy.
//
// Centralizing the two writes here is the single-injection invariant —
// any caller that produces a PAT-shaped stderr payload (cleanPATJSON,
// active-retry enrichers, scope-required builders) MUST go through this
// function instead of writing the fields directly. out["data"] is
// promoted to map[string]any if missing or of the wrong type.
func ApplyHostMutations(out map[string]any) {
	data := ensurePATData(out)
	if rawURI := patAuthorizationURIFromData(data); rawURI != "" {
		if authURL := TrustedPATAuthorizationURL(rawURI); authURL != "" {
			data["uri"] = authURL
		} else {
			delete(data, "uri")
		}
		delete(data, "authUrl")
		delete(data, "authorizationUrl")
	}
	if block := HostControlBlock(); block != nil {
		delete(data, "callbacks")
		data["hostControl"] = block
	}
	data["openBrowser"] = PATOpenBrowserValue()
}

func ensurePATData(out map[string]any) map[string]any {
	data, ok := out["data"].(map[string]any)
	if !ok || data == nil {
		data = map[string]any{}
		out["data"] = data
	}
	return data
}

func patAuthorizationURIFromData(data map[string]any) string {
	for _, key := range []string{"uri", "authUrl", "authorizationUrl"} {
		value, _ := data[key].(string)
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// PATAuthorizationURL returns the best URL for hosts to open or show to users.
// It keeps already-complete PAT URLs unchanged. For DingTalk's legacy
// /fe/old#%2FpersonalAuthorization?... hash-route form, it adds the explicit
// hash query and decoded fragment route used by the working authorization page.
func PATAuthorizationURL(rawURI string) string {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return ""
	}

	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return rawURI
	}
	if !strings.HasSuffix(parsed.Path, "/fe/old") {
		return rawURI
	}
	if parsed.Query().Get("hash") != "" && strings.Contains(parsed.Fragment, "personalAuthorization") {
		return rawURI
	}

	routeQuery := patAuthorizationRouteQuery(parsed)
	if routeQuery.Get("flowId") == "" || routeQuery.Get("userCode") == "" {
		return rawURI
	}

	route := "/personalAuthorization?" + routeQuery.Encode()

	next := *parsed
	query := next.Query()
	query.Set("hash", "#"+route)
	next.RawQuery = query.Encode()
	next.Fragment = route
	next.RawFragment = ""
	return next.String()
}

// TrustedPATAuthorizationURL validates a PAT authorization URL for display or
// browser opening. Only credential-free HTTPS DingTalk URLs are accepted.
func TrustedPATAuthorizationURL(rawURI string) string {
	value := sanitizePATAuthorizationURI(rawURI)
	trusted, _ := value.(string)
	return trusted
}

func patAuthorizationRouteQuery(parsed *url.URL) url.Values {
	candidates := []string{
		parsed.Fragment,
		parsed.RawFragment,
		parsed.Query().Get("hash"),
	}
	for _, candidate := range candidates {
		if values := parsePersonalAuthorizationRouteQuery(candidate); values.Get("flowId") != "" && values.Get("userCode") != "" {
			return values
		}
		if decoded, err := url.QueryUnescape(candidate); err == nil && decoded != candidate {
			if values := parsePersonalAuthorizationRouteQuery(decoded); values.Get("flowId") != "" && values.Get("userCode") != "" {
				return values
			}
		}
	}
	return nil
}

func parsePersonalAuthorizationRouteQuery(route string) url.Values {
	route = strings.TrimSpace(route)
	route = strings.TrimPrefix(route, "#")
	idx := strings.Index(route, "personalAuthorization?")
	if idx < 0 {
		return nil
	}
	rawQuery := route[idx+len("personalAuthorization?"):]
	if cut := strings.IndexAny(rawQuery, "?#"); cut >= 0 {
		rawQuery = rawQuery[:cut]
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil
	}
	return values
}

func cleanPATJSON(body map[string]any, code string) string {
	out := map[string]any{
		"success": false,
		"code":    code,
	}
	source := any(body)
	if data, ok := body["data"]; ok {
		source = data
	}
	if data := sanitizePATRoot(source); len(data) > 0 {
		out["data"] = data
	}
	ApplyHostMutations(out)
	if code == "PAT_ORG_POLICY_DENIED" {
		applyOrgPolicyDeniedHint(out)
	}

	// stderr JSON MUST be a single-line, directly json.Unmarshal-able
	// payload — pretty-printing would break naïve host parsers that read
	// stderr line-by-line and fail on leading whitespace.
	b, err := marshalSingleLineJSONNoHTMLEscape(out)
	if err != nil {
		return fmt.Sprintf(`{"success":false,"code":"%s"}`, code)
	}
	return string(b)
}

func applyOrgPolicyDeniedHint(out map[string]any) {
	data := ensurePATData(out)
	if _, ok := data["policy"]; !ok {
		data["policy"] = "OPEN_SOURCE_ORG_SCOPE_FORBIDDEN"
	}
	data["hint"] = "组织策略已禁止当前工具所需的开源数据权限，请联系组织管理员在 DWS/PAT 权限管控中放开对应 scope 后重试。"
	data["action"] = "contact_org_admin"
	data["openBrowser"] = false
	data["retryable"] = false
}

func sanitizePATRoot(value any) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return sanitizePATObject(object)
}

// sanitizePATObject is allowlist-only. The PAT payload is written directly to
// stderr and parsed by host applications, so unknown fields must never become
// an implicit credential, identity, free-text, or signed-URL channel.
func sanitizePATObject(object map[string]any) map[string]any {
	clean := make(map[string]any)
	for key, raw := range object {
		if !patAllowedDataKeys[key] {
			continue
		}
		var value any
		switch key {
		case "uri", "authUrl", "authorizationUrl":
			value = sanitizePATAuthorizationURI(raw)
		case "pollIntervalSeconds":
			value = sanitizePATPollInterval(raw)
		default:
			value = sanitizePATValue(raw)
		}
		if hasPATData(value) {
			clean[key] = value
		}
	}
	return clean
}

func sanitizePATValue(value any) any {
	switch current := value.(type) {
	case map[string]any:
		return sanitizePATObject(current)
	case []any:
		clean := make([]any, 0, len(current))
		for _, item := range current {
			if sanitized := sanitizePATValue(item); hasPATData(sanitized) {
				clean = append(clean, sanitized)
			}
		}
		return clean
	case string:
		return sanitizePATIdentifier(current)
	case bool:
		return current
	default:
		return nil
	}
}

func sanitizePATIdentifier(value string) any {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 {
		return nil
	}
	hasNonDigit := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == ':' {
			if r < '0' || r > '9' {
				hasNonDigit = true
			}
			continue
		}
		return nil
	}
	if !hasNonDigit {
		return nil
	}
	lower := strings.ToLower(value)
	for _, sensitive := range []string{
		"access_token", "refreshtoken", "refresh_token", "authorization",
		"clientsecret", "client_secret", "userid", "user_id", "uid:",
		"corpid", "corp_id", "bearer:",
	} {
		if strings.Contains(lower, sensitive) {
			return nil
		}
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "", ":", "").Replace(lower)
	for _, sensitive := range []string{
		"accesstoken", "refreshtoken", "clientsecret", "authorization",
		"idtoken", "bearer", "userid", "corpid",
	} {
		if strings.Contains(compact, sensitive) {
			return nil
		}
	}
	if strings.HasPrefix(compact, "uid") && len(compact) > len("uid") {
		return nil
	}
	if len(value) > 40 && strings.Count(value, ".") == 2 {
		return nil
	}
	return value
}

func sanitizePATPollInterval(value any) any {
	var interval int
	switch current := value.(type) {
	case int:
		interval = current
	case int64:
		interval = int(current)
	case float64:
		if current != float64(int(current)) {
			return nil
		}
		interval = int(current)
	default:
		return nil
	}
	if interval < 1 || interval > 60 {
		return nil
	}
	return interval
}

func sanitizePATAuthorizationURI(value any) any {
	raw, ok := value.(string)
	if !ok {
		return nil
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 4096 || containsSensitivePATURLMaterial(raw) {
		return nil
	}
	normalized := PATAuthorizationURL(raw)
	parsed, err := url.Parse(normalized)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.User != nil {
		return nil
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	trusted := host == "dingtalk.com" || strings.HasSuffix(host, ".dingtalk.com") ||
		host == "dingtalkapps.com" || strings.HasSuffix(host, ".dingtalkapps.com")
	if !trusted || (parsed.Port() != "" && parsed.Port() != "443") {
		return nil
	}
	if containsSensitivePATURLMaterial(normalized) {
		return nil
	}
	return normalized
}

func containsSensitivePATURLMaterial(raw string) bool {
	decoded := strings.ToLower(raw)
	for range 3 {
		for _, marker := range []string{
			"access_token=", "refresh_token=", "client_secret=", "clientsecret=",
			"id_token=", "authorization=", "bearer%20", "token=",
		} {
			if strings.Contains(decoded, marker) {
				return true
			}
		}
		next, err := url.QueryUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	return false
}

func hasPATData(value any) bool {
	switch current := value.(type) {
	case map[string]any:
		return len(current) > 0
	case []any:
		return len(current) > 0
	default:
		return current != nil
	}
}

func marshalSingleLineJSONNoHTMLEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

// ---- Runner adapter functions ------------------------------------------------
// These match the function signatures referenced by runner.go's PAT check
// framework (ClassifyPatAuthCheck / AsPatAuthCheckError).

// ClassifyPatAuthCheck is the open-source fallback that checks a tool-call
// Content map for PAT permission codes and auth-required codes. Returns a
// non-nil *PATError when the content carries a recognised PAT/auth error.
func ClassifyPatAuthCheck(content map[string]any) *PATError {
	if IsExplicitSuccessEnvelope(content) {
		return nil
	}
	if code, source, ok := findPATErrorBody(content, 0); ok {
		return newPATError(source, code)
	}
	return nil
}

// AsPatAuthCheckError extracts a *PATError from an error chain.
func AsPatAuthCheckError(err error) *PATError {
	var patErr *PATError
	if stderrors.As(err, &patErr) {
		return patErr
	}
	return nil
}

func stripClassFields(v any) any {
	switch val := v.(type) {
	case map[string]any:
		clean := make(map[string]any, len(val))
		for k, item := range val {
			if k == "class" {
				continue
			}
			clean[k] = stripClassFields(item)
		}
		return clean
	case []any:
		clean := make([]any, len(val))
		for i, item := range val {
			clean[i] = stripClassFields(item)
		}
		return clean
	default:
		return v
	}
}

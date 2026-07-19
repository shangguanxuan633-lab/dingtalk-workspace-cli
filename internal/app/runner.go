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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/audit"
	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/cli"
	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/executor"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/logging"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/safety"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/transport"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/authretry"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/configmeta"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
	"github.com/google/uuid"
)

func init() {
	runnerHandlePatAuthCheck = handlePatAuthCheck
	runnerRetryWithPatAuthRetry = retryWithPatAuthRetry

	configmeta.Register(configmeta.ConfigItem{
		Name:        "DWS_RUNTIME_CONTENT_SCAN",
		Category:    configmeta.CategoryRuntime,
		Description: "启用 MCP 响应内容安全扫描",
		Example:     "true",
	})
	configmeta.Register(configmeta.ConfigItem{
		Name:        "DWS_RUNTIME_CONTENT_SCAN_ENFORCE",
		Category:    configmeta.CategoryRuntime,
		Description: "内容安全扫描发现问题时阻断响应",
		Example:     "true",
	})
	configmeta.Register(configmeta.ConfigItem{
		Name:        "DWS_RUNTIME_CONTENT_SCAN_REPORT",
		Category:    configmeta.CategoryRuntime,
		Description: "在 JSON 输出中包含安全扫描报告",
		Example:     "true",
	})
	configmeta.Register(configmeta.ConfigItem{
		Name:        "DINGTALK_AGENT",
		Category:    configmeta.CategoryExternal,
		Description: "业务 Agent 名称；仅用于 x-dingtalk-agent 请求头，与 claw-type/host-owned PAT 判定无关",
	})
	configmeta.Register(configmeta.ConfigItem{
		Name:        "DINGTALK_TRACE_ID",
		Category:    configmeta.CategoryExternal,
		Description: "MCP 请求 x-dingtalk-trace-id 头",
	})
	configmeta.Register(configmeta.ConfigItem{
		Name:        "DINGTALK_SESSION_ID",
		Category:    configmeta.CategoryExternal,
		Description: "MCP 请求 x-dingtalk-session-id 头",
	})
	configmeta.Register(configmeta.ConfigItem{
		Name:        "DINGTALK_MESSAGE_ID",
		Category:    configmeta.CategoryExternal,
		Description: "MCP 请求 x-dingtalk-message-id 头",
	})
}

const (
	runtimeContentScanEnv             = "DWS_RUNTIME_CONTENT_SCAN"
	runtimeContentScanEnforceEnv      = "DWS_RUNTIME_CONTENT_SCAN_ENFORCE"
	runtimeContentScanReportOutputEnv = "DWS_RUNTIME_CONTENT_SCAN_REPORT"

	// Environment variables for MCP request headers (passed from caller)
	envDingtalkAgent     = "DINGTALK_AGENT"
	envDingtalkTraceID   = "DINGTALK_TRACE_ID"
	envDingtalkSessionID = "DINGTALK_SESSION_ID"
	envDingtalkMessageID = "DINGTALK_MESSAGE_ID"
	envDWSSessionID      = "DWS_SESSION_ID"
	envRewindSessionID   = "REWIND_SESSION_ID"

	// Environment variables for third-party channel integration
	envDWSChannel = "DWS_CHANNEL"
)

// hostOwnedPATDecisionOnce ensures the host-owned PAT decision is logged at
// most once per CLI process. The log line is emitted at Debug level so
// `--debug` (or `--verbose`) surfaces it on stderr; the file logger at
// ~/.dws/logs/dws.log captures it unconditionally at DEBUG. It records
// ONLY the derived booleans — never the env value, token, client-id or
// flow-id — so logs remain safe to attach to issues.
var hostOwnedPATDecisionOnce sync.Once

// logHostOwnedPATDecisionOnce emits the single-shot debug trace. It is
// called lazily from the runtime Run path (which executes AFTER
// PersistentPreRunE has applied --debug / --verbose via configureLogLevel)
// so the line actually surfaces when the user asks for it.
func logHostOwnedPATDecisionOnce() {
	hostOwnedPATDecisionOnce.Do(func() {
		slog.Debug("runtime.host_owned_pat",
			"hostOwned", authpkg.HostOwnsPATFlow(),
			"agentCodeEnvPresent", authpkg.AgentCodeEnvPresent(),
		)
	})
}

func newCommandRunnerWithFlags(loader cli.CatalogLoader, flags *GlobalFlags) executor.Runner {
	// Ensure DWS_CLIENT_ID env is populated from persisted config before
	// resolveIdentityHeaders reads it.  This covers fresh-process cold starts
	// where no env var has been inherited from a parent process.
	if os.Getenv("DWS_CLIENT_ID") == "" {
		if cid := authpkg.ClientID(); cid != "" {
			_ = os.Setenv("DWS_CLIENT_ID", cid)
		}
	}

	var httpClient *http.Client
	if flags != nil && flags.Timeout > 0 {
		httpClient = &http.Client{Timeout: time.Duration(flags.Timeout) * time.Second}
	}
	transportClient := transport.NewClient(httpClient)
	transportClient.ExtraHeaders = resolveIdentityHeaders()
	transportClient.FileLogger = FileLoggerInstance()
	return &runtimeRunner{
		loader:             loader,
		transport:          transportClient,
		globalFlags:        flags,
		fallback:           executor.EchoRunner{},
		scanner:            newRuntimeContentScanner(),
		enforceContentScan: runtimeFlagEnabled(os.Getenv(runtimeContentScanEnforceEnv), false),
		includeScanReport:  runtimeFlagEnabled(os.Getenv(runtimeContentScanReportOutputEnv), false),
	}
}

type runtimeRunner struct {
	loader             cli.CatalogLoader
	transport          *transport.Client
	globalFlags        *GlobalFlags
	fallback           executor.Runner
	scanner            safety.Scanner
	enforceContentScan bool
	includeScanReport  bool
	auditSink          audit.Sink
}

var (
	runnerResolveMultiProfileSelections = resolveMultiProfileSelections
	runnerResolveProfile                = authpkg.ResolveProfile
	runnerPreflightDocDownload          = (*runtimeRunner).preflightDocDownload
	runnerCallTool                      = (*transport.Client).CallTool
	runnerStdioEnsureInitialized        = (*transport.StdioClient).EnsureInitialized
	runnerStdioCallTool                 = (*transport.StdioClient).CallTool
	runnerHandlePatAuthCheck            func(context.Context, *runtimeRunner, executor.Invocation, *apperrors.PATError, string, io.Writer) (executor.Result, error)
	runnerRetryWithPatAuthRetry         func(context.Context, executor.Runner, executor.Invocation, *PatScopeError, string, io.Writer) (executor.Result, error)
	runnerCaptureRuntimeFailure         = captureRuntimeFailure
)

func (r *runtimeRunner) Run(ctx context.Context, invocation executor.Invocation) (executor.Result, error) {
	// Global dry-run is an execution barrier, not merely a transport option.
	// Return a deterministic local preview before profile resolution, catalog
	// discovery, Keychain/token prefetch, auth, stateful preflight or transport.
	// Use the non-injectable EchoRunner rather than r.fallback so tests and
	// edition overlays cannot accidentally turn this path into real execution.
	if invocation.DryRun || (r != nil && r.globalFlags != nil && r.globalFlags.DryRun) {
		invocation.DryRun = true
		return (executor.EchoRunner{}).Run(ctx, invocation)
	}
	if r == nil {
		return executor.Result{}, fmt.Errorf("runtime runner is not configured")
	}
	// Emit the one-shot host-owned PAT decision log. Placed here (not in
	// the constructor) so it fires AFTER PersistentPreRunE has configured
	// slog level per --debug / --verbose. The Once guard makes repeat
	// invocations within the same process free.
	logHostOwnedPATDecisionOnce()

	rawProfile := authpkg.RuntimeProfile()
	selections, multi, err := runnerResolveMultiProfileSelections(defaultConfigDir(), rawProfile)
	if err != nil {
		return executor.Result{}, apperrors.NewValidation(err.Error())
	}
	if multi {
		return r.runMultiProfile(ctx, invocation, selections)
	}
	requestProfile := ""
	if strings.TrimSpace(rawProfile) != "" {
		profile, err := authpkg.ResolveProfile(defaultConfigDir(), rawProfile)
		if err != nil {
			return executor.Result{}, apperrors.NewValidation(err.Error())
		}
		if profile == nil {
			return executor.Result{}, apperrors.NewValidation(fmt.Sprintf("profile %q not found", rawProfile))
		}
		requestProfile = authpkg.ProfileSelector(*profile)
	} else {
		profile, err := authpkg.ResolveProfile(defaultConfigDir(), "")
		if err != nil {
			return executor.Result{}, apperrors.NewValidation(err.Error())
		}
		if profile != nil {
			requestProfile = authpkg.ProfileSelector(*profile)
		}
	}

	return r.runSingle(withLogicalProfile(ctx, requestProfile), invocation, true)
}

func (r *runtimeRunner) runSingle(ctx context.Context, invocation executor.Invocation, _ bool) (executor.Result, error) {
	if r.loader == nil || r.transport == nil {
		return r.fallback.Run(ctx, invocation)
	}

	// Mock mode: skip catalog validation, use a placeholder endpoint.
	if r.globalFlags != nil && r.globalFlags.Mock {
		endpoint := fmt.Sprintf("https://mock-mcp-%s.dingtalk.com", invocation.CanonicalProduct)
		if override, ok := productEndpointOverride(invocation.CanonicalProduct); ok {
			endpoint = override
		}
		return r.executeInvocation(ctx, endpoint, invocation)
	}

	invocation = attachVerifiedToolIdempotency(invocation)

	if shouldUseDirectRuntime(invocation) {
		if endpoint, ok := directRuntimeEndpoint(invocation.CanonicalProduct, invocation.Tool); ok {
			return r.executeInvocation(ctx, endpoint, invocation)
		}
	}

	catalogStart := time.Now()
	catalog, err := r.loader.Load(ctx)
	RecordTiming(ctx, "catalog_load", time.Since(catalogStart))
	if err != nil {
		var degraded *cli.CatalogDegraded
		if !errors.As(err, &degraded) {
			return executor.Result{}, err
		}
	}

	product, ok := catalog.FindProduct(invocation.CanonicalProduct)
	if !ok || strings.TrimSpace(product.Endpoint) == "" {
		return r.handleCatalogMiss(ctx, invocation, "product missing from discovery catalog and no supplement/env override")
	}
	if _, ok := product.FindTool(invocation.Tool); !ok {
		// Catalog knows the product but not the tool — this happens when the
		// catalog entry came from SupplementServers (endpoint-only, no tool
		// list). Trust directRuntimeEndpoint to re-resolve a working endpoint
		// for the tool. If that also misses, fall through to handleCatalogMiss
		// so stderr still carries the explicit not-resolved signal.
		if endpoint, ok := directRuntimeEndpoint(invocation.CanonicalProduct, invocation.Tool); ok {
			if r.globalFlags != nil && r.globalFlags.DryRun {
				invocation.DryRun = true
			}
			return r.executeInvocation(ctx, endpoint, invocation)
		}
		return r.handleCatalogMiss(ctx, invocation, fmt.Sprintf("tool %q not declared by product %q in discovery catalog", invocation.Tool, invocation.CanonicalProduct))
	}
	if r.globalFlags != nil && r.globalFlags.DryRun {
		invocation.DryRun = true
	}

	endpoint := product.Endpoint
	if override, ok := productEndpointOverride(invocation.CanonicalProduct); ok {
		endpoint = override
	}
	// Multi-server tool-name authority correction.
	//
	// When two envelope servers share the same cli.command (e.g. group-chat
	// and im both publish `dws chat ...`), the endpoints[cmd] map in
	// registerDynamicServer is the second-writer wins, and catalog FindProduct
	// may pick the wrong product's Endpoint for a tool whose real owner is
	// a different server. Cross-check the canonical tool→endpoint map: when
	// the per-tool endpoint exists and differs from the per-product endpoint
	// catalog returned, trust the tool-owner endpoint (the server that
	// actually declares this tool in its toolOverrides).
	if toolEndpoint, ok := directRuntimeToolEndpoint(invocation.Tool); ok && toolEndpoint != "" && toolEndpoint != endpoint {
		endpoint = toolEndpoint
	}
	return r.executeInvocation(ctx, endpoint, invocation)
}

// attachVerifiedToolIdempotency adds the documented business idempotency key
// centrally, covering hardcoded helpers, shortcuts, editions, and direct
// ToolCaller users. It runs once before the first HTTP request; auth recovery
// reuses the same invocation map and therefore the same UUID.
func attachVerifiedToolIdempotency(invocation executor.Invocation) executor.Invocation {
	if strings.TrimSpace(invocation.Tool) != "send_personal_message" {
		return invocation
	}
	if existing, ok := invocation.Params["uuid"].(string); ok && strings.TrimSpace(existing) != "" {
		return invocation
	}
	invocation = cloneInvocation(invocation)
	if invocation.Params == nil {
		invocation.Params = make(map[string]any)
	}
	invocation.Params["uuid"] = uuid.NewString()
	return invocation
}

type multiProfileSelection struct {
	Selector string
	Profile  authpkg.Profile
}

func resolveMultiProfileSelections(configDir, rawSelector string) ([]multiProfileSelection, bool, error) {
	rawSelector = strings.TrimSpace(rawSelector)
	if rawSelector == "" || !strings.Contains(rawSelector, ",") {
		return nil, false, nil
	}
	if p, err := runnerResolveProfile(configDir, rawSelector); err == nil && p != nil {
		return nil, false, nil
	}

	parts := strings.Split(rawSelector, ",")
	selections := make([]multiProfileSelection, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		selector := strings.TrimSpace(part)
		if selector == "" {
			return nil, false, fmt.Errorf("--profile contains an empty profile selector: %q", rawSelector)
		}
		profile, err := runnerResolveProfile(configDir, selector)
		if err != nil {
			return nil, false, err
		}
		if profile == nil {
			return nil, false, fmt.Errorf("profile %q not found", selector)
		}
		identitySelector := authpkg.ProfileSelector(*profile)
		if seen[identitySelector] {
			continue
		}
		seen[identitySelector] = true
		selections = append(selections, multiProfileSelection{
			Selector: selector,
			Profile:  *profile,
		})
	}
	return selections, true, nil
}

func (r *runtimeRunner) runMultiProfile(ctx context.Context, invocation executor.Invocation, selections []multiProfileSelection) (executor.Result, error) {
	entries := make([]any, 0, len(selections))
	succeeded := 0
	failed := 0

	for _, selection := range selections {
		resolvedSelector := authpkg.ProfileSelector(selection.Profile)
		result, err := r.runSingle(withLogicalProfile(ctx, resolvedSelector), cloneInvocation(invocation), false)

		entry := map[string]any{
			"selector": selection.Selector,
			"profile":  resolvedSelector,
			"corpId":   selection.Profile.CorpID,
			"corpName": selection.Profile.CorpName,
			"userId":   selection.Profile.UserID,
			"userName": selection.Profile.UserName,
			"ok":       err == nil,
		}
		if err != nil {
			failed++
			entry["error"] = multiProfileErrorPayload(err)
		} else {
			succeeded++
			if payload := multiProfileResultPayload(result); payload != nil {
				entry["result"] = payload
			}
			if result.Response != nil {
				if endpoint, ok := result.Response["endpoint"]; ok {
					entry["endpoint"] = endpoint
				}
			}
		}
		entries = append(entries, entry)
	}

	invocation.Implemented = true
	return executor.Result{
		Invocation: invocation,
		Response: map[string]any{
			"content": map[string]any{
				"success":      failed == 0,
				"multiProfile": true,
				"summary": map[string]any{
					"total":     len(selections),
					"succeeded": succeeded,
					"failed":    failed,
				},
				"profiles": entries,
			},
		},
	}, nil
}

func cloneInvocation(invocation executor.Invocation) executor.Invocation {
	cloned := invocation
	if invocation.Params != nil {
		cloned.Params = make(map[string]any, len(invocation.Params))
		for key, value := range invocation.Params {
			cloned.Params[key] = value
		}
	}
	return cloned
}

func multiProfileResultPayload(result executor.Result) any {
	if result.Response == nil {
		return nil
	}
	if content, ok := result.Response["content"]; ok {
		return content
	}
	return result.Response
}

func multiProfileErrorPayload(err error) map[string]any {
	payload := map[string]any{
		"message": err.Error(),
	}
	var typed *apperrors.Error
	if errors.As(err, &typed) {
		payload["category"] = string(typed.Category)
		if typed.Reason != "" {
			payload["reason"] = typed.Reason
		}
		if typed.Operation != "" {
			payload["operation"] = typed.Operation
		}
		if code := typed.ExitCode(); code != 0 {
			payload["exitCode"] = code
		}
	}
	return payload
}

// handleCatalogMiss decides what to do when discovery catalog does not cover the
// requested product / tool and no `directRuntimeEndpoint` match fired earlier.
//
// Previously every catalog miss silently fell through to EchoRunner, which
// returns an empty `executor.Result{Response: nil}`. The helper-invocation
// adapter then converted that into `&edition.ToolResult{}`, whose `Content`
// marshals to `null`, surfacing as `{"Content": null}` at the CLI. Users had no
// signal that endpoint resolution failed — see the fix-wukong-discovery-missing-servers plan (Phase 3) for the full trace.
//
// New contract:
//   - Dry-run (invocation.DryRun or globalFlags.DryRun): keep EchoRunner so
//     `--dry-run` still prints the planned payload without real execution.
//   - Otherwise: return an explicit apperrors.NewAPI("endpoint_not_resolved")
//     with the offending product/tool attached. This fails fast to stderr and
//     makes missing envelopes / supplement gaps immediately visible.
func (r *runtimeRunner) handleCatalogMiss(ctx context.Context, invocation executor.Invocation, detail string) (executor.Result, error) {
	dryRun := invocation.DryRun || (r.globalFlags != nil && r.globalFlags.DryRun)
	if dryRun {
		invocation.DryRun = true
		return r.fallback.Run(ctx, invocation)
	}
	hint := "当前命令已注册，但静态端点目录中缺少对应 product/server endpoint。这通常是服务发现下线后的同步产物缺口，不是参数错误；请不要通过反复调整 flag 重试。"
	actions := []string{
		"确认 internal/syncdata.StaticServers() 是否包含该 product/server",
		"运行 sync-oss 重新生成静态端点与路由",
		"若该能力已下线，请在 skill 与 --help 中标记 unavailable 并提供替代命令",
	}
	if strings.TrimSpace(invocation.CanonicalProduct) == devappProductID {
		hint = "dev app（product id: devapp）是 helper-only 产品，命令树不依赖服务发现；真实调用需要通过 StaticServers/SupplementServers 注入 MCP endpoint，或本地调试临时设置 DINGTALK_DEVAPP_MCP_URL。"
		actions = []string{
			"检查 StaticServers/SupplementServers 是否包含 devapp endpoint",
			"本地调试可临时设置 DINGTALK_DEVAPP_MCP_URL 后重试",
		}
	}
	return executor.Result{}, apperrors.NewAPI(
		fmt.Sprintf("endpoint not resolved for product %q (tool %q): %s", invocation.CanonicalProduct, invocation.Tool, detail),
		apperrors.WithOperation("discovery.resolve"),
		apperrors.WithReason("endpoint_not_resolved"),
		apperrors.WithServerKey(invocation.CanonicalProduct),
		apperrors.WithHint(hint),
		apperrors.WithActions(actions...),
	)
}

func (r *runtimeRunner) executeInvocation(ctx context.Context, endpoint string, invocation executor.Invocation) (result executor.Result, retErr error) {
	// Route stdio:// endpoints to the local StdioClient — no HTTP, no auth.
	if IsStdioEndpoint(endpoint) {
		return r.executeStdioInvocation(ctx, invocation)
	}

	// Constructing the Cobra tree is also used for help, schema, and command
	// discovery. Open the process-wide audit writer only when a real invocation
	// reaches the execution boundary so read-only command inspection does not
	// leave an audit lock handle behind (which prevents TempDir cleanup on
	// Windows). Keep an injected sink when tests or editions provide one.
	logicalAttempt := !IsAuthRetrying(ctx)
	var auditSink audit.Sink
	if logicalAttempt {
		auditSink = r.auditSink
		if auditSink == nil {
			auditSink = setupAuditSink()
		}
	}

	invokeStart := time.Now()
	execID, present := logicalExecutionID(ctx)
	if !present {
		execID = generateExecutionID()
		ctx = context.WithValue(ctx, logicalExecutionIDKey{}, execID)
	}
	// Never mutate the shared base client. Concurrent invocations must not race
	// on ExecutionId/FileLogger and accidentally send another command's
	// execution or idempotency correlation headers.
	baseTransport := r.transport.WithExecutionId(execID)
	if baseTransport.FileLogger == nil {
		baseTransport.FileLogger = FileLoggerInstance()
	}

	fl := baseTransport.FileLogger

	if logicalAttempt {
		defer func() {
			var errCat, errReason string
			if retErr != nil {
				var typed *apperrors.Error
				if errors.As(retErr, &typed) {
					errCat = string(typed.Category)
					errReason = typed.Reason
				} else {
					errCat = "unknown"
					errReason = "unclassified_error"
				}
			}
			logging.LogCommandEnd(fl, execID,
				invocation.CanonicalProduct, invocation.Tool,
				retErr == nil, time.Since(invokeStart), errCat, errReason)
			emitAudit(auditSink, execID, invokeStart, invocation, endpoint, retErr, version)
		}()
	}

	var timeoutSec int
	if r.globalFlags != nil {
		timeoutSec = r.globalFlags.Timeout
	}
	dryRun := invocation.DryRun || (r.globalFlags != nil && r.globalFlags.DryRun)
	if dryRun {
		if logicalAttempt {
			logging.LogCommandStart(fl, execID,
				invocation.CanonicalProduct, invocation.Tool, endpoint, version, false, timeoutSec)
		}
		if argsJSON, err := json.Marshal(invocation.Params); err == nil {
			fmt.Fprintf(os.Stderr, "DRY-RUN Arguments: %s\n", argsJSON)
		}
		return executor.Result{
			Invocation: invocation,
			Response: map[string]any{
				"dry_run":  true,
				"endpoint": transport.RedactURL(endpoint),
				"request":  executor.ToolCallRequest(invocation.Tool, invocation.Params),
				"note":     "execution skipped by --dry-run",
			},
		}, nil
	}
	if r.globalFlags != nil && r.globalFlags.Mock {
		if logicalAttempt {
			logging.LogCommandStart(fl, execID,
				invocation.CanonicalProduct, invocation.Tool, endpoint, version, false, timeoutSec)
		}
		invocation.Implemented = true
		return executor.Result{
			Invocation: invocation,
			Response: map[string]any{
				"endpoint": transport.RedactURL(endpoint),
				"content": map[string]any{
					"success": true,
					"result":  []any{},
					"_mock":   true,
					"_tool":   invocation.Tool,
				},
			},
		}, nil
	}

	// Keep this at the final HTTP boundary as well as runSingle so editions and
	// recovery/direct callers cannot bypass the verified business key.
	invocation = attachVerifiedToolIdempotency(invocation)

	// Check if this product has plugin-level auth credentials registered.
	// If so, use the plugin's token instead of the default DingTalk OAuth token.
	// This allows third-party MCP servers (e.g. Bailian) to use their own API keys.
	pluginAuth, hasPluginAuth := LookupPluginAuth(invocation.CanonicalProduct)

	authToken := ""
	authSnapshot := AccessTokenSnapshot{}
	if hasPluginAuth {
		authToken = pluginAuth.Token
	} else {
		snapshot, tokenErr := r.resolveAuthToken(ctx)
		if tokenErr != nil {
			return executor.Result{}, authResolutionError(tokenErr)
		}
		authSnapshot = snapshot
		authToken = snapshot.AccessToken
	}

	if logicalAttempt {
		logging.LogCommandStart(fl, execID,
			invocation.CanonicalProduct, invocation.Tool, endpoint, version, authToken != "", timeoutSec)
	}

	// Fail-fast: reject unauthenticated requests before making network calls.
	// This provides a clear error message instead of cryptic HTTP 400 from MCP.
	if strings.TrimSpace(authToken) == "" {
		return executor.Result{}, apperrors.NewAuth(
			"未登录，请先执行 dws auth login",
			apperrors.WithReason("not_authenticated"),
			apperrors.WithHint("运行 'dws auth login' 完成登录后重试"),
			apperrors.WithActions("dws auth login"),
		)
	}

	var tc *transport.Client
	if hasPluginAuth {
		// Use plugin-level auth: inject the plugin's token and trust its domains.
		tc = baseTransport.WithAuth(authToken, pluginAuth.ExtraHeaders)
		tc.TrustedDomains = pluginAuth.TrustedDomains
	} else {
		// Default path: use DingTalk OAuth token with identity headers.
		requestProfile, _ := logicalProfile(ctx)
		if authSnapshot.profilePinned {
			requestProfile = authSnapshot.profile
		}
		headers := resolveIdentityHeadersForProfile(requestProfile)
		// Every logical invocation gets a stable idempotency identifier even
		// when the caller did not supply one. executeInvocation carries execID in
		// the context, so transport retries and the one auth-refresh retry reuse
		// the exact same value rather than duplicating a write/owner-ack.
		if strings.TrimSpace(headers["x-dingtalk-message-id"]) == "" {
			headers["x-dingtalk-message-id"] = execID
		}
		tc = baseTransport.WithAuth(authToken, headers)
	}

	callCtx := ctx
	if r.globalFlags != nil && r.globalFlags.Timeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, time.Duration(r.globalFlags.Timeout)*time.Second)
		defer cancel()
	}

	if err := runnerPreflightDocDownload(r, callCtx, tc, endpoint, invocation); err != nil {
		if patCheck := apperrors.AsPatAuthCheckError(err); patCheck != nil {
			if IsPatRetrying(ctx) {
				return executor.Result{}, patCheck
			}
			return runnerHandlePatAuthCheck(ctx, r, invocation, patCheck, defaultConfigDir(), os.Stderr)
		}
		if attempted, result, retryErr := r.recoverAuthError(ctx, endpoint, invocation, authSnapshot, hasPluginAuth, err); attempted {
			if retryErr != nil {
				runnerCaptureRuntimeFailure(invocation, err, retryErr)
			}
			return result, retryErr
		}
		runnerCaptureRuntimeFailure(invocation, err, err)
		return executor.Result{}, err
	}

	callStart := time.Now()
	callResult, err := runnerCallTool(tc, callCtx, endpoint, invocation.Tool, invocation.Params)
	RecordTiming(ctx, "mcp_call", time.Since(callStart))
	if err != nil {
		if attempted, result, retryErr := r.recoverAuthError(ctx, endpoint, invocation, authSnapshot, hasPluginAuth, err); attempted {
			if retryErr != nil {
				runnerCaptureRuntimeFailure(invocation, err, retryErr)
			}
			return result, retryErr
		}
		// PAT scope error: offer human-readable output and retry after authorization
		if isPatScopeError(err) {
			scopeErr := extractPatScopeError(err)
			runnerCaptureRuntimeFailure(invocation, err, err)
			return runnerRetryWithPatAuthRetry(ctx, r, invocation, scopeErr, defaultConfigDir(), os.Stderr)
		}
		runnerCaptureRuntimeFailure(invocation, err, err)
		return executor.Result{}, err
	}

	coreRefresh, coreRejected := coreAuthRejectionFromContent(callResult.Content)

	// ---- Edition hook gets first dibs (preserves overlay PATError passthrough) ----
	if fn := edition.Get().ClassifyToolResult; fn != nil {
		if editionErr := fn(callResult.Content); editionErr != nil {
			if patCheck := apperrors.AsPatAuthCheckError(editionErr); patCheck != nil {
				if IsPatRetrying(ctx) {
					return executor.Result{}, patCheck // already retried once, don't loop
				}
				return runnerHandlePatAuthCheck(ctx, r, invocation, patCheck, defaultConfigDir(), os.Stderr)
			}
			if marker, marked := authretry.As(editionErr); marked {
				cause := marker.Cause
				if cause == nil {
					cause = editionErr
				}
				if r.canAutoRefreshAuth(hasPluginAuth, authSnapshot) && authRefreshAllowed(editionErr, cause) {
					result, retryErr := r.maybeAuthRefreshRetry(ctx, endpoint, invocation, authSnapshot, cause)
					if retryErr != nil {
						runnerCaptureRuntimeFailure(invocation, editionErr, retryErr)
					}
					return result, retryErr
				}
				return executor.Result{}, cause
			}
			return executor.Result{}, editionErr
		}
	}
	if coreRejected && r.canAutoRefreshAuth(hasPluginAuth, authSnapshot) && authRefreshAllowed(coreRefresh.Cause, coreRefresh.Cause) {
		result, retryErr := r.maybeAuthRefreshRetry(ctx, endpoint, invocation, authSnapshot, coreRefresh.Cause)
		if retryErr != nil {
			runnerCaptureRuntimeFailure(invocation, coreRefresh.Cause, retryErr)
		}
		return result, retryErr
	}

	// ---- Structured PAT auth check (open-source fallback) ----
	if patCheck := apperrors.ClassifyPatAuthCheck(callResult.Content); patCheck != nil {
		if IsPatRetrying(ctx) {
			return executor.Result{}, patCheck // already retried once, don't loop
		}
		return runnerHandlePatAuthCheck(ctx, r, invocation, patCheck, defaultConfigDir(), os.Stderr)
	}

	if callResult.IsError {
		diag := transport.ExtractServerDiagnosticsFromMap(callResult.Content)
		logBusinessError(fl, "mcp_tool_error", invocation, callResult.Content, diag)

		mcpErr := apperrors.NewAPI(
			extractMCPErrorMessage(callResult),
			apperrors.WithOperation("tools/call"),
			apperrors.WithReason("mcp_tool_error"),
			apperrors.WithServerKey(invocation.CanonicalProduct),
			apperrors.WithHint("MCP tool returned a business error; check tool parameters and refer to skill documentation."),
			apperrors.WithServerDiag(diag),
		)
		// PAT scope error in business response: offer human-readable output and retry
		if isPatScopeError(mcpErr) {
			scopeErr := extractPatScopeError(mcpErr)
			runnerCaptureRuntimeFailure(invocation, mcpErr, mcpErr)
			return runnerRetryWithPatAuthRetry(ctx, r, invocation, scopeErr, defaultConfigDir(), os.Stderr)
		}
		runnerCaptureRuntimeFailure(invocation, mcpErr, mcpErr)
		return executor.Result{}, mcpErr
	}

	scanReport, err := r.scanContent(callResult.Content)
	if err != nil {
		return executor.Result{}, err
	}

	if bizErr := detectBusinessError(callResult.Content); bizErr != "" {
		diag := transport.ExtractServerDiagnosticsFromMap(callResult.Content)
		logBusinessError(fl, "business_error", invocation, callResult.Content, diag)
		return executor.Result{}, apperrors.NewAPI(bizErr,
			apperrors.WithOperation("tools/call"),
			apperrors.WithReason("business_error"),
			apperrors.WithServerKey(invocation.CanonicalProduct),
			apperrors.WithHint("The API returned a business-level error. Check required parameters and values."),
			apperrors.WithServerDiag(diag),
		)
	}

	invocation.Implemented = true
	// Align with wukong's response envelope: stamp a top-level success=true on
	// map payloads that don't already carry a success flag. Business errors
	// (success=false) are intercepted above, so reaching here means the call
	// succeeded. Additive only — existing keys are never overwritten.
	if callResult.Content != nil {
		if _, has := callResult.Content["success"]; !has {
			callResult.Content["success"] = true
		}
	}
	response := map[string]any{
		"endpoint": transport.RedactURL(endpoint),
		"content":  callResult.Content,
	}
	if r.includeScanReport && scanReport.Scanned {
		response["safety"] = scanReport
	}
	return executor.Result{Invocation: invocation, Response: response}, nil
}

type logicalExecutionIDKey struct{}

type logicalProfileKey struct{}

func withLogicalProfile(ctx context.Context, profile string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, logicalProfileKey{}, strings.TrimSpace(profile))
}

func logicalProfile(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value, ok := ctx.Value(logicalProfileKey{}).(string)
	return strings.TrimSpace(value), ok
}

func logicalExecutionID(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value, ok := ctx.Value(logicalExecutionIDKey{}).(string)
	value = strings.TrimSpace(value)
	return value, ok && value != ""
}

// executeStdioInvocation dispatches a tool call through a local StdioClient
// subprocess instead of the HTTP transport. This is used for plugin stdio
// servers whose endpoints use the stdio:// scheme.
func (r *runtimeRunner) executeStdioInvocation(ctx context.Context, invocation executor.Invocation) (executor.Result, error) {
	if invocation.DryRun {
		return executor.Result{
			Invocation: invocation,
			Response: map[string]any{
				"dry_run":   true,
				"transport": "stdio",
				"request":   executor.ToolCallRequest(invocation.Tool, invocation.Params),
				"note":      "execution skipped by --dry-run",
			},
		}, nil
	}

	client, ok := LookupStdioClient(invocation.CanonicalProduct)
	if !ok {
		return executor.Result{}, apperrors.NewInternal(
			fmt.Sprintf("stdio client not found for %q", invocation.CanonicalProduct))
	}

	callCtx := ctx
	if r.globalFlags != nil && r.globalFlags.Timeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, time.Duration(r.globalFlags.Timeout)*time.Second)
		defer cancel()
	}
	if err := runnerStdioEnsureInitialized(client, callCtx); err != nil {
		return executor.Result{}, apperrors.NewAPI(
			fmt.Sprintf("stdio initialize failed: %v", err),
			apperrors.WithOperation("initialize"),
			apperrors.WithReason("stdio_initialize_error"),
		)
	}

	callResult, err := runnerStdioCallTool(client, callCtx, invocation.Tool, invocation.Params)
	if err != nil {
		return executor.Result{}, apperrors.NewAPI(
			fmt.Sprintf("stdio call failed: %v", err),
			apperrors.WithOperation("tools/call"),
			apperrors.WithReason("stdio_error"),
		)
	}

	if callResult.IsError {
		return executor.Result{}, apperrors.NewAPI(
			extractMCPErrorMessage(callResult),
			apperrors.WithOperation("tools/call"),
			apperrors.WithReason("mcp_tool_error"),
			apperrors.WithServerKey(invocation.CanonicalProduct),
		)
	}

	invocation.Implemented = true
	return executor.Result{
		Invocation: invocation,
		Response: map[string]any{
			"transport": "stdio",
			"content":   callResult.Content,
		},
	}, nil
}

func (r *runtimeRunner) resolveAuthToken(ctx context.Context) (AccessTokenSnapshot, error) {
	explicitToken := ""
	if r != nil && r.globalFlags != nil {
		explicitToken = r.globalFlags.Token
	}
	if token := strings.TrimSpace(explicitToken); token != "" {
		return AccessTokenSnapshot{AccessToken: token, Source: "explicit"}, nil
	}
	return getRuntimeTokenSnapshot(ctx)
}

func resolveRuntimeAuthToken(ctx context.Context, explicitToken string) (string, error) {
	if token := strings.TrimSpace(explicitToken); token != "" {
		return token, nil
	}
	snapshot, err := getRuntimeTokenSnapshot(ctx)
	if err != nil {
		return "", err
	}
	return snapshot.AccessToken, nil
}

func getRuntimeTokenSnapshot(ctx context.Context) (AccessTokenSnapshot, error) {
	loadStart := time.Now()
	defer func() { RecordTiming(ctx, "auth_keychain", time.Since(loadStart)) }()
	if profile, ok := logicalProfile(ctx); ok {
		return runtimeTokenManager.getForProfile(ctx, defaultConfigDir(), "", profile)
	}
	return runtimeTokenManager.Get(ctx, defaultConfigDir(), "")
}

// generateExecutionID returns a random 16-char hex string used to correlate
// all log entries (command_start, jsonrpc_request, command_end, etc.) belonging
// to a single command invocation.
func generateExecutionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ResetRuntimeTokenCache clears the cached token, forcing a reload on next access.
// This should be called after login/logout operations.
func ResetRuntimeTokenCache() {
	runtimeTokenManager.Invalidate()
	if invalidate := edition.Get().InvalidateAuthCaches; invalidate != nil {
		invalidate()
	}
}

func authResolutionError(err error) error {
	if err == nil {
		return nil
	}
	reason := "auth_load_failed"
	message := "无法读取登录态"
	hint := "使用 --verbose 查看认证阶段日志；修复本地凭证读取错误后重试"
	actions := []string{"dws auth status --verbose", "dws doctor --verbose"}
	if errors.Is(err, authpkg.ErrTokenDataNotFound) || errors.Is(err, os.ErrNotExist) || errors.Is(err, authpkg.ErrRefreshTokenExpired) {
		reason = "login_required"
		message = "登录态不存在或已失效"
		hint = "运行 'dws auth login' 完成登录后重试"
		actions = []string{"dws auth login"}
	} else if authpkg.ClassifyRefreshFailure(err) == authpkg.RefreshFailureTransient {
		reason = "auth_refresh_transient"
		message = "登录态刷新暂时失败"
		hint = "网络、限流或认证服务暂时不可用；稍后重试，原登录态已保留"
	} else if authpkg.ClassifyRefreshFailure(err) == authpkg.RefreshFailureTerminal {
		reason = "login_required"
		message = "登录态已失效"
		hint = "运行 'dws auth login' 完成登录后重试"
		actions = []string{"dws auth login"}
	} else {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) || errors.Is(err, authpkg.ErrTokenDecryption) {
			reason = "auth_store_failed"
			message = "本地登录态存储不可用"
			hint = "检查 DWS_CONFIG_DIR、文件锁和凭证加密存储权限后重试"
		}
	}
	var endpointErr *authpkg.OAuthEndpointError
	if errors.As(err, &endpointErr); endpointErr != nil {
		if code := authpkg.SafeOAuthDiagnosticCode(endpointErr.Code); code != "" {
			message += "（OAuth code: " + code + "）"
		}
	}
	return apperrors.NewAuth(
		message,
		apperrors.WithReason(reason),
		apperrors.WithHint(hint),
		apperrors.WithActions(actions...),
		apperrors.WithCause(authpkg.NewDiagnosticStageError("token_resolution", err)),
	)
}

func newRuntimeContentScanner() safety.Scanner {
	if !runtimeFlagEnabled(os.Getenv(runtimeContentScanEnv), true) {
		return nil
	}
	return safety.NewContentScanner()
}

func (r *runtimeRunner) scanContent(content map[string]any) (safety.Report, error) {
	if r == nil || r.scanner == nil {
		return safety.Report{Scanned: false}, nil
	}
	report := r.scanner.ScanPayload(content)
	if r.enforceContentScan && len(report.Findings) > 0 {
		return report, apperrors.NewValidation("runtime response blocked by content safety scan")
	}
	return report, nil
}

func runtimeFlagEnabled(raw string, defaultValue bool) bool {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return defaultValue
	}
	switch trimmed {
	case "0", "false", "no", "n", "off":
		return false
	default:
		return true
	}
}

func isAuthError(err error) bool {
	var appErr *apperrors.Error
	if errors.As(err, &appErr) {
		return appErr.Category == apperrors.CategoryAuth
	}
	return false
}

func productEndpointOverride(productID string) (string, bool) {
	key := "DINGTALK_" + strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(productID), "-", "_")) + "_MCP_URL"
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", false
	}
	return value, true
}

// resolveIdentityHeaders loads or creates agent identity and returns HTTP
// headers to inject into MCP requests. Best-effort: returns nil on failure.
func resolveIdentityHeaders() map[string]string {
	return resolveIdentityHeadersForProfile(strings.TrimSpace(authpkg.RuntimeProfile()))
}

func resolveIdentityHeadersForProfile(profile string) map[string]string {
	id := authpkg.EnsureExists(defaultConfigDir())
	headers := id.Headers()

	// Inject environment variable based headers for MCP gateway tracking.
	// DINGTALK_AGENT, if set by the caller, is forwarded verbatim as the
	// x-dingtalk-agent header. It does NOT influence claw-type (which the
	// open-source edition pins to edition.DefaultOSSClawType via the
	// MergeHeaders hook below) and it does NOT influence the host-owned
	// PAT decision (driven solely by DINGTALK_DWS_AGENTCODE).
	sessionID := os.Getenv(envDingtalkSessionID)
	if sessionID == "" {
		sessionID = os.Getenv(envDWSSessionID)
	}
	if sessionID == "" {
		sessionID = os.Getenv(envRewindSessionID)
	}
	// Resolve the agent_code (accuracy-first; unknown hosts stay empty) and the
	// per-(machine × agent_code) instance id when a code is known. Synthetic
	// fallbacks must not be sent because PAT authorization checks use the same
	// header as their grant key.
	//
	// Backward-compat by design (additive, not breaking):
	//   - x-dws-agent-id keeps its v1 meaning = machine-level install UUID
	//     (set by id.Headers() above), so old/new clients stay comparable.
	//   - x-dws-agent-instance-id is NEW: the per-(machine × agent_code) id,
	//     sent only when x-dingtalk-dws-agent-code is non-empty.
	// Note: x-dws-channel (DWS_CHANNEL) is a separate axis, untouched.
	agentCode, agentCodeSig := authpkg.DetectAgentCode()
	if agentInstanceID := id.ResolveAgentID(defaultConfigDir(), agentCode, agentCodeSig); agentInstanceID != "" {
		headers["x-dws-agent-instance-id"] = agentInstanceID
	}

	// Emit the CLI version on the wire so the gateway can segment old vs new
	// clients (and scope agent_code coverage / adoption). The header constant
	// existed but was never set; wire it here.
	if version != "" {
		headers[transport.HeaderVersion] = version
	}
	envHeaders := map[string]string{
		"x-dingtalk-agent":          os.Getenv(envDingtalkAgent),
		"x-dingtalk-dws-agent-code": agentCode,
		"x-dingtalk-trace-id":       os.Getenv(envDingtalkTraceID),
		"x-dingtalk-session-id":     sessionID,
		"x-dingtalk-message-id":     os.Getenv(envDingtalkMessageID),
	}
	for k, v := range envHeaders {
		if v != "" {
			headers[k] = v
		}
	}

	// Inject third-party channel headers. DWS_CHANNEL is forwarded as the
	// upstream channelCode.
	if v := os.Getenv(envDWSChannel); v != "" {
		headers["x-dws-channel"] = v
	}

	if fn := edition.Get().MergeHeadersForProfile; fn != nil {
		headers = fn(headers, strings.TrimSpace(profile))
	} else if fn := edition.Get().MergeHeaders; fn != nil {
		headers = fn(headers)
	}
	if fn := edition.Get().EnterpriseCredentialHeaders; fn != nil {
		headers = fn(headers)
	}
	return headers
}

// detectBusinessError checks the MCP response content for DingTalk business
// errors (success=false + errorCode/errorMsg) that are not flagged at the MCP
// protocol level. Returns the error message, or "" if the response is OK.
func detectBusinessError(content map[string]any) string {
	return detectBusinessErrorAtDepth(content, 0)
}

func detectBusinessErrorAtDepth(content map[string]any, depth int) string {
	if content == nil || depth > 8 {
		return ""
	}
	success, ok := content["success"]
	if !ok {
		return detectNestedBusinessError(content, depth)
	}
	b, ok := success.(bool)
	if !ok || b {
		return detectNestedBusinessError(content, depth)
	}
	if nested := detectNestedBusinessError(content, depth); nested != "" {
		return nested
	}
	if msg, ok := content["errorMsg"].(string); ok && strings.TrimSpace(msg) != "" {
		return strings.TrimSpace(msg)
	}
	if code, ok := content["errorCode"].(string); ok && strings.TrimSpace(code) != "" {
		return "business error: code " + strings.TrimSpace(code)
	}
	return "business error: success=false"
}

func detectNestedBusinessError(content map[string]any, depth int) string {
	for _, key := range []string{"content", "result", "data"} {
		switch child := content[key].(type) {
		case map[string]any:
			if msg := detectBusinessErrorAtDepth(child, depth+1); msg != "" {
				return msg
			}
		case []any:
			for _, item := range child {
				childMap, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if msg := detectBusinessErrorAtDepth(childMap, depth+1); msg != "" {
					return msg
				}
			}
		}
	}
	return ""
}

// extractMCPErrorMessage builds an error message from a ToolCallResult with
// isError=true. It extracts text from content blocks when available.
func extractMCPErrorMessage(result transport.ToolCallResult) string {
	// Try text from content blocks first.
	for _, block := range result.Blocks {
		text := strings.TrimSpace(block.Text)
		if text != "" {
			return text
		}
	}
	// Try stringified content map.
	if msg, ok := result.Content["message"].(string); ok && strings.TrimSpace(msg) != "" {
		return strings.TrimSpace(msg)
	}
	if msg, ok := result.Content["error"].(string); ok && strings.TrimSpace(msg) != "" {
		return strings.TrimSpace(msg)
	}
	return "MCP tool returned an error response"
}

// logBusinessError logs MCP tool errors and business errors to the file logger
// so they can be diagnosed offline. These errors arrive as HTTP 200 responses
// and would otherwise not be captured by transport-level logging.
func logBusinessError(logger *slog.Logger, reason string, inv executor.Invocation, content map[string]any, diag apperrors.ServerDiagnostics) {
	if logger == nil {
		return
	}
	attrs := []any{
		"product", inv.CanonicalProduct,
		"tool", inv.Tool,
		"reason", reason,
	}
	if diag.TraceID != "" {
		attrs = append(attrs, "trace_id", diag.TraceID)
	}
	if diag.ServerErrorCode != "" {
		// Arbitrary upstream codes are not trusted diagnostic text; some
		// gateways echo request identifiers in this field.
		attrs = append(attrs, "server_error_code_present", true)
	}
	// Never log free-form upstream detail or the response envelope. Error
	// messages frequently echo request arguments, identities, and credentials.
	// Structured category/reason/code/trace are sufficient for correlation.
	attrs = append(attrs, "response_fields", len(content))
	logger.Warn("business_error", attrs...)
}

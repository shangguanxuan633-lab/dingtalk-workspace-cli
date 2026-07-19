package app

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/audit"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/logging"
)

// TestAuditIdentityReresolvesOnProfileSwitch guards the reviewer's finding that a
// long-running process (e.g. serve mode) must attribute events to the ACTIVE
// runtime profile rather than reusing a process-global first Actor. It also
// asserts the per-profile cache avoids redundant token loads within one profile.
func TestAuditIdentityReresolvesOnProfileSwitch(t *testing.T) {
	prevLoader := loadTokenForProfile
	prevProfile := auth.RuntimeProfile()
	t.Cleanup(func() {
		loadTokenForProfile = prevLoader
		auth.SetRuntimeProfile(prevProfile)
		resetAuditIdentityCache()
	})
	resetAuditIdentityCache()

	var mu sync.Mutex
	calls := map[string]int{}
	loadTokenForProfile = func(_ /*configDir*/, profile string) (*auth.TokenData, error) {
		mu.Lock()
		calls[profile]++
		mu.Unlock()
		switch profile {
		case "orgA":
			return &auth.TokenData{UserID: "ua", UserName: "Alice", CorpID: "ca", CorpName: "CorpA"}, nil
		case "orgB":
			return &auth.TokenData{UserID: "ub", UserName: "Bob", CorpID: "cb", CorpName: "CorpB"}, nil
		default:
			return nil, nil
		}
	}

	auth.SetRuntimeProfile("orgA")
	if actor, _ := auditIdentity(); actor.UserID != "ua" || actor.CorpName != "CorpA" {
		t.Fatalf("orgA: got %+v, want Alice/CorpA", actor)
	}
	// Second call under the same profile must hit the cache (no extra load).
	if actor, _ := auditIdentity(); actor.UserID != "ua" {
		t.Fatalf("orgA cached: got %+v", actor)
	}

	auth.SetRuntimeProfile("orgB")
	if actor, _ := auditIdentity(); actor.UserID != "ub" || actor.CorpName != "CorpB" {
		t.Fatalf("orgB: got %+v, want Bob/CorpB (stale Actor reused?)", actor)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls["orgA"] != 1 {
		t.Fatalf("orgA loaded %d times, want 1 (cache miss?)", calls["orgA"])
	}
	if calls["orgB"] != 1 {
		t.Fatalf("orgB loaded %d times, want 1", calls["orgB"])
	}
}

func resetAuditIdentityCache() {
	auditIDMu.Lock()
	defer auditIDMu.Unlock()
	cachedActor = audit.Actor{}
	cachedAgentID = ""
	cachedProfile = ""
	identityLoaded = false
}

func TestAuditIdentityTransientLoadFailureIsSafeAndNotCached(t *testing.T) {
	prevLoader := loadTokenForProfile
	prevProfile := auth.RuntimeProfile()
	configDir := t.TempDir()
	t.Setenv("DWS_CONFIG_DIR", configDir)
	logger := logging.Setup(configDir)

	fileLoggerMu.Lock()
	prevFileLogger := fileLogger
	fileLogger = logger
	fileLoggerMu.Unlock()
	t.Cleanup(func() {
		loadTokenForProfile = prevLoader
		auth.SetRuntimeProfile(prevProfile)
		resetAuditIdentityCache()
		fileLoggerMu.Lock()
		fileLogger = prevFileLogger
		fileLoggerMu.Unlock()
		_ = logger.Close()
	})

	rawProfile := "raw-profile-secret"
	rawCause := "raw-access-token raw-uid raw-corp"
	auth.SetRuntimeProfile(rawProfile)
	resetAuditIdentityCache()
	calls := 0
	loadTokenForProfile = func(string, string) (*auth.TokenData, error) {
		calls++
		if calls == 1 {
			return nil, errors.New(rawCause)
		}
		return &auth.TokenData{UserID: "user-after-retry", CorpID: "corp-after-retry"}, nil
	}

	if actor, _ := auditIdentity(); actor.UserID != "" || actor.CorpID != "" {
		t.Fatalf("failed load actor = %#v, want empty", actor)
	}
	if actor, _ := auditIdentity(); actor.UserID != "user-after-retry" || actor.CorpID != "corp-after-retry" {
		t.Fatalf("retried actor = %#v", actor)
	}
	if calls != 2 {
		t.Fatalf("credential metadata loads = %d, want 2", calls)
	}

	logBytes, err := os.ReadFile(filepath.Join(configDir, "logs", "dws.log"))
	if err != nil {
		t.Fatalf("read audit diagnostics: %v", err)
	}
	logText := string(logBytes)
	for _, want := range []string{"audit_actor_load", "error_type", "cause_type", "profile_selected"} {
		if !strings.Contains(logText, want) {
			t.Fatalf("audit diagnostics missing %q: %s", want, logText)
		}
	}
	for _, secret := range []string{rawProfile, rawCause, "raw-access-token", "raw-uid", "raw-corp"} {
		if strings.Contains(logText, secret) {
			t.Fatalf("audit diagnostics leaked %q: %s", secret, logText)
		}
	}
}

func TestClassifyAuditErrorDoesNotPersistRawUnknownCause(t *testing.T) {
	raw := errors.New("raw-profile raw-uid raw-corp raw-access-token")
	category, reason := classifyAuditError(raw)
	if category != "unknown" || reason != "unknown" {
		t.Fatalf("classifyAuditError() = %q, %q", category, reason)
	}
}

// TestCloseAuditSinkDrainsOnErrorPath guards the reviewer's V5 finding: when a
// command's RunE returns an error, Cobra skips PersistentPostRunE, so the audit
// drain must instead happen through the unconditional defer in Execute that calls
// CloseAuditSink. This test wires a real forwarder-backed sink into the shared
// slot and asserts CloseAuditSink flushes the queued forward exactly as the
// error-path defer would, and that a second call is a harmless no-op.
func TestCloseAuditSinkDrainsOnErrorPath(t *testing.T) {
	var delivered int64
	var releaseOnce sync.Once
	release := make(chan struct{})
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // hold the request until the drain awaits it
		atomic.AddInt64(&delivered, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer releaseFn() // LIFO: unblock any in-flight handler before srv.Close()

	writer, err := audit.NewDateRotatingWriter(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	fwd := audit.NewHTTPForwarder(srv.URL, "", audit.RedactNone, nil)
	sink := audit.NewFileSink(writer, audit.NewChain(""), fwd)

	prevSink := sharedAuditSink
	t.Cleanup(func() {
		sharedAuditSink = prevSink
		auditCloseOnce = sync.Once{}
	})
	sharedAuditSink = sink
	auditCloseOnce = sync.Once{}

	if err := sink.Emit(&audit.Event{Timestamp: time.Unix(0, 0), Product: "calendar", Command: "event_list", Result: "error"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if got := atomic.LoadInt64(&delivered); got != 0 {
		t.Fatalf("forward delivered before drain: %d", got)
	}

	// Let the held request complete, then drain via the same entry point the
	// error-path defer uses. CloseAuditSink blocks until the forward goroutine
	// observes the HTTP response, so the counter is settled when it returns.
	releaseFn()
	CloseAuditSink()

	if got := atomic.LoadInt64(&delivered); got != 1 {
		t.Fatalf("forward not drained on error path: delivered=%d, want 1", got)
	}

	// Idempotent: the success-path PersistentPostRunE and the defer both call it.
	CloseAuditSink()
}

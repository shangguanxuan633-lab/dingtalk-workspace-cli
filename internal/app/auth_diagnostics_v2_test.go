package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

func TestAuthResolutionCauseIsSafeForJSONAndVerboseButUnwraps(t *testing.T) {
	secret := "token-secret-for-uid-4496576595"
	wantErr := errors.New(secret)
	err := authResolutionError(wantErr)
	if !errors.Is(err, wantErr) {
		t.Fatalf("errors.Is() = false: %v", err)
	}
	var jsonOut, verboseOut bytes.Buffer
	if printErr := apperrors.PrintJSON(&jsonOut, err); printErr != nil {
		t.Fatal(printErr)
	}
	if printErr := apperrors.PrintHumanAt(&verboseOut, err, apperrors.VerbosityVerbose); printErr != nil {
		t.Fatal(printErr)
	}
	for name, output := range map[string]string{"json": jsonOut.String(), "verbose": verboseOut.String()} {
		if strings.Contains(output, secret) || !strings.Contains(output, "token_resolution") {
			t.Fatalf("%s output is unsafe or missing stage: %s", name, output)
		}
	}
}

func TestAuthStatusReasonsDistinguishMissingAndFullyExpired(t *testing.T) {
	for _, tc := range []struct {
		name string
		load func(string) ([]byte, error)
		want string
	}{
		{"missing", func(string) ([]byte, error) { return nil, authpkg.ErrTokenDataNotFound }, "not_authenticated"},
		{"expired", func(string) ([]byte, error) {
			raw, _ := json.Marshal(&authpkg.TokenData{
				AccessToken: "expired-access", RefreshToken: "expired-refresh",
				ExpiresAt: time.Now().Add(-time.Hour), RefreshExpAt: time.Now().Add(-time.Hour),
			})
			return raw, nil
		}, "login_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := edition.Get()
			edition.Override(&edition.Hooks{
				SaveToken: func(string, []byte) error { return nil }, LoadToken: tc.load, DeleteToken: func(string) error { return nil },
			})
			t.Cleanup(func() { edition.Override(previous) })
			t.Setenv("DWS_CONFIG_DIR", t.TempDir())
			cmd := NewRootCommand()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{"--format", "json", "auth", "status"})
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			var response authStatusResponse
			if err := json.Unmarshal(out.Bytes(), &response); err != nil {
				t.Fatalf("unmarshal %q: %v", out.String(), err)
			}
			if response.Authenticated || response.Reason != tc.want {
				t.Fatalf("response = %+v, want reason %q", response, tc.want)
			}
		})
	}
}

func TestOptionalContactEnrichmentFailureWarnsSafely(t *testing.T) {
	secret := "token-secret-for-uid-4496576595"
	caller := &authCoverageCaller{err: errors.New(secret)}
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })
	err := enrichAuthLoginProfileFromContact(context.Background(), t.TempDir(), caller, &authpkg.TokenData{
		CorpID: "corp", UserID: "known-user", AccessToken: "secret-access",
	})
	if err != nil {
		t.Fatalf("optional enrichment error = %v", err)
	}
	got := logs.String()
	if !strings.Contains(got, "auth.login.identity.lookup_failed") || !strings.Contains(got, "contact_identity_lookup") ||
		strings.Contains(got, secret) || strings.Contains(got, "known-user") || strings.Contains(got, "secret-access") {
		t.Fatalf("unsafe or missing enrichment warning: %s", got)
	}
}

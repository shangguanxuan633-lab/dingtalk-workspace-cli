package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestSkillDownloadInfoManagedSnapshotRefreshesOnLogical40014Once(t *testing.T) {
	oldFetch := skillFetchDownloadInfo
	oldRefresh := skillRefreshRejectedSnapshot
	t.Cleanup(func() {
		skillFetchDownloadInfo = oldFetch
		skillRefreshRejectedSnapshot = oldRefresh
	})
	var tokens []string
	skillFetchDownloadInfo = func(_ context.Context, token, _ string) (*downloadSkillResponse, error) {
		tokens = append(tokens, token)
		if len(tokens) == 1 {
			return &downloadSkillResponse{Success: false, ErrorCode: "40014", ErrorMsg: "token-secret-for-uid-4496576595"}, nil
		}
		return &downloadSkillResponse{Success: true, Result: &downloadSkillResult{DownloadURL: "https://example.test/file"}}, nil
	}
	refreshes := 0
	skillRefreshRejectedSnapshot = func(context.Context, string, AccessTokenSnapshot) (AccessTokenSnapshot, error) {
		refreshes++
		return AccessTokenSnapshot{AccessToken: "new", Source: "oauth", profilePinned: true}, nil
	}
	snapshot := AccessTokenSnapshot{AccessToken: "old", Source: "oauth", profile: "corp:user", profilePinned: true}
	result, err := fetchSkillDownloadInfoWithSnapshot(context.Background(), snapshot, "skill")
	if err != nil || result == nil || !result.Success || refreshes != 1 || strings.Join(tokens, ",") != "old,new" {
		t.Fatalf("result=%#v err=%v refreshes=%d tokens=%v", result, err, refreshes, tokens)
	}
}

func TestSkillDownloadManagedSnapshotRefreshesOnHTTP401Once(t *testing.T) {
	oldDownload := skillDownloadToTmp
	oldRefresh := skillRefreshRejectedSnapshot
	t.Cleanup(func() {
		skillDownloadToTmp = oldDownload
		skillRefreshRejectedSnapshot = oldRefresh
	})
	var tokens []string
	skillDownloadToTmp = func(_ context.Context, _, token string) (string, error) {
		tokens = append(tokens, token)
		if len(tokens) == 1 {
			return "", skillAuthError()
		}
		return "/tmp/skill", nil
	}
	refreshes := 0
	skillRefreshRejectedSnapshot = func(context.Context, string, AccessTokenSnapshot) (AccessTokenSnapshot, error) {
		refreshes++
		return AccessTokenSnapshot{AccessToken: "new", Source: "oauth", profilePinned: true}, nil
	}
	snapshot := AccessTokenSnapshot{AccessToken: "old", Source: "oauth", profile: "corp:user", profilePinned: true}
	dir, err := downloadSkillToTmpWithSnapshot(context.Background(), "https://example.test/skill", snapshot)
	if err != nil || dir != "/tmp/skill" || refreshes != 1 || strings.Join(tokens, ",") != "old,new" {
		t.Fatalf("dir=%q err=%v refreshes=%d tokens=%v", dir, err, refreshes, tokens)
	}
}

func TestSkillPATAndExplicitRejectionsDoNotRefresh(t *testing.T) {
	oldFetch := skillFetchDownloadInfo
	oldRefresh := skillRefreshRejectedSnapshot
	t.Cleanup(func() {
		skillFetchDownloadInfo = oldFetch
		skillRefreshRejectedSnapshot = oldRefresh
	})
	skillFetchDownloadInfo = func(context.Context, string, string) (*downloadSkillResponse, error) {
		return &downloadSkillResponse{Success: false, ErrorCode: "PAT_SCOPE_AUTH_REQUIRED"}, nil
	}
	refreshes := 0
	skillRefreshRejectedSnapshot = func(context.Context, string, AccessTokenSnapshot) (AccessTokenSnapshot, error) {
		refreshes++
		return AccessTokenSnapshot{}, errors.New("unexpected")
	}
	for _, snapshot := range []AccessTokenSnapshot{
		{AccessToken: "oauth", Source: "oauth", profilePinned: true},
		{AccessToken: "explicit", Source: "explicit"},
	} {
		result, err := fetchSkillDownloadInfoWithSnapshot(context.Background(), snapshot, "skill")
		if err != nil || result == nil || result.ErrorCode != "PAT_SCOPE_AUTH_REQUIRED" {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	}
	if refreshes != 0 {
		t.Fatalf("refreshes=%d", refreshes)
	}
}

func TestSkillBusinessFailureDoesNotExposeServerMessageOrUnknownCode(t *testing.T) {
	oldLoad := skillLoadTokenSnapshot
	oldTarget := skillResolveTargetPath
	oldFetch := skillFetchDownloadInfo
	t.Cleanup(func() {
		skillLoadTokenSnapshot = oldLoad
		skillResolveTargetPath = oldTarget
		skillFetchDownloadInfo = oldFetch
	})
	secret := "token-secret-for-uid-4496576595"
	skillLoadTokenSnapshot = func(context.Context) (AccessTokenSnapshot, error) {
		return AccessTokenSnapshot{AccessToken: "token", Source: "explicit"}, nil
	}
	skillResolveTargetPath = func(string) (string, error) { return t.TempDir(), nil }
	skillFetchDownloadInfo = func(context.Context, string, string) (*downloadSkillResponse, error) {
		return &downloadSkillResponse{Success: false, ErrorCode: secret, ErrorMsg: secret}, nil
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := runSkillAdd(cmd, []string{"skill", "."})
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "other") {
		t.Fatalf("runSkillAdd() error = %v", err)
	}
}

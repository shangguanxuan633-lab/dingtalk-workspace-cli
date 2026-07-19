package runtimetoken

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

type profileStore struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func (s *profileStore) hooks() *edition.Hooks {
	s.blobs = make(map[string][]byte)
	return &edition.Hooks{TokenStoreV2: &edition.TokenStoreV2Hooks{
		Save: func(_, profile string, blob []byte) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.blobs[profile] = append([]byte(nil), blob...)
			return nil
		},
		Load: func(_, profile string) ([]byte, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			blob, ok := s.blobs[profile]
			if !ok {
				return nil, authpkg.ErrTokenDataNotFound
			}
			return append([]byte(nil), blob...), nil
		},
		Delete: func(_, profile string) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			delete(s.blobs, profile)
			return nil
		},
	}}
}

func runtimeToken(corpID, userID, access string) *authpkg.TokenData {
	return &authpkg.TokenData{
		AccessToken:  access,
		RefreshToken: "refresh-" + access,
		ExpiresAt:    time.Now().Add(time.Hour),
		RefreshExpAt: time.Now().Add(24 * time.Hour),
		ClientID:     "client",
		CorpID:       corpID,
		UserID:       userID,
	}
}

func TestRefreshRejectedUsesOpaqueOriginalProfileAndReusesConcurrentRotation(t *testing.T) {
	previousHooks := edition.Get()
	previousProfile := authpkg.RuntimeProfile()
	store := &profileStore{}
	edition.Override(store.hooks())
	t.Cleanup(func() {
		edition.Override(previousHooks)
		authpkg.SetRuntimeProfile(previousProfile)
	})
	configDir := t.TempDir()

	authpkg.SetRuntimeProfile("corp-a")
	if err := authpkg.SaveTokenData(configDir, runtimeToken("corp-a", "user-a", "token-a-old")); err != nil {
		t.Fatal(err)
	}
	authpkg.SetRuntimeProfile("corp-b")
	if err := authpkg.SaveTokenData(configDir, runtimeToken("corp-b", "user-b", "token-b")); err != nil {
		t.Fatal(err)
	}
	authpkg.SetRuntimeProfile("corp-a:user-a")
	rejected, err := ResolveSnapshot(context.Background(), configDir, "")
	if err != nil || rejected.AccessToken != "token-a-old" {
		t.Fatalf("rejected snapshot = %#v, %v", rejected, err)
	}
	if rejected.ProfileFingerprint == "" {
		t.Fatal("default-profile snapshot did not carry an opaque exact-profile lease")
	}

	// Simulate another process winning the refresh CAS before this runtime
	// reacts to the server rejection.
	if err := authpkg.SaveTokenData(configDir, runtimeToken("corp-a", "user-a", "token-a-new")); err != nil {
		t.Fatal(err)
	}
	authpkg.SetRuntimeProfile("corp-b:user-b")
	refreshed, err := RefreshRejected(context.Background(), configDir, rejected)
	if err != nil || refreshed.AccessToken != "token-a-new" {
		t.Fatalf("opaque RefreshRejected = %#v, %v", refreshed, err)
	}
	if refreshed.ProfileFingerprint != rejected.ProfileFingerprint {
		t.Fatalf("profile fingerprint changed: %q -> %q", rejected.ProfileFingerprint, refreshed.ProfileFingerprint)
	}
	storedB, err := authpkg.LoadTokenDataForProfile(configDir, "corp-b:user-b")
	if err != nil || storedB.AccessToken != "token-b" {
		t.Fatalf("profile B after profile-A recovery = %#v, %v", storedB, err)
	}
}

func TestRefreshRejectedRejectsSyntheticSnapshot(t *testing.T) {
	_, err := RefreshRejected(context.Background(), t.TempDir(), TokenSnapshot{AccessToken: "synthetic"})
	if err == nil || errors.Is(err, authpkg.ErrTokenDataNotFound) {
		t.Fatalf("synthetic snapshot error = %v", err)
	}
}

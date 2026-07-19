package auth

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

type memoryEditionTokenStore struct {
	mu   sync.Mutex
	blob []byte
}

func (s *memoryEditionTokenStore) hooks() *edition.Hooks {
	return &edition.Hooks{
		SaveToken: func(_ string, data []byte) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.blob = append([]byte(nil), data...)
			return nil
		},
		LoadToken: func(string) ([]byte, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if len(s.blob) == 0 {
				return nil, ErrTokenDataNotFound
			}
			return append([]byte(nil), s.blob...), nil
		},
		DeleteToken: func(string) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.blob = nil
			return nil
		},
	}
}

func installMemoryEditionTokenStore(t *testing.T) (*memoryEditionTokenStore, string) {
	t.Helper()
	previous := edition.Get()
	store := &memoryEditionTokenStore{}
	edition.Override(store.hooks())
	t.Cleanup(func() { edition.Override(previous) })
	return store, t.TempDir()
}

func rejectedTokenData(access string) *TokenData {
	return &TokenData{
		AccessToken:  access,
		RefreshToken: "refresh-" + access,
		ExpiresAt:    time.Now().Add(time.Hour),
		RefreshExpAt: time.Now().Add(24 * time.Hour),
		ClientID:     "client",
	}
}

func TestForceRefreshRejectedTokenConcurrentCallersExchangeOnceV2(t *testing.T) {
	_, configDir := installMemoryEditionTokenStore(t)
	old := rejectedTokenData("old-access")
	if err := SaveTokenData(configDir, old); err != nil {
		t.Fatalf("SaveTokenData() error = %v", err)
	}

	originalRefresh := oauthRefreshToken
	t.Cleanup(func() { oauthRefreshToken = originalRefresh })
	var exchanges atomic.Int32
	oauthRefreshToken = func(p *OAuthProvider, _ context.Context, current *TokenData) (*TokenData, error) {
		exchanges.Add(1)
		time.Sleep(10 * time.Millisecond)
		updated := rejectedTokenData("new-access")
		updated.RefreshToken = "new-refresh"
		if err := saveTokenDataLocked(p.configDir, updated); err != nil {
			return nil, err
		}
		return updated, nil
	}

	provider := NewOAuthProvider(configDir, nil)
	const callers = 16
	start := make(chan struct{})
	results := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			token, err := provider.ForceRefreshRejectedToken(context.Background(), "old-access", old.Generation)
			results <- token
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("ForceRefreshRejectedToken() error = %v", err)
		}
	}
	for token := range results {
		if token != "new-access" {
			t.Fatalf("ForceRefreshRejectedToken() token = %q, want new-access", token)
		}
	}
	if got := exchanges.Load(); got != 1 {
		t.Fatalf("refresh exchanges = %d, want 1", got)
	}
}

func TestDeleteTokenDataIfAccessTokenMatchesUsesGenerationAndIsIdempotent(t *testing.T) {
	_, configDir := installMemoryEditionTokenStore(t)
	first := rejectedTokenData("same-access")
	if err := SaveTokenData(configDir, first); err != nil {
		t.Fatal(err)
	}
	firstGeneration := first.Generation
	second := rejectedTokenData("same-access")
	if err := SaveTokenData(configDir, second); err != nil {
		t.Fatal(err)
	}
	if second.Generation <= firstGeneration {
		t.Fatalf("generation did not increase: first=%d second=%d", firstGeneration, second.Generation)
	}

	deleted, err := DeleteTokenDataIfAccessTokenMatches(context.Background(), configDir, "same-access", firstGeneration)
	if err != nil || deleted {
		t.Fatalf("stale generation delete = (%v, %v), want (false, nil)", deleted, err)
	}
	stored, err := LoadTokenData(configDir)
	if err != nil || stored.Generation != second.Generation {
		t.Fatalf("credential after stale CAS = %#v, %v", stored, err)
	}

	deleted, err = DeleteTokenDataIfAccessTokenMatches(context.Background(), configDir, "same-access", second.Generation)
	if err != nil || !deleted {
		t.Fatalf("matching generation delete = (%v, %v), want (true, nil)", deleted, err)
	}
	deleted, err = DeleteTokenDataIfAccessTokenMatches(context.Background(), configDir, "same-access", second.Generation)
	if err != nil || deleted {
		t.Fatalf("idempotent delete = (%v, %v), want (false, nil)", deleted, err)
	}
}

func TestOAuthProviderTerminalRefreshCompareDeletesButTransientPreserves(t *testing.T) {
	originalLoad := oauthLoadToken
	originalLoadLocked := oauthLoadTokenLocked
	originalAcquire := oauthAcquireLock
	originalRefresh := oauthRefreshToken
	originalDelete := oauthDeleteRejected
	t.Cleanup(func() {
		oauthLoadToken = originalLoad
		oauthLoadTokenLocked = originalLoadLocked
		oauthAcquireLock = originalAcquire
		oauthRefreshToken = originalRefresh
		oauthDeleteRejected = originalDelete
	})

	data := rejectedTokenData("expired-access")
	data.ExpiresAt = time.Now().Add(-time.Hour)
	data.Generation = 41
	oauthLoadToken = func(string) (*TokenData, error) { copy := *data; return &copy, nil }
	oauthLoadTokenLocked = func(string, string) (*TokenData, error) { copy := *data; return &copy, nil }
	oauthAcquireLock = func(context.Context, string) (*DualLock, error) { return &DualLock{}, nil }

	var deletes atomic.Int32
	oauthDeleteRejected = func(_ context.Context, _ string, token string, generation ...uint64) (bool, error) {
		deletes.Add(1)
		if token != data.AccessToken || len(generation) != 1 || generation[0] != data.Generation {
			t.Fatalf("CAS args = (%q, %v)", token, generation)
		}
		return true, nil
	}
	provider := NewOAuthProvider(t.TempDir(), nil)

	oauthRefreshToken = func(*OAuthProvider, context.Context, *TokenData) (*TokenData, error) {
		return nil, &OAuthEndpointError{StatusCode: 400, Code: "invalid_grant"}
	}
	if _, err := provider.GetTokenSnapshot(context.Background()); err == nil || ClassifyRefreshFailure(err) != RefreshFailureTerminal {
		t.Fatalf("terminal refresh error = %v", err)
	}
	if got := deletes.Load(); got != 1 {
		t.Fatalf("terminal deletes = %d, want 1", got)
	}

	oauthRefreshToken = func(*OAuthProvider, context.Context, *TokenData) (*TokenData, error) {
		return nil, context.DeadlineExceeded
	}
	if _, err := provider.GetTokenSnapshot(context.Background()); err == nil || ClassifyRefreshFailure(err) != RefreshFailureTransient {
		t.Fatalf("transient refresh error = %v", err)
	}
	if got := deletes.Load(); got != 1 {
		t.Fatalf("transient refresh changed delete count to %d", got)
	}
}

func TestMemoryEditionStoreBlobCarriesGeneration(t *testing.T) {
	store, configDir := installMemoryEditionTokenStore(t)
	data := rejectedTokenData("access")
	if err := SaveTokenData(configDir, data); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	blob := append([]byte(nil), store.blob...)
	store.mu.Unlock()
	var persisted TokenData
	if err := json.Unmarshal(blob, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Generation == 0 || persisted.Generation != data.Generation {
		t.Fatalf("persisted generation = %d, caller generation = %d", persisted.Generation, data.Generation)
	}
	if persisted.UpdatedAt == "" || persisted.UpdatedAt != data.UpdatedAt {
		t.Fatalf("persisted updatedAt = %q, caller updatedAt = %q", persisted.UpdatedAt, data.UpdatedAt)
	}
	if _, err := time.Parse(time.RFC3339Nano, data.UpdatedAt); err != nil {
		t.Fatalf("updatedAt is not RFC3339Nano: %q: %v", data.UpdatedAt, err)
	}
}

func TestForceRefreshPreflightFailureMakesZeroOAuthCalls(t *testing.T) {
	store, configDir := installMemoryEditionTokenStore(t)
	data := rejectedTokenData("old-access")
	if err := SaveTokenData(configDir, data); err != nil {
		t.Fatal(err)
	}
	preflightErr := errors.New("host key unavailable")
	hooks := store.hooks()
	hooks.PreflightTokenStore = func(gotConfigDir string) error {
		if gotConfigDir != configDir {
			t.Fatalf("preflight configDir = %q, want %q", gotConfigDir, configDir)
		}
		return preflightErr
	}
	edition.Override(hooks)

	originalRefresh := oauthRefreshToken
	var oauthCalls atomic.Int32
	oauthRefreshToken = func(*OAuthProvider, context.Context, *TokenData) (*TokenData, error) {
		oauthCalls.Add(1)
		return nil, errors.New("must not be called")
	}
	t.Cleanup(func() { oauthRefreshToken = originalRefresh })

	_, err := NewOAuthProvider(configDir, nil).ForceRefreshRejectedToken(context.Background(), data.AccessToken, data.Generation)
	if !errors.Is(err, preflightErr) {
		t.Fatalf("ForceRefreshRejectedToken() error = %v, want preflight cause", err)
	}
	if got := oauthCalls.Load(); got != 0 {
		t.Fatalf("OAuth refresh calls = %d, want 0", got)
	}
}

package bus

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
)

func TestSafeSourceExitAttrsDoNotExposeCauseText(t *testing.T) {
	secret := "ticket=token-secret-uid-4496576595"
	wantErr := errors.New(secret)
	err := authpkg.NewDiagnosticStageError("personal_ticket_token_resolve", wantErr)
	attrs := fmt.Sprint(safeSourceExitAttrs(err))
	if strings.Contains(attrs, secret) || strings.Contains(attrs, "4496576595") || !strings.Contains(attrs, "personal_ticket_token_resolve") {
		t.Fatalf("safe source attrs = %s", attrs)
	}
	if !errors.Is(err, wantErr) {
		t.Fatal("safe source error lost cause")
	}
}

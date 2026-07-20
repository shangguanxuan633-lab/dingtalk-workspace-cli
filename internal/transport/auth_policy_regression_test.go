// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");

package transport

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"

	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
)

func TestHTTP401AuthorizationEvidenceVetoesRefreshWithoutLeakingBody(t *testing.T) {
	t.Parallel()
	const secret = "access-token-secret"
	evidence := extractAuthPolicyEvidence([]byte(`{
		"errorCode":"PAT_SCOPE_AUTH_REQUIRED",
		"data":{"missingScopes":["mail:send"],"clientSecret":"access-token-secret"}
	}`))
	if !evidence.auth || !evidence.veto || evidence.code != "PAT_SCOPE_AUTH_REQUIRED" {
		t.Fatalf("evidence = %#v", evidence)
	}

	err := httpStatusError("tools/call", "https://mcp.dingtalk.com/server", http.StatusUnauthorized, "", "trace-safe-1", evidence)
	var typed *apperrors.Error
	if !errors.As(err, &typed) {
		t.Fatalf("error = %T", err)
	}
	if typed.Reason != "permission_denied" || typed.ServerDiag.ServerErrorCode != "PAT_SCOPE_AUTH_REQUIRED" {
		t.Fatalf("typed error = %#v", typed)
	}
	var output bytes.Buffer
	if printErr := apperrors.PrintJSON(&output, err); printErr != nil {
		t.Fatal(printErr)
	}
	if strings.Contains(output.String(), secret) || strings.Contains(output.String(), "mail:send") {
		t.Fatalf("HTTP auth error leaked response body: %s", output.String())
	}
}

func TestHTTP401EmptyScopeMetadataRemainsRecoverable(t *testing.T) {
	t.Parallel()
	evidence := extractAuthPolicyEvidence([]byte(`{"code":40014,"data":{"missingScopes":[]}}`))
	if !evidence.auth || evidence.veto || evidence.code != "40014" {
		t.Fatalf("evidence = %#v", evidence)
	}
	err := httpStatusError("tools/call", "https://mcp.dingtalk.com/server", http.StatusUnauthorized, "", "", evidence)
	var typed *apperrors.Error
	if !errors.As(err, &typed) || typed.Reason != "http_401" || typed.ServerDiag.ServerErrorCode != "40014" {
		t.Fatalf("typed error = %#v", typed)
	}
}

func TestJSONRPCAuthPolicyEvidenceIsStrictAndSanitized(t *testing.T) {
	t.Parallel()
	const (
		secret = "access-token-secret"
		uid    = "4496576595"
	)
	tests := []struct {
		name       string
		rpc        *RPCError
		wantReason string
		wantCode   string
	}{
		{
			name:       "plain rpc 401",
			rpc:        &RPCError{Code: http.StatusUnauthorized, Message: "rejected " + secret},
			wantReason: "tools_call_jsonrpc_error_401",
		},
		{
			name: "rpc 401 PAT veto",
			rpc: &RPCError{Code: http.StatusUnauthorized, Message: "rejected " + secret, Data: []byte(`{
				"errorCode":"PAT_SCOPE_AUTH_REQUIRED",
				"data":{"missingScope":"mail:send","clientSecret":"access-token-secret"}
			}`)},
			wantReason: "permission_denied",
			wantCode:   "PAT_SCOPE_AUTH_REQUIRED",
		},
		{
			name: "wrapped exact token rejection",
			rpc: &RPCError{Code: -32000, Message: "调用失败 " + uid, Data: []byte(`{
				"error_code":"DWS_SERVICE_UNAUTHORIZED",
				"trace_id":"trace-safe-1",
				"technical_detail":"access-token-secret"
			}`)},
			wantReason: "tools_call_jsonrpc_server_error_32000",
			wantCode:   "DWS_SERVICE_UNAUTHORIZED",
		},
		{
			name: "permission wins over token rejection",
			rpc: &RPCError{Code: -32000, Message: "调用失败 " + uid, Data: []byte(`{
				"code":"DWS_SERVICE_UNAUTHORIZED",
				"details":{"missingScopes":["mail:send"]},
				"technical_detail":"access-token-secret"
			}`)},
			wantReason: "permission_denied",
			wantCode:   "SCOPE_REQUIRED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := jsonrpcEnvelopeError("tools/call", tt.rpc, "", "")
			var typed *apperrors.Error
			if !errors.As(err, &typed) {
				t.Fatalf("error = %T", err)
			}
			if typed.Category != apperrors.CategoryAuth || typed.Reason != tt.wantReason || typed.ServerDiag.ServerErrorCode != tt.wantCode {
				t.Fatalf("typed error = %#v", typed)
			}
			if len(typed.RPCData) != 0 || typed.ServerDiag.TechnicalDetail != "" || typed.ServerDiag.FriendlyHint != "" || typed.ServerDiag.ActionURL != "" {
				t.Fatalf("auth error retained raw diagnostics: %#v", typed)
			}
			var output bytes.Buffer
			if printErr := apperrors.PrintJSON(&output, err); printErr != nil {
				t.Fatal(printErr)
			}
			for _, forbidden := range []string{secret, uid, "mail:send", "technical_detail", "rpc_data"} {
				if strings.Contains(output.String(), forbidden) {
					t.Fatalf("JSON-RPC auth error leaked %q: %s", forbidden, output.String())
				}
			}
		})
	}
}

func TestAuthPolicyEvidenceHonorsExplicitSuccess(t *testing.T) {
	t.Parallel()
	evidence := extractAuthPolicyEvidence([]byte(`{"success":true,"code":"DWS_SERVICE_UNAUTHORIZED","missingScope":"mail:send"}`))
	if evidence != (authPolicyEvidence{}) {
		t.Fatalf("explicit success produced evidence: %#v", evidence)
	}
}

// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");

package app

import (
	"context"
	"errors"
	"net/http"
	"testing"

	apperrors "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/errors"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/executor"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/transport"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/pkg/edition"
)

func TestCoreAuthRejectionFromJSONRPCError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "rpc 401",
			err: apperrors.NewAuth("remote text",
				apperrors.WithRPCCode(http.StatusUnauthorized),
				apperrors.WithCause(&transport.CallError{Stage: transport.CallStageJSONRPC, RPCCode: http.StatusUnauthorized, Cause: errors.New("remote text")}),
			),
			want: true,
		},
		{
			name: "wrapped exact server code",
			err: apperrors.NewAuth("remote text",
				apperrors.WithRPCCode(-32000),
				apperrors.WithServerDiag(apperrors.ServerDiagnostics{ServerErrorCode: "DWS_SERVICE_UNAUTHORIZED"}),
				apperrors.WithCause(&transport.CallError{Stage: transport.CallStageJSONRPC, RPCCode: -32000, Cause: errors.New("remote text")}),
			),
			want: true,
		},
		{
			name: "wrapped numeric server code",
			err: apperrors.NewAuth("remote text",
				apperrors.WithRPCCode(-32000),
				apperrors.WithServerDiag(apperrors.ServerDiagnostics{ServerErrorCode: "40014"}),
			),
			want: true,
		},
		{
			name: "permission veto",
			err: apperrors.NewAuth("permission",
				apperrors.WithReason("permission_denied"),
				apperrors.WithRPCCode(http.StatusUnauthorized),
				apperrors.WithServerDiag(apperrors.ServerDiagnostics{ServerErrorCode: "PAT_SCOPE_AUTH_REQUIRED"}),
			),
		},
		{
			name: "rpc 403 veto",
			err: apperrors.NewAuth("permission",
				apperrors.WithRPCCode(http.StatusForbidden),
				apperrors.WithCause(&transport.CallError{Stage: transport.CallStageJSONRPC, RPCCode: http.StatusForbidden}),
			),
		},
		{
			name: "arbitrary server error",
			err:  apperrors.NewAuth("auth-looking but unproven", apperrors.WithRPCCode(-32000)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marker, got := coreAuthRejectionFromError(tt.err)
			if got != tt.want {
				t.Fatalf("coreAuthRejectionFromError() = %v, want %v", got, tt.want)
			}
			if !tt.want {
				return
			}
			if marker == nil || marker.Cause == nil {
				t.Fatal("missing safe auth marker")
			}
			var typed *apperrors.Error
			if !errors.As(marker.Cause, &typed) || typed.Reason != "access_token_rejected" || len(typed.RPCData) != 0 {
				t.Fatalf("marker = %#v", marker)
			}
		})
	}
}

func TestEditionClassifierStillSeesFormalNestedReason(t *testing.T) {
	oldEdition := edition.Get()
	oldCall := runnerCallTool
	t.Cleanup(func() {
		edition.Override(oldEdition)
		runnerCallTool = oldCall
	})

	wantErr := errors.New("edition formal auth marker")
	classifier := func(content map[string]any) error {
		result, _ := content["result"].(map[string]any)
		if reason, _ := result["reason"].(string); reason == "access_token_rejected" {
			return wantErr
		}
		return nil
	}
	edition.Override(&edition.Hooks{ClassifyToolResult: classifier})
	content := map[string]any{"result": map[string]any{"reason": "access_token_rejected"}}

	runnerCallTool = func(*transport.Client, context.Context, string, string, map[string]any) (transport.ToolCallResult, error) {
		return transport.ToolCallResult{Content: content}, nil
	}
	runner := &runtimeRunner{transport: transport.NewClient(nil), globalFlags: &GlobalFlags{Token: "explicit-test-token"}}
	invocation := executor.Invocation{CanonicalProduct: "test", Tool: "formal_reason"}
	if _, err := runner.executeInvocation(context.Background(), "https://example.test", invocation); !errors.Is(err, wantErr) {
		t.Fatalf("runner skipped edition formal reason classifier: %v", err)
	}

	server := docPreflightServer(t, map[string]any{"content": content})
	defer server.Close()
	client := transport.NewClient(nil)
	client.TrustedDomains = []string{"127.0.0.1"}
	docInvocation := executor.Invocation{CanonicalProduct: "doc", Tool: "download_file", Params: map[string]any{"nodeId": "node"}}
	if err := runner.preflightDocDownload(context.Background(), client, server.URL, docInvocation); !errors.Is(err, wantErr) {
		t.Fatalf("doc preflight skipped edition formal reason classifier: %v", err)
	}
}

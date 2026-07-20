// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");

// Package authlease carries one request-local access-token snapshot together
// with the exact CAS refresh callback for that snapshot. It deliberately does
// not expose profile selectors to event transports.
package authlease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
)

type Lease struct {
	AccessToken     string
	RefreshRejected func(context.Context) (string, error)
}

type Provider func(context.Context) (Lease, error)

func Resolve(ctx context.Context, snapshotProvider Provider, provider func(context.Context) (string, error), fallback, stage string) (Lease, error) {
	if snapshotProvider != nil {
		lease, err := snapshotProvider(ctx)
		if err != nil {
			return Lease{}, authpkg.NewDiagnosticStageError(stage, err)
		}
		lease.AccessToken = strings.TrimSpace(lease.AccessToken)
		if lease.AccessToken == "" {
			return Lease{}, authpkg.NewDiagnosticStageError(stage, errors.New("access token snapshot provider returned an empty token"))
		}
		return lease, nil
	}
	if provider != nil {
		token, err := provider(ctx)
		if err != nil {
			return Lease{}, authpkg.NewDiagnosticStageError(stage, err)
		}
		if token = strings.TrimSpace(token); token != "" {
			return Lease{AccessToken: token}, nil
		}
		return Lease{}, authpkg.NewDiagnosticStageError(stage, errors.New("access token provider returned an empty token"))
	}
	if token := strings.TrimSpace(fallback); token != "" {
		return Lease{AccessToken: token}, nil
	}
	return Lease{}, authpkg.NewDiagnosticStageError(stage, errors.New("access token is required"))
}

// RefreshRejected invokes the callback bound to the rejected snapshot. The
// returned lease cannot refresh again, enforcing one transparent replay per
// logical HTTP request.
func RefreshRejected(ctx context.Context, lease Lease, stage string) (Lease, error) {
	if lease.RefreshRejected == nil {
		return Lease{}, errors.New("access token lease is not refreshable")
	}
	token, err := lease.RefreshRejected(ctx)
	if err != nil {
		logRefresh(stage, "failed", err)
		return Lease{}, authpkg.NewDiagnosticStageError(stage, err)
	}
	if token = strings.TrimSpace(token); token == "" {
		emptyErr := errors.New("rejected-token refresh returned an empty token")
		logRefresh(stage, "failed", emptyErr)
		return Lease{}, authpkg.NewDiagnosticStageError(stage, emptyErr)
	}
	logRefresh(stage, "succeeded", nil)
	return Lease{AccessToken: token}, nil
}

func logRefresh(stage, outcome string, err error) {
	attrs := []any{
		"stage", stage,
		"outcome", outcome,
		"retry_count", 1,
		"error_type", fmt.Sprintf("%T", err),
		"failure_class", string(authpkg.ClassifyRefreshFailure(err)),
		"http_status", authpkg.DiagnosticStatus(err),
		"oauth_code", "",
	}
	var endpointErr *authpkg.OAuthEndpointError
	if errors.As(err, &endpointErr) && endpointErr != nil {
		attrs[len(attrs)-1] = authpkg.SafeOAuthDiagnosticCode(endpointErr.Code)
	}
	slog.Warn("event.auth_recovery", attrs...)
}

// IsStrictRejection accepts an HTTP 401 or a structured exact 40014 code.
// HTTP 403 and scope/permission/PAT-shaped payloads are explicit vetoes.
func IsStrictRejection(status int, body []byte) bool {
	if status == http.StatusForbidden {
		return false
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	decodeErr := decoder.Decode(&value)
	if decodeErr == nil && status >= http.StatusOK && status < http.StatusMultipleChoices && explicitSuccess(value) {
		return false
	}
	if decodeErr == nil && permissionVeto(value) {
		return false
	}
	if status == http.StatusUnauthorized {
		return true
	}
	if decodeErr != nil {
		return false
	}
	return containsExactAuthRejection(value, 0)
}

func explicitSuccess(value any) bool {
	body, ok := value.(map[string]any)
	if !ok {
		return false
	}
	for _, key := range []string{"success", "ok"} {
		switch current := body[key].(type) {
		case bool:
			if current {
				return true
			}
		case string:
			if strings.EqualFold(strings.TrimSpace(current), "true") {
				return true
			}
		}
	}
	return false
}

func containsExactAuthRejection(value any, depth int) bool {
	if depth > 8 {
		return false
	}
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"code", "errorCode", "error_code", "errCode", "errcode", "serverErrorCode", "server_error_code"} {
			if child, ok := typed[key]; ok {
				switch code := child.(type) {
				case string:
					if exactAuthRejectionCode(code) {
						return true
					}
				case json.Number:
					if string(code) == "40014" {
						return true
					}
				}
			}
		}
		for _, key := range []string{"error", "data", "result", "details", "content"} {
			if child, ok := typed[key]; ok && containsExactAuthRejection(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsExactAuthRejection(child, depth+1) {
				return true
			}
		}
	}
	return false
}

func exactAuthRejectionCode(code string) bool {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "40014", "TOKEN_VERIFIED_FAILED", "USER_TOKEN_ILLEGAL", "ACCESS_TOKEN_EXPIRED", "DWS_SERVICE_UNAUTHORIZED":
		return true
	default:
		return false
	}
}

// SafeDiagnosticCode returns only fixed event/auth business codes that may be
// surfaced in logs or CLI diagnostics.
func SafeDiagnosticCode(code string) string {
	upper := strings.ToUpper(strings.TrimSpace(code))
	if upper == "" {
		return ""
	}
	if exactAuthRejectionCode(upper) || permissionVeto(upper) {
		return upper
	}
	switch upper {
	case "INVALID_PARAMETER", "NOT_FOUND", "INTERNAL_ERROR", "SERVICE_UNAVAILABLE", "TOO_MANY_REQUESTS":
		return upper
	default:
		return "other"
	}
}

func permissionVeto(value any) bool {
	return permissionVetoDepth(value, 0)
}

func permissionVetoDepth(value any, depth int) bool {
	if depth > 8 {
		return true
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalizedKey := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(strings.TrimSpace(key)))
			if normalizedKey == "missingscope" || normalizedKey == "missingscopes" ||
				normalizedKey == "requiredscope" || normalizedKey == "requiredscopes" ||
				normalizedKey == "permission" || normalizedKey == "permissions" {
				if hasPermissionEvidence(child) {
					return true
				}
			}
			if permissionVetoDepth(child, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if permissionVetoDepth(child, depth+1) {
				return true
			}
		}
	case string:
		signal := strings.ToLower(strings.TrimSpace(typed))
		if signal == "403" {
			return true
		}
		for _, marker := range []string{
			"missing_scope", "insufficient_scope", "permission_denied", "forbidden", "scope_required", "pat_scope",
			"pat_scope_auth_required", "pat_org_policy_denied", "pat_no_permission", "pat_low_risk_no_permission",
			"pat_medium_risk_no_permission", "pat_high_risk_no_permission", "pat_batch_auth_pending",
			"cli_org_not_authorized", "cli_not_authorized", "auth_permission_denied", "agent_code_not_exists", "access_denied",
		} {
			if signal == marker || strings.Contains(signal, marker+":") {
				return true
			}
		}
	case json.Number:
		return string(typed) == "403"
	}
	return false
}

func hasPermissionEvidence(value any) bool {
	switch current := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(current) != ""
	case []any:
		return len(current) > 0
	case map[string]any:
		return len(current) > 0
	case bool:
		return current
	default:
		return strings.TrimSpace(fmt.Sprint(current)) != ""
	}
}

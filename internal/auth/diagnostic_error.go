// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");

package auth

import (
	"errors"
	"fmt"
	"strings"
)

// DiagnosticStageError keeps the original error chain available to
// errors.Is/errors.As while exposing only bounded authentication diagnostics
// through Error(). It is safe to attach as a CLI JSON/verbose cause or to pass
// through a default structured logger.
type DiagnosticStageError struct {
	Stage      string
	StatusCode int
	OAuthCode  string
	Cause      error
}

func (e *DiagnosticStageError) Error() string {
	if e == nil {
		return "authentication operation failed"
	}
	stage := safeDiagnosticStage(e.Stage)
	message := "authentication stage " + stage + " failed"
	if e.Cause != nil {
		message += fmt.Sprintf(" (error type %T)", e.Cause)
	}
	if e.StatusCode != 0 {
		message += fmt.Sprintf(" (HTTP %d)", e.StatusCode)
	}
	if code := SafeOAuthDiagnosticCode(e.OAuthCode); code != "" {
		message += " (OAuth code " + code + ")"
	}
	return message
}

func (e *DiagnosticStageError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// NewDiagnosticStageError redacts a cause for user-visible/log-visible
// boundaries without destroying its typed chain.
func NewDiagnosticStageError(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	status, code := 0, ""
	var endpointErr *OAuthEndpointError
	if errors.As(cause, &endpointErr) && endpointErr != nil {
		status = endpointErr.StatusCode
		code = endpointErr.Code
	}
	return &DiagnosticStageError{Stage: stage, StatusCode: status, OAuthCode: code, Cause: cause}
}

func safeDiagnosticStage(stage string) string {
	stage = strings.TrimSpace(stage)
	if stage == "" || len(stage) > 64 {
		return "auth"
	}
	for _, r := range stage {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return "auth"
	}
	return stage
}

// DiagnosticStatus returns a safe status for structured logs.
func DiagnosticStatus(err error) int {
	var stageErr *DiagnosticStageError
	if errors.As(err, &stageErr) && stageErr != nil && stageErr.StatusCode != 0 {
		return stageErr.StatusCode
	}
	var endpointErr *OAuthEndpointError
	if errors.As(err, &endpointErr) && endpointErr != nil {
		return endpointErr.StatusCode
	}
	return 0
}

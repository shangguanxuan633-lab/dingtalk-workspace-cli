// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");

package source

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	dwsevent "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/event"
)

func transientTokenResolutionError() error {
	return &authpkg.OAuthEndpointError{StatusCode: http.StatusServiceUnavailable}
}

func terminalTokenResolutionError() error {
	return &authpkg.OAuthEndpointError{StatusCode: http.StatusBadRequest, Code: "invalid_grant"}
}

func TestPersonalSourceReconnectsAfterTransientTokenResolutionFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	src, err := NewPersonal(PersonalConfig{
		AccessTokenSnapshotProvider: func(context.Context) (AccessTokenLease, error) {
			if calls.Add(1) == 2 {
				cancel()
			}
			return AccessTokenLease{}, transientTokenResolutionError()
		},
		ClientID:     "client",
		SourceID:     "open",
		TicketURL:    "https://ticket.invalid",
		ReconnectMin: time.Millisecond,
		ReconnectMax: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = src.Start(ctx, func(*dwsevent.RawEvent) {})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context canceled after retry", err)
	}
	if calls.Load() != 2 || src.State().ReconnectCount != 1 {
		t.Fatalf("provider calls=%d reconnects=%d, want 2 calls and 1 reconnect", calls.Load(), src.State().ReconnectCount)
	}
}

func TestPersonalSourceDoesNotReconnectAfterTerminalTokenResolutionFailure(t *testing.T) {
	var calls atomic.Int32
	src, err := NewPersonal(PersonalConfig{
		AccessTokenSnapshotProvider: func(context.Context) (AccessTokenLease, error) {
			calls.Add(1)
			return AccessTokenLease{}, terminalTokenResolutionError()
		},
		ClientID:  "client",
		SourceID:  "open",
		TicketURL: "https://ticket.invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = src.Start(context.Background(), func(*dwsevent.RawEvent) {})
	if authpkg.ClassifyRefreshFailure(err) != authpkg.RefreshFailureTerminal {
		t.Fatalf("Start() error = %v, want terminal refresh failure", err)
	}
	if calls.Load() != 1 || src.State().ReconnectCount != 0 {
		t.Fatalf("provider calls=%d reconnects=%d, want 1 call and no reconnect", calls.Load(), src.State().ReconnectCount)
	}
}

func TestPortalSourceReconnectsAfterTransientTokenResolutionFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	src, err := New(Config{PortalTicket: &PortalTicketConfig{
		TicketURL: "https://ticket.invalid",
		AccessTokenSnapshotProvider: func(context.Context) (AccessTokenLease, error) {
			if calls.Add(1) == 2 {
				cancel()
			}
			return AccessTokenLease{}, transientTokenResolutionError()
		},
		SourceID:     "open",
		ReconnectMin: time.Millisecond,
		ReconnectMax: time.Millisecond,
	}})
	if err != nil {
		t.Fatal(err)
	}
	err = src.Start(ctx, func(*dwsevent.RawEvent) {})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context canceled after retry", err)
	}
	if calls.Load() != 2 || src.State().ReconnectCount != 1 {
		t.Fatalf("provider calls=%d reconnects=%d, want 2 calls and 1 reconnect", calls.Load(), src.State().ReconnectCount)
	}
}

func TestPortalSourceDoesNotReconnectAfterTerminalTokenResolutionFailure(t *testing.T) {
	var calls atomic.Int32
	src, err := New(Config{PortalTicket: &PortalTicketConfig{
		TicketURL: "https://ticket.invalid",
		AccessTokenSnapshotProvider: func(context.Context) (AccessTokenLease, error) {
			calls.Add(1)
			return AccessTokenLease{}, terminalTokenResolutionError()
		},
		SourceID: "open",
	}})
	if err != nil {
		t.Fatal(err)
	}
	err = src.Start(context.Background(), func(*dwsevent.RawEvent) {})
	if authpkg.ClassifyRefreshFailure(err) != authpkg.RefreshFailureTerminal {
		t.Fatalf("Start() error = %v, want terminal refresh failure", err)
	}
	if calls.Load() != 1 || src.State().ReconnectCount != 0 {
		t.Fatalf("provider calls=%d reconnects=%d, want 1 call and no reconnect", calls.Load(), src.State().ReconnectCount)
	}
}

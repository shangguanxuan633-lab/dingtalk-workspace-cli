// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	authpkg "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/auth"
	dwsevent "github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/event"
	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/event/authlease"
	"github.com/gorilla/websocket"
	"github.com/open-dingtalk/dingtalk-stream-sdk-go/payload"
)

const (
	PortalTicketModeNormal = "normal"
	PortalTicketModeCustom = "custom"
)

// PortalTicketConfig describes the portal-managed user Stream ticket flow.
// normal mode uses portal-side managed credentials; custom mode asks portal to
// open the user connection with the caller-provided clientId/clientSecret.
type PortalTicketConfig struct {
	TicketURL                   string
	AccessToken                 string
	AccessTokenProvider         AccessTokenProvider
	AccessTokenSnapshotProvider AccessTokenSnapshotProvider
	SourceID                    string
	Mode                        string
	ClientID                    string
	ClientSecret                string
	UserAgent                   string
	HTTPClient                  *http.Client
	WebSocketDialer             *websocket.Dialer
	ReconnectMin                time.Duration
	ReconnectMax                time.Duration
	DisableReconnect            bool
}

const (
	portalReconnectMinBackoff = time.Second
	portalReconnectMaxBackoff = 30 * time.Second
)

type portalStageError struct {
	stage     string
	status    int
	code      string
	retryable bool
	cause     error
}

func (e *portalStageError) Error() string {
	if e == nil {
		return "source: portal stream failed"
	}
	message := "source: portal " + strings.ReplaceAll(strings.TrimSpace(e.stage), "_", " ") + " failed"
	if e.status != 0 {
		message += fmt.Sprintf(" (HTTP %d)", e.status)
	}
	if e.code != "" {
		message += " (code " + e.code + ")"
	}
	return message
}

func (e *portalStageError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

var portalWriteMessage = func(conn *websocket.Conn, messageType int, data []byte) error {
	return conn.WriteMessage(messageType, data)
}

func (c *PortalTicketConfig) Valid() error {
	if c == nil {
		return errors.New("source: PortalTicketConfig is nil")
	}
	if strings.TrimSpace(c.TicketURL) == "" {
		return errors.New("source: portal ticket URL is required")
	}
	if c.AccessTokenSnapshotProvider == nil && c.AccessTokenProvider == nil && strings.TrimSpace(c.AccessToken) == "" {
		return errors.New("source: portal access token or provider is required")
	}
	if strings.TrimSpace(c.SourceID) == "" {
		return errors.New("source: portal sourceId is required")
	}
	mode := normalizePortalTicketMode(c.Mode)
	if mode == "" {
		return fmt.Errorf("source: unsupported portal ticket mode %q", c.Mode)
	}
	if mode == PortalTicketModeCustom &&
		(strings.TrimSpace(c.ClientID) == "" || strings.TrimSpace(c.ClientSecret) == "") {
		return errors.New("source: custom portal ticket mode requires clientId/clientSecret")
	}
	return nil
}

func (c *PortalTicketConfig) normalizedMode() string {
	return normalizePortalTicketMode(c.Mode)
}

func normalizePortalTicketMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return PortalTicketModeNormal
	}
	switch mode {
	case PortalTicketModeNormal, PortalTicketModeCustom:
		return mode
	default:
		return ""
	}
}

func (s *DingtalkSource) startPortalTicket(ctx context.Context, emit dwsevent.EmitFn) error {
	s.machine.OnConnecting()
	defer s.machine.OnStopped()
	minBackoff := s.cfg.PortalTicket.ReconnectMin
	if minBackoff <= 0 {
		minBackoff = portalReconnectMinBackoff
	}
	maxBackoff := s.cfg.PortalTicket.ReconnectMax
	if maxBackoff <= 0 {
		maxBackoff = portalReconnectMaxBackoff
	}
	if maxBackoff < minBackoff {
		maxBackoff = minBackoff
	}
	backoff := minBackoff
	for {
		acked, err := s.runPortalTicketAttempt(ctx, emit)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var stageErr *portalStageError
		isStageError := errors.As(err, &stageErr)
		if !isStageError && isTransientAuthFailure(err) {
			stageErr = &portalStageError{
				stage:     "ticket_auth",
				status:    authpkg.DiagnosticStatus(err),
				retryable: true,
				cause:     err,
			}
			isStageError = true
		}
		if !isStageError || !stageErr.retryable || s.cfg.PortalTicket.DisableReconnect {
			return err
		}
		if acked {
			backoff = minBackoff
		}
		s.machine.OnReconnect()
		slog.Warn("portal source reconnecting",
			"stage", stageErr.stage,
			"http_status", stageErr.status,
			"server_code", stageErr.code,
			"error_type", fmt.Sprintf("%T", stageErr.cause),
			"retry_in", backoff,
			"reconnect_count", s.machine.Snapshot().ReconnectCount,
		)
		if err := waitPersonalReconnect(ctx, backoff); err != nil {
			return err
		}
		backoff = nextPersonalBackoff(backoff, maxBackoff)
	}
}

func (s *DingtalkSource) runPortalTicketAttempt(ctx context.Context, emit dwsevent.EmitFn) (bool, error) {
	ticket, err := requestPortalTicket(ctx, s.cfg.PortalTicket)
	if err != nil {
		return false, err
	}
	wsURL, err := websocketURL(ticket)
	if err != nil {
		return false, &portalStageError{stage: "websocket_url", cause: err}
	}

	userAgent := strings.TrimSpace(s.cfg.PortalTicket.UserAgent)
	if userAgent == "" {
		userAgent = "dws-event-consume"
	}
	dialer := s.cfg.PortalTicket.WebSocketDialer
	if dialer == nil {
		dialer = &websocket.Dialer{HandshakeTimeout: 20 * time.Second}
	}
	conn, resp, err := dialer.DialContext(ctx, wsURL, http.Header{
		"User-Agent": []string{userAgent},
	})
	if err != nil {
		status := 0
		if resp != nil {
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			status = resp.StatusCode
		}
		return false, &portalStageError{stage: "stream_connect", status: status, retryable: status == 0 || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500, cause: err}
	}
	attemptCtx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		_ = conn.Close()
	}()
	s.machine.OnConnected()

	closeOnContext(attemptCtx, conn)
	handler := s.makeHandler(emit)
	acked := false
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if isContextDone(ctx) {
				return acked, ctx.Err()
			}
			return acked, &portalStageError{stage: "stream_read", retryable: true, cause: err}
		}
		df, err := payload.DecodeDataFrame(message)
		if err != nil {
			continue
		}
		resp, _ := handler(ctx, df)
		ensurePortalAckHeaders(resp, df)
		if err := portalWriteMessage(conn, websocket.TextMessage, resp.Encode()); err != nil {
			if isContextDone(ctx) {
				return acked, ctx.Err()
			}
			return acked, &portalStageError{stage: "stream_ack", retryable: true, cause: err}
		}
		acked = true
	}
}

type portalStreamTicket struct {
	Endpoint string `json:"endpoint"`
	Ticket   string `json:"ticket"`
}

func requestPortalTicket(ctx context.Context, cfg *PortalTicketConfig) (portalStreamTicket, error) {
	lease, err := resolveSourceAccessTokenLease(ctx, cfg.AccessTokenSnapshotProvider, cfg.AccessTokenProvider, cfg.AccessToken, "portal_ticket_token_resolve")
	if err != nil {
		return portalStreamTicket{}, err
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	body := map[string]string{
		"sourceId":    strings.TrimSpace(cfg.SourceID),
		"channelType": strings.TrimSpace(cfg.SourceID),
		"mode":        cfg.normalizedMode(),
	}
	if cfg.normalizedMode() == PortalTicketModeCustom {
		body["clientId"] = strings.TrimSpace(cfg.ClientID)
		body["clientSecret"] = strings.TrimSpace(cfg.ClientSecret)
	}
	rawBody, _ := json.Marshal(body)
	for attempt := 0; attempt < 2; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(cfg.TicketURL), bytes.NewReader(rawBody))
		if reqErr != nil {
			return portalStreamTicket{}, &portalStageError{stage: "ticket_request_build", cause: reqErr}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if ua := strings.TrimSpace(cfg.UserAgent); ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		req.Header.Set("x-user-access-token", lease.AccessToken)

		resp, doErr := httpClient.Do(req)
		if doErr != nil {
			return portalStreamTicket{}, &portalStageError{stage: "ticket_request", retryable: true, cause: doErr}
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if attempt == 0 && lease.RefreshRejected != nil && authlease.IsStrictRejection(resp.StatusCode, raw) {
			lease, err = authlease.RefreshRejected(ctx, lease, "portal_ticket_rejected_refresh")
			if err != nil {
				return portalStreamTicket{}, err
			}
			continue
		}
		if resp.StatusCode >= 400 {
			code := portalResponseCode(raw)
			retryable := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
			return portalStreamTicket{}, &portalStageError{stage: "ticket_request", status: resp.StatusCode, code: code, retryable: retryable}
		}

		var direct portalStreamTicket
		if jsonErr := json.Unmarshal(raw, &direct); jsonErr == nil && direct.Endpoint != "" && direct.Ticket != "" {
			return direct, nil
		}

		var envelope struct {
			Success   bool               `json:"success"`
			Result    portalStreamTicket `json:"result"`
			ErrorCode string             `json:"errorCode"`
			ErrorMsg  string             `json:"errorMsg"`
		}
		if jsonErr := json.Unmarshal(raw, &envelope); jsonErr != nil {
			return portalStreamTicket{}, &portalStageError{stage: "ticket_parse", cause: jsonErr}
		}
		if !envelope.Success {
			return portalStreamTicket{}, &portalStageError{stage: "ticket_response", code: safePortalCode(envelope.ErrorCode)}
		}
		if envelope.Result.Endpoint == "" || envelope.Result.Ticket == "" {
			return portalStreamTicket{}, &portalStageError{stage: "ticket_response", code: "MISSING_ENDPOINT_OR_TICKET"}
		}
		return envelope.Result, nil
	}
	return portalStreamTicket{}, &portalStageError{stage: "ticket_request", code: "AUTH_RETRY_EXHAUSTED"}
}

func portalResponseCode(raw []byte) string {
	var envelope struct {
		ErrorCode string `json:"errorCode"`
		Code      string `json:"code"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return ""
	}
	if envelope.ErrorCode != "" {
		return safePortalCode(envelope.ErrorCode)
	}
	return safePortalCode(envelope.Code)
}

func safePortalCode(value string) string {
	switch value = strings.TrimSpace(value); strings.ToUpper(value) {
	case "":
		return ""
	case "40014":
		return "40014"
	case "UNAUTHORIZED", "NO_AUTH", "INVALID_TOKEN", "ACCESS_TOKEN_EXPIRED", "TOKEN_EXPIRED":
		return strings.ToUpper(value)
	default:
		return "other"
	}
}

func websocketURL(ticket portalStreamTicket) (string, error) {
	u, err := url.Parse(ticket.Endpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("ticket", ticket.Ticket)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func ensurePortalAckHeaders(resp *payload.DataFrameResponse, df *payload.DataFrame) {
	if resp.GetHeader(payload.DataFrameHeaderKMessageId) == "" {
		resp.SetHeader(payload.DataFrameHeaderKMessageId, df.GetMessageId())
	}
	if resp.GetHeader(payload.DataFrameHeaderKContentType) == "" {
		resp.SetHeader(payload.DataFrameHeaderKContentType, payload.DataFrameContentTypeKJson)
	}
}

func closeOnContext(ctx context.Context, conn *websocket.Conn) {
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
}

func isContextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func truncatePortalTicketLog(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

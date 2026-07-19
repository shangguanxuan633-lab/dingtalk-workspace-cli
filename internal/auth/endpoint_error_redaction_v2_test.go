package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDeviceAndAppEndpointErrorsExcludeServerFreeText(t *testing.T) {
	const secret = "token-secret-uid-4496576595"
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body: io.NopCloser(strings.NewReader(
				`{"error":"unknown-` + secret + `","errorCode":"unknown-` + secret + `","message":"` + secret + `"}`,
			)),
			Header: make(http.Header),
		}, nil
	})}
	provider := NewDeviceFlowProvider(t.TempDir(), nil)
	provider.httpClient = client
	for _, invoke := range []func() error{
		func() error { _, err := provider.postForm(context.Background(), "https://example.invalid", url.Values{}); return err },
		func() error { _, err := provider.doGet(context.Background(), "https://example.invalid"); return err },
	} {
		err := invoke()
		var endpointErr *OAuthEndpointError
		if !errors.As(err, &endpointErr) || endpointErr.StatusCode != http.StatusBadRequest {
			t.Fatalf("safe device endpoint error = %#v", err)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "4496576595") {
			t.Fatalf("device endpoint leaked server body: %v", err)
		}
	}

	previousClient := appTokenHTTPClient
	appTokenHTTPClient = client
	t.Cleanup(func() { appTokenHTTPClient = previousClient })
	_, _, err := FetchAppToken(context.Background(), "app", "secret")
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "4496576595") {
		t.Fatalf("app token endpoint error = %v", err)
	}
}

func TestDevicePollFreeTextIsNotRendered(t *testing.T) {
	const secret = "token-secret-uid-4496576595"
	previousAfter := deviceFlowAfter
	previousPoll := devicePollToken
	t.Cleanup(func() {
		deviceFlowAfter = previousAfter
		devicePollToken = previousPoll
	})
	ready := make(chan time.Time)
	close(ready)
	deviceFlowAfter = func(time.Duration) <-chan time.Time { return ready }
	ctx, cancel := context.WithCancel(context.Background())
	devicePollToken = func(*DeviceFlowProvider, context.Context, string) (*DeviceTokenResponse, error) {
		cancel()
		return &DeviceTokenResponse{Error: secret}, nil
	}
	provider := NewDeviceFlowProvider(t.TempDir(), nil)
	var output bytes.Buffer
	provider.Output = &output
	_, err := provider.waitForAuthorizationByDeviceCode(ctx, &DeviceAuthResponse{
		DeviceCode: "device", Interval: 1, ExpiresIn: 60,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("poll error = %v", err)
	}
	if strings.Contains(output.String(), secret) || strings.Contains(output.String(), "4496576595") {
		t.Fatalf("device poll output leaked free text: %s", output.String())
	}
}

func TestDevicePollFailureIsLoggedAndRetainedWithoutExplicitLogger(t *testing.T) {
	const secret = "token-secret-uid-4496576595"
	sentinel := errors.New(secret)
	previousAfter, previousNow, previousPoll := deviceFlowAfter, deviceFlowNow, devicePollToken
	previousLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		deviceFlowAfter, deviceFlowNow, devicePollToken = previousAfter, previousNow, previousPoll
		slog.SetDefault(previousLogger)
	})
	ready := make(chan time.Time)
	close(ready)
	deviceFlowAfter = func(time.Duration) <-chan time.Time { return ready }
	base := time.Unix(100, 0)
	var nowCalls int
	deviceFlowNow = func() time.Time {
		nowCalls++
		if nowCalls >= 4 {
			return base.Add(2 * time.Second)
		}
		return base
	}
	devicePollToken = func(*DeviceFlowProvider, context.Context, string) (*DeviceTokenResponse, error) {
		return nil, sentinel
	}
	provider := NewDeviceFlowProvider(t.TempDir(), nil)
	provider.Output = io.Discard
	_, err := provider.waitForAuthorizationByDeviceCode(context.Background(), &DeviceAuthResponse{
		DeviceCode: "device", Interval: 1, ExpiresIn: 1,
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("poll error lost cause: %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "auth.device.poll_failed") || !strings.Contains(out, "device_token_poll") {
		t.Fatalf("missing safe poll diagnostic: %s", out)
	}
	if strings.Contains(out, secret) || strings.Contains(out, "4496576595") {
		t.Fatalf("poll diagnostic leaked error text: %s", out)
	}
}

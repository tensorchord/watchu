package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/internal/tool"
)

const (
	endpointHealth = "/healthz"
	endpointIngest = "/api/v1/ingest"

	maxGatewayRetryCount = 3
	gatewayRetryDelay    = time.Second
	healthCheckTimeout   = 5 * time.Second
	requestTimeout       = 30 * time.Second
)

var (
	errGatewayRequestTimeout = errors.New("gateway request timed out")
	errGatewayHealthTimeout  = errors.New("gateway health check timed out")
)

type BatchRecord struct {
	Events []any `json:"events"`
}

type GatewaySink struct {
	baseURL   string
	client    *http.Client
	transport *http.Transport
}

func NewGatewaySink(ctx context.Context, baseURL string) (*GatewaySink, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{Transport: transport}

	if err := gatewayHealthCheck(ctx, client, baseURL); err != nil {
		return nil, err
	}
	log.Info().Str("target", baseURL).Msg("exporting events to gateway")
	log.Debug().Str("boot_time", bootTime.String()).Str("target", baseURL).Msg("init gateway sink")
	return &GatewaySink{
		baseURL:   baseURL,
		client:    client,
		transport: transport,
	}, nil
}

func (s *GatewaySink) Close() error {
	if s != nil && s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	return nil
}

func (s *GatewaySink) WriteBatch(ctx context.Context, endpoint string, events []any) error {
	var lastErr error
	for attempt := 1; attempt <= maxGatewayRetryCount; attempt++ {
		attemptCtx, cancel := context.WithTimeoutCause(ctx, requestTimeout, errGatewayRequestTimeout)
		lastErr = s.writeBatchOnce(attemptCtx, endpoint, events)
		cancel()
		if lastErr == nil {
			return nil
		}
		log.Error().
			Err(lastErr).
			Int("attempt", attempt).
			Int("max_attempts", maxGatewayRetryCount).
			Str("endpoint", endpoint).
			Msg("failed to export batch to gateway")
		if attempt == maxGatewayRetryCount {
			break
		}
		timer := time.NewTimer(gatewayRetryDelay * time.Duration(attempt))
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("gateway export canceled after %d attempts: %w", attempt, context.Cause(ctx))
		}
	}
	return fmt.Errorf("gateway export failed after %d attempts: %w", maxGatewayRetryCount, lastErr)
}

func (s *GatewaySink) writeBatchOnce(ctx context.Context, endpoint string, events []any) error {
	payload, err := json.Marshal(BatchRecord{Events: events})
	if err != nil {
		return fmt.Errorf("marshal events: %w", err)
	}
	link, err := url.JoinPath(s.baseURL, endpointIngest, endpoint)
	if err != nil {
		return fmt.Errorf("join ingest URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, link, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create HTTP request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	//nolint:bodyclose // closed in ReadCloserToBytes
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send HTTP request: %w", err)
	}
	respMessage, err := tool.ReadCloserToBytes(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("gateway status %d for %s: %s", resp.StatusCode, endpoint, string(respMessage))
	}
	log.Debug().Int("count", len(events)).Bytes("resp", respMessage).Str("endpoint", endpoint).Msg("successfully ingested events")
	return nil
}

func gatewayHealthCheck(ctx context.Context, client *http.Client, baseURL string) error {
	checkCtx, cancel := context.WithTimeoutCause(ctx, healthCheckTimeout, errGatewayHealthTimeout)
	defer cancel()

	link, err := url.JoinPath(baseURL, endpointHealth)
	if err != nil {
		return fmt.Errorf("failed to join URL path: %w", err)
	}
	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, link, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request to the gateway health endpoint: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request to the gateway health endpoint: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("failed to close health check response body")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway health check failed with status code: %d", resp.StatusCode)
	}
	return nil
}

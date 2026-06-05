package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const defaultEventRequestTimeout = 5 * time.Second

type EventClientConfig struct {
	BaseURL        string
	InternalAPIKey string
	Timeout        time.Duration
	Client         *http.Client
}

type EventClient struct {
	baseURL        *url.URL
	internalAPIKey string
	httpClient     *http.Client
}

func NewEventClient(cfg EventClientConfig) (*EventClient, error) {
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		return nil, errors.New("notification service url is required")
	}
	if !strings.Contains(baseURL, "://") {
		baseURL = "http://" + baseURL
	}

	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse notification service url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("notification service url must include scheme and host")
	}

	internalAPIKey := strings.TrimSpace(cfg.InternalAPIKey)
	if internalAPIKey == "" {
		return nil, errors.New("notification internal api key is required")
	}

	httpClient := cfg.Client
	if httpClient == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = defaultEventRequestTimeout
		}
		httpClient = &http.Client{Timeout: timeout}
	}

	return &EventClient{
		baseURL:        parsed,
		internalAPIKey: internalAPIKey,
		httpClient:     httpClient,
	}, nil
}

func (c *EventClient) SendEvent(ctx context.Context, userID uuid.UUID, event string, data map[string]any) error {
	if userID == uuid.Nil {
		return errors.New("notification user id is required")
	}
	if strings.TrimSpace(event) == "" {
		return errors.New("notification event name is required")
	}

	payload := map[string]any{
		"userId": userID.String(),
		"event":  event,
		"data":   data,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal notification event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/internal/notification-events"), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create notification event request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-API-Key", c.internalAPIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send notification event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("send notification event: unexpected status %s: %s", resp.Status, responseSnippet(resp.Body))
	}

	return nil
}

func (c *EventClient) endpoint(route string) string {
	next := *c.baseURL
	next.Path = strings.TrimRight(next.Path, "/") + route
	return next.String()
}

func responseSnippet(r io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(r, 1024))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

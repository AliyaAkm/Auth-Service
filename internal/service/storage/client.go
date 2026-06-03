package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"strings"
	"time"
)

const defaultRequestTimeout = 30 * time.Minute

type ClientConfig struct {
	BaseURL string
	Timeout time.Duration
	Client  *http.Client
}

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
}

func NewClient(cfg ClientConfig) (*Client, error) {
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		return nil, errors.New("storage service url is required")
	}
	if !strings.Contains(baseURL, "://") {
		baseURL = "http://" + baseURL
	}

	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse storage service url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("storage service url must include scheme and host")
	}

	httpClient := cfg.Client
	if httpClient == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = defaultRequestTimeout
		}
		httpClient = &http.Client{Timeout: timeout}
	}

	return &Client{
		baseURL:    parsed,
		httpClient: httpClient,
	}, nil
}

func (c *Client) PutObject(ctx context.Context, objectKey string, body io.ReadSeeker, _ int64, contentType string) error {
	objectKey = strings.Trim(strings.TrimSpace(objectKey), "/")
	if objectKey == "" {
		return errors.New("storage object key is required")
	}
	if body == nil {
		return errors.New("storage object body is required")
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind storage object body: %w", err)
	}

	reader, writer := io.Pipe()
	multipartWriter := multipart.NewWriter(writer)
	writeErr := make(chan error, 1)

	go func() {
		err := writeUploadBody(multipartWriter, objectKey, body, contentType)
		if err != nil {
			_ = writer.CloseWithError(err)
			writeErr <- err
			return
		}

		writeErr <- writer.Close()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/objects"), reader)
	if err != nil {
		_ = reader.CloseWithError(err)
		return fmt.Errorf("create storage upload request: %w", err)
	}
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		_ = reader.CloseWithError(err)
		<-writeErr
		return fmt.Errorf("upload storage object: %w", err)
	}
	defer resp.Body.Close()

	if err = <-writeErr; err != nil {
		return fmt.Errorf("write storage upload request: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("upload storage object: unexpected status %s: %s", resp.Status, responseSnippet(resp.Body))
	}

	return nil
}

func (c *Client) PresignGetObject(objectKey string) (string, error) {
	objectKey = strings.Trim(strings.TrimSpace(objectKey), "/")
	if objectKey == "" {
		return "", errors.New("storage object key is required")
	}

	endpoint, err := url.Parse(c.endpoint("/objects/presign"))
	if err != nil {
		return "", fmt.Errorf("parse storage presign endpoint: %w", err)
	}

	query := endpoint.Query()
	query.Set("object_key", objectKey)
	endpoint.RawQuery = query.Encode()

	resp, err := c.httpClient.Get(endpoint.String())
	if err != nil {
		return "", fmt.Errorf("presign storage object: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("presign storage object: unexpected status %s: %s", resp.Status, responseSnippet(resp.Body))
	}

	var payload struct {
		URL string `json:"url"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode storage presign response: %w", err)
	}
	if strings.TrimSpace(payload.URL) == "" {
		return "", errors.New("storage presign response url is empty")
	}

	return payload.URL, nil
}

func (c *Client) endpoint(route string) string {
	next := *c.baseURL
	next.Path = strings.TrimRight(next.Path, "/") + route
	return next.String()
}

func writeUploadBody(w *multipart.Writer, objectKey string, body io.Reader, contentType string) error {
	if err := w.WriteField("object_key", objectKey); err != nil {
		return fmt.Errorf("write object key field: %w", err)
	}

	if strings.TrimSpace(contentType) == "" {
		contentType = "application/octet-stream"
	}

	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{
		"name":     "file",
		"filename": path.Base(objectKey),
	}))
	header.Set("Content-Type", contentType)

	part, err := w.CreatePart(header)
	if err != nil {
		return fmt.Errorf("create file form part: %w", err)
	}
	if _, err = io.Copy(part, body); err != nil {
		return fmt.Errorf("copy file form part: %w", err)
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("close multipart writer: %w", err)
	}

	return nil
}

func responseSnippet(r io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(r, 1024))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

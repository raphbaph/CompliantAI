package backend

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config configures the bounded non-streaming OpenAI-compatible client.
type Config struct {
	BaseURL          string
	Credential       string // optional bearer token injected by the gateway only
	Timeout          time.Duration
	MaxResponseBytes int64
	AllowInsecure    bool // permits non-loopback http:// when true (mirrors config policy)
	HTTPClient       *http.Client
}

// Client calls one configured OpenAI-compatible backend with reconstructed requests.
type Client struct {
	baseURL          string
	credential       string
	timeout          time.Duration
	maxResponseBytes int64
	httpClient       *http.Client
}

// NewClient validates configuration and constructs a fail-closed backend client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 || cfg.MaxResponseBytes <= 0 {
		return nil, ErrInvalidConfig
	}
	if err := validateBaseURL(cfg.BaseURL, cfg.AllowInsecure); err != nil {
		return nil, err
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	} else {
		// Clone so we can enforce no redirects without mutating caller state.
		cloned := *httpClient
		httpClient = &cloned
	}
	// Backend BaseURL is static config; never follow redirects that could move credentials.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		baseURL:          strings.TrimRight(cfg.BaseURL, "/"),
		credential:       cfg.Credential,
		timeout:          cfg.Timeout,
		maxResponseBytes: cfg.MaxResponseBytes,
		httpClient:       httpClient,
	}, nil
}

// ChatCompletions sends a reconstructed non-streaming chat completion request.
// After invocation begins, caller context cancellation does not abort the backend
// round-trip; a bounded internal timeout still applies so settlement can complete.
func (client *Client) ChatCompletions(ctx context.Context, request ChatRequest) (ChatResult, error) {
	if client == nil || client.httpClient == nil {
		return ChatResult{}, ErrUnavailable
	}
	body, err := encodeChatRequest(request)
	if err != nil {
		return ChatResult{}, err
	}

	base := context.WithoutCancel(ctx)
	reqCtx, cancel := context.WithTimeout(base, client.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, client.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return ChatResult{}, ErrUnavailable
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	// Never forward caller headers. Only inject configured backend credential.
	if client.credential != "" {
		httpReq.Header.Set("Authorization", "Bearer "+client.credential)
	}

	resp, err := client.httpClient.Do(httpReq)
	if err != nil {
		if reqCtx.Err() != nil {
			return ChatResult{}, ErrTimeout
		}
		return ChatResult{}, ErrUnavailable
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, client.maxResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		if reqCtx.Err() != nil {
			return ChatResult{}, ErrTimeout
		}
		return ChatResult{}, ErrUnavailable
	}
	if int64(len(raw)) > client.maxResponseBytes {
		return ChatResult{}, ErrResponseTooLarge
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		clear(raw)
		return ChatResult{}, ErrUnavailable
	}
	result, err := parseChatResponse(raw)
	if err != nil {
		clear(raw)
		return ChatResult{}, err
	}
	return result, nil
}

func validateBaseURL(raw string, allowInsecure bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ErrInvalidConfig
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrInvalidConfig
	}
	switch {
	case strings.HasPrefix(raw, "https://"):
		return nil
	case strings.HasPrefix(raw, "http://"):
		host := parsed.Hostname()
		if host == "127.0.0.1" || host == "localhost" || host == "::1" || allowInsecure {
			return nil
		}
		return ErrInvalidConfig
	default:
		return ErrInvalidConfig
	}
}

package backend_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/raphbaph/CompliantAI/internal/backend"
)

func TestClientForwardsReconstructedSupportedFieldsOnly(t *testing.T) {
	var sawAuth string
	var sawBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &sawBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-1",
			"object":"chat.completion",
			"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}
		}`))
	}))
	defer server.Close()

	client, err := backend.NewClient(backend.Config{
		BaseURL:          server.URL,
		Credential:       "backend-secret-token",
		Timeout:          time.Second,
		MaxResponseBytes: 1 << 20,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	raw := []byte(`{
		"model":"qwen-local",
		"messages":[{"role":"user","content":"hello"}],
		"temperature":0.2,
		"max_tokens":16
	}`)
	req, err := backend.ParseChatRequest(raw)
	if err != nil {
		t.Fatalf("ParseChatRequest: %v", err)
	}
	result, err := client.ChatCompletions(context.Background(), req)
	if err != nil {
		t.Fatalf("ChatCompletions: %v", err)
	}
	if sawAuth != "Bearer backend-secret-token" {
		t.Fatalf("backend auth = %q", sawAuth)
	}
	if _, ok := sawBody["stream"]; ok {
		t.Fatalf("stream forwarded: %#v", sawBody)
	}
	if sawBody["model"] != "qwen-local" {
		t.Fatalf("model = %#v", sawBody["model"])
	}
	if result.Usage.PromptTokens != 3 || result.Usage.CompletionTokens != 1 || result.Usage.TotalTokens != 4 {
		t.Fatalf("usage = %#v", result.Usage)
	}
	if !strings.Contains(string(result.RawJSON), `"content":"ok"`) {
		t.Fatalf("raw response missing content marker")
	}
}

func TestParseChatRequestRejectsUnsupportedShapes(t *testing.T) {
	tests := []string{
		`{"model":"m","messages":[{"role":"user","content":"x"}],"stream":true}`,
		`{"model":"m","messages":[{"role":"user","content":"x"}],"tools":[]}`,
		`{"model":"m","messages":[{"role":"user","content":"x"}],"functions":[]}`,
		`{"model":"m","messages":[{"role":"user","content":"x"}],"modalities":["text"]}`,
		`{"model":"m","messages":[{"role":"user","content":"x"}],"tool_choice":"auto"}`,
		`{"model":"m","messages":[{"role":"user","content":"x"}],"unknown":1}`,
		`{"model":"m","messages":[{"role":"user","content":{"type":"image"}}]}`,
	}
	for _, raw := range tests {
		if _, err := backend.ParseChatRequest([]byte(raw)); err != backend.ErrInvalidRequest {
			t.Fatalf("raw %s error = %v, want ErrInvalidRequest", raw, err)
		}
	}
	// stream:false is accepted and not forwarded on the wire reconstruction.
	req, err := backend.ParseChatRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"x"}],"stream":false}`))
	if err != nil {
		t.Fatalf("stream false parse: %v", err)
	}
	if req.Model != "m" {
		t.Fatalf("request = %#v", req)
	}
}

func TestClientRejectsOmittedUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}]}`))
	}))
	defer server.Close()
	client, err := backend.NewClient(backend.Config{
		BaseURL:          server.URL,
		Timeout:          time.Second,
		MaxResponseBytes: 4096,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req, err := backend.ParseChatRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := client.ChatCompletions(context.Background(), req); err != backend.ErrUsageInvalid {
		t.Fatalf("omitted usage error = %v, want ErrUsageInvalid", err)
	}
}

func TestClientRejectsInconsistentUsageTotals(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":2,"total_tokens":3}}`))
	}))
	defer server.Close()
	client, err := backend.NewClient(backend.Config{
		BaseURL:          server.URL,
		Timeout:          time.Second,
		MaxResponseBytes: 4096,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req, err := backend.ParseChatRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := client.ChatCompletions(context.Background(), req); err != backend.ErrUsageInvalid {
		t.Fatalf("inconsistent usage error = %v, want ErrUsageInvalid", err)
	}
}

func TestClientAllowInsecureRemoteHTTP(t *testing.T) {
	if _, err := backend.NewClient(backend.Config{
		BaseURL:          "http://example.com",
		Timeout:          time.Second,
		MaxResponseBytes: 1024,
	}); err != backend.ErrInvalidConfig {
		t.Fatalf("insecure remote without flag error = %v", err)
	}
	if _, err := backend.NewClient(backend.Config{
		BaseURL:          "http://example.com",
		Timeout:          time.Second,
		MaxResponseBytes: 1024,
		AllowInsecure:    true,
	}); err != nil {
		t.Fatalf("allow_insecure remote error = %v", err)
	}
}

func TestClientNeverForwardsCallerAuthorizationHeader(t *testing.T) {
	// The client API does not accept caller headers at all; only configured credential.
	var got http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer server.Close()
	client, err := backend.NewClient(backend.Config{
		BaseURL:          server.URL,
		Credential:       "only-backend-cred",
		Timeout:          time.Second,
		MaxResponseBytes: 4096,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req, err := backend.ParseChatRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := client.ChatCompletions(context.Background(), req); err != nil {
		t.Fatalf("call: %v", err)
	}
	if got.Get("Authorization") != "Bearer only-backend-cred" {
		t.Fatalf("authorization = %q", got.Get("Authorization"))
	}
	// No leakage of arbitrary client header names.
	if got.Get("X-Caller-Authorization") != "" {
		t.Fatal("caller authorization header was forwarded")
	}
}

func TestClientMapsBackendFailuresToFixedCodes(t *testing.T) {
	var mode atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 1:
			time.Sleep(200 * time.Millisecond)
			_, _ = w.Write([]byte(`{}`))
		case 2:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{not-json`))
		case 3:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":{"message":"BACKEND-ERROR-CANARY-secret"}}`))
		case 4:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":-1,"completion_tokens":1,"total_tokens":0}}`))
		case 5:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat("a", 100)))
		default:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`upstream boom BACKEND-ERROR-CANARY`))
		}
	}))
	defer server.Close()

	newClient := func(maxResp int64, timeout time.Duration) *backend.Client {
		client, err := backend.NewClient(backend.Config{
			BaseURL:          server.URL,
			Timeout:          timeout,
			MaxResponseBytes: maxResp,
			HTTPClient:       server.Client(),
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		return client
	}
	req, err := backend.ParseChatRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	mode.Store(0)
	if _, err := newClient(4096, time.Second).ChatCompletions(context.Background(), req); err != backend.ErrUnavailable {
		t.Fatalf("unavailable = %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("error leaked backend body: %v", err)
	}

	mode.Store(1)
	if _, err := newClient(4096, 50*time.Millisecond).ChatCompletions(context.Background(), req); err != backend.ErrTimeout {
		t.Fatalf("timeout = %v", err)
	}

	mode.Store(2)
	if _, err := newClient(4096, time.Second).ChatCompletions(context.Background(), req); err != backend.ErrInvalidResponse {
		t.Fatalf("malformed = %v", err)
	}

	mode.Store(3)
	if _, err := newClient(4096, time.Second).ChatCompletions(context.Background(), req); err != backend.ErrInvalidResponse {
		t.Fatalf("content-bearing error body = %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("leaked canary: %v", err)
	}

	mode.Store(4)
	if _, err := newClient(4096, time.Second).ChatCompletions(context.Background(), req); err != backend.ErrUsageInvalid {
		t.Fatalf("usage = %v", err)
	}

	mode.Store(5)
	if _, err := newClient(32, time.Second).ChatCompletions(context.Background(), req); err != backend.ErrResponseTooLarge {
		t.Fatalf("too large = %v", err)
	}
}

func TestClientIgnoresCallerCancelAfterInvocation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer server.Close()

	client, err := backend.NewClient(backend.Config{
		BaseURL:          server.URL,
		Timeout:          2 * time.Second,
		MaxResponseBytes: 4096,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req, err := backend.ParseChatRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	var result backend.ChatResult
	go func() {
		var callErr error
		result, callErr = client.ChatCompletions(ctx, req)
		errCh <- callErr
	}()
	<-started
	cancel() // simulate client disconnect after backend invocation began
	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("call after cancel error = %v", err)
	}
	if result.Usage.TotalTokens != 2 {
		t.Fatalf("result = %#v", result)
	}
}

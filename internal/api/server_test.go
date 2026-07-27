package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/raphbaph/CompliantAI/internal/api"
	"github.com/raphbaph/CompliantAI/internal/audit"
	"github.com/raphbaph/CompliantAI/internal/auth"
	"github.com/raphbaph/CompliantAI/internal/backend"
	"github.com/raphbaph/CompliantAI/internal/budget"
	"github.com/raphbaph/CompliantAI/internal/detect"
	"github.com/raphbaph/CompliantAI/internal/policy"
)

const testPrincipal = "00000000-0000-4000-8000-0000000000a1"

func TestChatCompletionsVerticalSlice(t *testing.T) {
	fixture := newAPIFixture(t)
	var backendCalls int
	fixture.backend.fn = func(ctx context.Context, req backend.ChatRequest) (backend.ChatResult, error) {
		backendCalls++
		if req.Model != "qwen-local" {
			t.Fatalf("backend model = %q", req.Model)
		}
		raw := []byte(`{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"RESPONSE-CANARY-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`)
		return backend.ChatResult{
			ID:      "chatcmpl-1",
			Content: "RESPONSE-CANARY-ok",
			Usage:   backend.Usage{PromptTokens: 5, CompletionTokens: 2, TotalTokens: 7},
			RawJSON: raw,
		}, nil
	}

	body := `{"model":"local-legal","messages":[{"role":"user","content":"PROMPT-CANARY-hello max@example.com"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if backendCalls != 1 {
		t.Fatalf("backend calls = %d", backendCalls)
	}
	if !strings.Contains(rec.Body.String(), "RESPONSE-CANARY-ok") {
		t.Fatalf("response body = %s", rec.Body.String())
	}
	if len(fixture.auditor.events) < 2 {
		t.Fatalf("audit events = %d", len(fixture.auditor.events))
	}
	// Canaries must not appear in audit metadata fields.
	encoded, _ := json.Marshal(fixture.auditor.events)
	if strings.Contains(string(encoded), "PROMPT-CANARY") || strings.Contains(string(encoded), "RESPONSE-CANARY") || strings.Contains(string(encoded), "max@example.com") {
		t.Fatalf("audit retained canary content: %s", encoded)
	}
	if fixture.budget.reserved != 0 || fixture.budget.committed <= 0 {
		t.Fatalf("budget reserved/committed = %d/%d", fixture.budget.reserved, fixture.budget.committed)
	}
	// Classification should have noticed email.
	foundEmail := false
	for _, event := range fixture.auditor.events {
		for _, category := range event.PIICategories {
			if category == "email_address" {
				foundEmail = true
			}
		}
	}
	if !foundEmail {
		t.Fatal("expected email_address classification in audit")
	}
}

func TestChatCompletionsPolicyDenial(t *testing.T) {
	fixture := newAPIFixture(t)
	// Replace policy with deny-all engine.
	engine, err := policy.NewEngine(policy.Document{
		Version: "deny-all",
		Rules: []policy.Rule{{
			ID:         "deny",
			Effect:     policy.EffectDeny,
			Principals: []string{testPrincipal},
			Endpoints:  []string{"chat.completions"},
			Models:     []string{"local-legal"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.deps.Policy = engine
	server, err := api.New(fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	fixture.backend.fn = func(ctx context.Context, req backend.ChatRequest) (backend.ChatResult, error) {
		t.Fatal("backend must not be called")
		return backend.ChatResult{}, nil
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"local-legal","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(fixture.auditor.events) != 1 || fixture.auditor.events[0].EventType != audit.EventRunDenied {
		t.Fatalf("events = %#v", fixture.auditor.events)
	}
}

func TestUnknownModelUsesSameDenialSurfaceAsPolicyDeny(t *testing.T) {
	fixture := newAPIFixture(t)
	fixture.backend.fn = func(ctx context.Context, req backend.ChatRequest) (backend.ChatResult, error) {
		t.Fatal("backend must not be called")
		return backend.ChatResult{}, nil
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"not-configured","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "policy_denied") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if len(fixture.auditor.events) != 1 || fixture.auditor.events[0].EventType != audit.EventRunDenied {
		t.Fatalf("events = %#v", fixture.auditor.events)
	}
}

func TestChatCompletionsAuthAndValidationFailures(t *testing.T) {
	fixture := newAPIFixture(t)
	fixture.backend.fn = func(ctx context.Context, req backend.ChatRequest) (backend.ChatResult, error) {
		t.Fatal("backend must not be called")
		return backend.ChatResult{}, nil
	}

	// Missing auth
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"local-legal","messages":[{"role":"user","content":"hi"}]}`))
	rec := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth status = %d", rec.Code)
	}

	// Query params rejected
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions?x=1", strings.NewReader(`{"model":"local-legal","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("query status = %d", rec.Code)
	}

	// stream true rejected
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"local-legal","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("stream status = %d", rec.Code)
	}
}

func TestModelsFilteredByPolicy(t *testing.T) {
	fixture := newAPIFixture(t)
	fixture.deps.Models = append(fixture.deps.Models, api.ModelRoute{
		Name:         "local-denied",
		BackendModel: "denied-backend",
		Price: budget.ModelPrice{
			InputMicrosPerMillion:  1000,
			OutputMicrosPerMillion: 2000,
			MaxOutputTokens:        16,
		},
	})
	server, err := api.New(fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data) != 1 || payload.Data[0].ID != "local-legal" {
		t.Fatalf("models = %#v", payload.Data)
	}
}

func TestBudgetDenialDoesNotCallBackend(t *testing.T) {
	fixture := newAPIFixture(t)
	fixture.budget.deny = true
	fixture.backend.fn = func(ctx context.Context, req backend.ChatRequest) (backend.ChatResult, error) {
		t.Fatal("backend must not be called")
		return backend.ChatResult{}, nil
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"local-legal","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	fixture.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(fixture.auditor.events) != 1 || fixture.auditor.events[0].DecisionReasonCodes[0] != "budget_denied" {
		t.Fatalf("events = %#v", fixture.auditor.events)
	}
}

func TestOIDCPrincipalAuditsWithIssuerHash(t *testing.T) {
	fixture := newAPIFixture(t)
	issuerHash := [32]byte{9, 8, 7}
	fixture.deps.Authenticate = func(ctx context.Context, authorizationHeader string) (auth.Principal, error) {
		if authorizationHeader != "Bearer oidc-token" {
			return auth.Principal{}, auth.ErrUnauthenticated
		}
		return auth.Principal{
			ID:             testPrincipal,
			AuthMethod:     auth.AuthMethodOIDC,
			Groups:         []string{},
			OIDCIssuerHash: issuerHash,
		}, nil
	}
	// Deny by empty allow set for this endpoint/model via deny engine.
	engine, err := policy.NewEngine(policy.Document{
		Version: "deny-oidc",
		Rules: []policy.Rule{{
			ID:         "deny-all-chat",
			Effect:     policy.EffectDeny,
			Principals: []string{testPrincipal},
			Endpoints:  []string{"chat.completions"},
			Models:     []string{"local-legal"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.deps.Policy = engine
	server, err := api.New(fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"local-legal","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer oidc-token")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if len(fixture.auditor.events) != 1 {
		t.Fatalf("events = %d", len(fixture.auditor.events))
	}
	event := fixture.auditor.events[0]
	if event.AuthMethod != audit.AuthOIDC || event.OIDCIssuerHash == nil || *event.OIDCIssuerHash != audit.Digest(issuerHash) {
		t.Fatalf("event auth evidence = %#v", event)
	}
}

type apiFixture struct {
	server  *api.Server
	deps    api.Dependencies
	backend *fakeBackend
	budget  *fakeBudget
	auditor *fakeAuditor
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	engine, err := policy.NewEngine(policy.Document{
		Version: "api-test-v1",
		Rules: []policy.Rule{
			{
				ID:         "allow-chat",
				Effect:     policy.EffectAllow,
				Principals: []string{testPrincipal},
				Endpoints:  []string{"chat.completions"},
				Models:     []string{"local-legal"},
			},
			{
				ID:         "allow-models",
				Effect:     policy.EffectAllow,
				Principals: []string{testPrincipal},
				Endpoints:  []string{"models.list"},
				Models:     []string{"local-legal"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x11}, audit.ContentHMACKeySize)
	digester, err := audit.NewContentDigester("content-key-v1", key)
	if err != nil {
		t.Fatal(err)
	}
	backendFake := &fakeBackend{}
	budgetFake := &fakeBudget{}
	auditorFake := &fakeAuditor{}
	cfgHash := sha256.Sum256([]byte("config-v1"))
	var cfgDigest audit.Digest
	copy(cfgDigest[:], cfgHash[:])
	deps := api.Dependencies{
		Authenticate: func(ctx context.Context, authorizationHeader string) (auth.Principal, error) {
			if authorizationHeader != "Bearer test-token" {
				return auth.Principal{}, auth.ErrUnauthenticated
			}
			return auth.Principal{ID: testPrincipal, AuthMethod: auth.AuthMethodAPIKey, APIKeyIDPrefix: "aabbccdd", Groups: []string{}}, nil
		},
		Policy:  engine,
		Detect:  detect.Detect,
		Budget:  budgetFake,
		Audit:   auditorFake,
		Backend: backendFake,
		Digester: digester,
		Models: []api.ModelRoute{{
			Name:         "local-legal",
			BackendModel: "qwen-local",
			Price: budget.ModelPrice{
				InputMicrosPerMillion:  1000,
				OutputMicrosPerMillion: 2000,
				MaxOutputTokens:        128,
			},
		}},
		MaxRequestBytes:  1 << 20,
		MaxResponseBytes: 1 << 20,
		ResolvedBackend:  "local-backend",
		ConfigHash:       cfgDigest,
		Now:              func() time.Time { return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC) },
		BudgetTTL:        time.Minute,
	}
	server, err := api.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	return &apiFixture{server: server, deps: deps, backend: backendFake, budget: budgetFake, auditor: auditorFake}
}

type fakeBackend struct {
	fn func(ctx context.Context, req backend.ChatRequest) (backend.ChatResult, error)
}

func (f *fakeBackend) ChatCompletions(ctx context.Context, req backend.ChatRequest) (backend.ChatResult, error) {
	if f.fn == nil {
		return backend.ChatResult{}, backend.ErrUnavailable
	}
	return f.fn(ctx, req)
}

type fakeBudget struct {
	mu        sync.Mutex
	reserved  int64
	committed int64
	deny      bool
	seq       int
}

func (f *fakeBudget) Reserve(ctx context.Context, request budget.ReserveRequest) (budget.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deny {
		return budget.Reservation{}, budget.ErrBudgetDenied
	}
	f.reserved += request.ReservedMaxMicros
	f.seq++
	return budget.Reservation{
		ID:                "00000000-0000-4000-8000-0000000000b1",
		RunID:             request.RunID,
		PrincipalID:       request.PrincipalID,
		ModelName:         request.ModelName,
		ReservedMaxMicros: request.ReservedMaxMicros,
		State:             budget.StateReserved,
		ExpiresAt:         time.Now().UTC().Add(request.TTL),
	}, nil
}

func (f *fakeBudget) Settle(ctx context.Context, request budget.SettleRequest) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	actual := f.reserved
	if request.ActualMicros != nil {
		actual = *request.ActualMicros
	}
	if actual > f.reserved {
		actual = f.reserved
	}
	f.reserved = 0
	f.committed += actual
	return actual, nil
}

type fakeAuditor struct {
	mu     sync.Mutex
	events []audit.Event
	seq    int64
}

func (f *fakeAuditor) Append(ctx context.Context, event audit.Event) (audit.AppendReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := event.Validate(); err != nil {
		return audit.AppendReceipt{}, err
	}
	f.seq++
	f.events = append(f.events, event)
	var hash audit.Digest
	copy(hash[:], bytes.Repeat([]byte{byte(f.seq)}, 32))
	return audit.NewAppendReceipt(f.seq, hash, event.EventType), nil
}

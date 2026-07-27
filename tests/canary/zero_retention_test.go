package canary_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raphbaph/CompliantAI/internal/api"
	"github.com/raphbaph/CompliantAI/internal/audit"
	"github.com/raphbaph/CompliantAI/internal/auth"
	"github.com/raphbaph/CompliantAI/internal/backend"
	"github.com/raphbaph/CompliantAI/internal/budget"
	"github.com/raphbaph/CompliantAI/internal/detect"
	"github.com/raphbaph/CompliantAI/internal/policy"
	"github.com/raphbaph/CompliantAI/internal/safelog"
	"github.com/raphbaph/CompliantAI/tests/canary"
)

const testPrincipal = "00000000-0000-4000-8000-0000000000c1"

func TestZeroRetentionCanarySweep(t *testing.T) {
	markers, err := canary.NewCanaries()
	if err != nil {
		t.Fatalf("NewCanaries: %v", err)
	}
	report := canary.Report{
		Canaries:  markers.All(),
		Encodings: canary.DefaultEncodings(),
	}

	tmpRoot := t.TempDir()
	exportDir := filepath.Join(tmpRoot, "export")
	checkpointDir := filepath.Join(tmpRoot, "checkpoints")
	if err := os.MkdirAll(exportDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(checkpointDir, 0o700); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	logger := safelog.New(&logBuf)

	auditor := &recordingAuditor{}
	budgetSvc := &recordingBudget{}
	backendSvc := &recordingBackend{responseCanary: markers.Response, errorCanary: markers.BackendError}
	fixture := newCanaryAPI(t, markers, logger, auditor, budgetSvc, backendSvc)

	// 1) Allowed path with prompt canary and email-like classification bait.
	allowedBody := fmt.Sprintf(`{"model":"local-legal","messages":[{"role":"user","content":"%s contact max@example.com"}]}`, markers.Prompt)
	status, respBody := doJSON(t, fixture.handler, http.MethodPost, "/v1/chat/completions", "Bearer test-token", allowedBody)
	if status != http.StatusOK {
		t.Fatalf("allowed status=%d body=%s", status, respBody)
	}
	if !strings.Contains(respBody, markers.Response) {
		t.Fatalf("allowed response missing backend canary marker")
	}
	report.PathsExercised = append(report.PathsExercised, "allowed_chat_completions")

	// 2) Policy denied path.
	denyServer := newDenyServer(t, fixture.deps)
	status, _ = doJSON(t, denyServer.Handler(), http.MethodPost, "/v1/chat/completions", "Bearer test-token", allowedBody)
	if status != http.StatusForbidden {
		t.Fatalf("denied status=%d", status)
	}
	report.PathsExercised = append(report.PathsExercised, "policy_denied_chat_completions")

	// 3a) Invalid JSON body containing malformed canary.
	status, body := doJSON(t, fixture.handler, http.MethodPost, "/v1/chat/completions", "Bearer test-token", `{"model":"local-legal","messages":[{"role":"user","content":"`+markers.Malformed+`"`)
	if status != http.StatusBadRequest {
		t.Fatalf("invalid json status=%d body=%s", status, body)
	}
	if strings.Contains(body, markers.Malformed) {
		t.Fatalf("public error echoed malformed canary")
	}
	report.PathsExercised = append(report.PathsExercised, "malformed_json_rejected")

	// 3b) Valid JSON with stream:true rejected.
	status, _ = doJSON(t, fixture.handler, http.MethodPost, "/v1/chat/completions", "Bearer test-token", `{"model":"local-legal","messages":[{"role":"user","content":"`+markers.Malformed+`"}],"stream":true}`)
	if status != http.StatusBadRequest {
		t.Fatalf("stream status=%d", status)
	}
	report.PathsExercised = append(report.PathsExercised, "stream_rejected")

	// 3c) Credential canaries in Authorization header (must fail closed without persistence).
	status, body = doJSON(t, fixture.handler, http.MethodPost, "/v1/chat/completions", "Bearer "+markers.APIKey, allowedBody)
	if status != http.StatusUnauthorized {
		t.Fatalf("api-key canary auth status=%d body=%s", status, body)
	}
	if strings.Contains(body, markers.APIKey) {
		t.Fatalf("public error echoed API key canary")
	}
	report.PathsExercised = append(report.PathsExercised, "api_key_canary_auth_rejected")

	status, body = doJSON(t, fixture.handler, http.MethodPost, "/v1/chat/completions", "Bearer "+markers.JWTClaim, allowedBody)
	if status != http.StatusUnauthorized {
		t.Fatalf("jwt-claim canary auth status=%d body=%s", status, body)
	}
	if strings.Contains(body, markers.JWTClaim) {
		t.Fatalf("public error echoed JWT claim canary")
	}
	report.PathsExercised = append(report.PathsExercised, "jwt_claim_canary_auth_rejected")

	// 4) Oversized body containing canary.
	oversized := `{"model":"local-legal","messages":[{"role":"user","content":"` + markers.Prompt + strings.Repeat("X", int(fixture.deps.MaxRequestBytes)) + `"}]}`
	status, _ = doJSON(t, fixture.handler, http.MethodPost, "/v1/chat/completions", "Bearer test-token", oversized)
	if status != http.StatusRequestEntityTooLarge && status != http.StatusBadRequest {
		t.Fatalf("oversized status=%d", status)
	}
	report.PathsExercised = append(report.PathsExercised, "oversized_request")

	// 5) Backend failure path with content-bearing upstream error canary.
	backendSvc.failNext = true
	status, body = doJSON(t, fixture.handler, http.MethodPost, "/v1/chat/completions", "Bearer test-token",
		fmt.Sprintf(`{"model":"local-legal","messages":[{"role":"user","content":"%s"}]}`, markers.Prompt))
	if status == http.StatusOK {
		t.Fatalf("backend failure returned success: %s", body)
	}
	if strings.Contains(body, markers.BackendError) {
		t.Fatalf("public error echoed backend canary")
	}
	report.PathsExercised = append(report.PathsExercised, "backend_failure")

	// 6) Client disconnect after backend invocation began.
	backendSvc.failNext = false
	release := make(chan struct{})
	started := make(chan struct{})
	backendSvc.blockUntil = release
	backendSvc.onStart = func() {
		select {
		case <-started:
		default:
			close(started)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(
			fmt.Sprintf(`{"model":"local-legal","messages":[{"role":"user","content":"%s"}]}`, markers.Prompt),
		))
		req.Header.Set("Authorization", "Bearer test-token")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req = req.WithContext(ctx)
		rec := httptest.NewRecorder()
		go func() {
			<-started
			cancel()
			close(release)
		}()
		fixture.handler.ServeHTTP(rec, req)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("disconnect path timed out")
	}
	report.PathsExercised = append(report.PathsExercised, "client_disconnect_after_invocation")

	// Write synthetic export/checkpoint files that should contain only digests, not canaries.
	exportPayload, _ := json.Marshal(auditor.events)
	if err := os.WriteFile(filepath.Join(exportDir, "events.json"), exportPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkpointDir, "checkpoint.txt"), []byte("checkpoint-placeholder-no-content\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// --- Sweep enumerated locations ---
	// Response canary is expected only in the live HTTP response (C0 transit), not in durable sinks.
	persistenceCanaries := []string{markers.Prompt, markers.APIKey, markers.JWTClaim, markers.Malformed, markers.BackendError, markers.Response}

	// A) safelog buffer
	report.AddLocation("safelog_buffer")
	for _, hit := range canary.SearchBytes(logBuf.Bytes(), persistenceCanaries) {
		report.NoteFinding("safelog_buffer", hit)
	}

	// B) audit events as JSON (in-memory repository substitute / export input)
	report.AddLocation("in_memory_audit_events_json")
	encodedEvents, _ := json.Marshal(auditor.events)
	for _, hit := range canary.SearchBytes(encodedEvents, persistenceCanaries) {
		report.NoteFinding("in_memory_audit_events_json", hit)
	}

	// C) temp export + checkpoint dirs written by this test
	report.AddLocation("temp_export_dir")
	report.AddLocation("temp_checkpoint_dir")
	for _, dir := range []string{exportDir, checkpointDir} {
		hits, _, err := canary.SearchDir(dir, persistenceCanaries, 1000)
		if err != nil {
			t.Fatalf("SearchDir %s: %v", dir, err)
		}
		for path, found := range hits {
			for _, c := range found {
				report.NoteFinding(path, c)
			}
		}
	}

	// D) fake service debug dumps (non-durable collaborators)
	report.AddLocation("budget_service_debug")
	for _, hit := range canary.SearchText(fmt.Sprintf("%#v", budgetSvc), persistenceCanaries) {
		report.NoteFinding("budget_service_debug", hit)
	}
	// Backend fixture fields intentionally hold canary constants for injection; only the
	// retained response buffer is a retention concern. Search lastRaw, then clear.
	report.AddLocation("backend_last_raw_before_clear")
	for _, hit := range canary.SearchBytes(backendSvc.snapshotRaw(), []string{markers.Prompt, markers.APIKey, markers.JWTClaim, markers.Malformed, markers.BackendError}) {
		report.NoteFinding("backend_last_raw_before_clear", hit)
	}
	backendSvc.clear()
	report.AddLocation("backend_last_raw_after_clear")
	for _, hit := range canary.SearchBytes(backendSvc.snapshotRaw(), persistenceCanaries) {
		report.NoteFinding("backend_last_raw_after_clear", hit)
	}

	// E) live PostgreSQL text/varchar/json columns when DSN is provided.
	if dsn := os.Getenv("TEST_GATEWAY_DSN"); dsn != "" {
		report.AddLocation("postgresql_public_text_varchar_json_columns")
		report.Encodings = append(report.Encodings, "postgresql CAST(column AS text) substring via LIKE")
		ctx := context.Background()
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("pgxpool: %v", err)
		}
		defer pool.Close()
		rows, err := pool.Query(ctx, `
			SELECT table_schema, table_name, column_name
			FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND data_type IN ('text', 'character varying', 'jsonb', 'json')
		`)
		if err != nil {
			t.Fatalf("list columns: %v", err)
		}
		type col struct{ schema, table, column string }
		var cols []col
		for rows.Next() {
			var c col
			if err := rows.Scan(&c.schema, &c.table, &c.column); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		rows.Close()
		for _, c := range cols {
			q := fmt.Sprintf(`SELECT COUNT(*) FROM %s.%s WHERE CAST(%s AS text) LIKE '%%' || $1 || '%%'`, c.schema, c.table, c.column)
			for _, marker := range persistenceCanaries {
				var n int64
				if err := pool.QueryRow(ctx, q, marker).Scan(&n); err != nil {
					continue
				}
				if n > 0 {
					report.NoteFinding(fmt.Sprintf("%s.%s.%s", c.schema, c.table, c.column), marker)
				}
			}
		}
	} else {
		report.AddLocation("postgresql_public_text_varchar_json_columns(skipped_no_TEST_GATEWAY_DSN)")
	}

	// F) test temp root
	report.AddLocation("test_temp_root")
	hits, _, err := canary.SearchDir(tmpRoot, persistenceCanaries, 2000)
	if err != nil {
		t.Fatalf("SearchDir tmp: %v", err)
	}
	for path, found := range hits {
		for _, c := range found {
			report.NoteFinding(path, c)
		}
	}

	// Persist report for evidence pack consumers (no canary values repeated beyond the marker list).
	reportPath := filepath.Join(tmpRoot, "canary-report.json")
	rawReport, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(reportPath, rawReport, 0o600); err != nil {
		t.Fatal(err)
	}

	if len(report.Findings) != 0 {
		t.Fatalf("canary findings: %v\nreport=%s", report.Findings, rawReport)
	}
	t.Log(canary.ValidWording)
	t.Logf("locations=%v encodings=%v paths=%v", report.Locations, report.Encodings, report.PathsExercised)
}

type canaryAPI struct {
	handler http.Handler
	deps    api.Dependencies
}

func newCanaryAPI(t *testing.T, markers canary.Canaries, logger *safelog.Logger, auditor *recordingAuditor, budgetSvc *recordingBudget, backendSvc *recordingBackend) *canaryAPI {
	t.Helper()
	engine, err := policy.NewEngine(policy.Document{
		Version: "canary-v1",
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
	key := bytes.Repeat([]byte{0x42}, audit.ContentHMACKeySize)
	digester, err := audit.NewContentDigester("content-key-v1", key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("canary-config"))
	var cfgHash audit.Digest
	copy(cfgHash[:], sum[:])
	deps := api.Dependencies{
		Authenticate: func(ctx context.Context, authorizationHeader string) (auth.Principal, error) {
			// Accept fixed token; API-key canary must not be the live credential string stored anywhere.
			if authorizationHeader != "Bearer test-token" {
				// Ensure JWT-claim canary is not used as principal material.
				if strings.Contains(authorizationHeader, markers.JWTClaim) || strings.Contains(authorizationHeader, markers.APIKey) {
					return auth.Principal{}, auth.ErrUnauthenticated
				}
				return auth.Principal{}, auth.ErrUnauthenticated
			}
			return auth.Principal{ID: testPrincipal, AuthMethod: auth.AuthMethodAPIKey, APIKeyIDPrefix: "cafebabe", Groups: []string{}}, nil
		},
		Policy:           engine,
		Detect:           detect.Detect,
		Budget:           budgetSvc,
		Audit:            auditor,
		Backend:          backendSvc,
		Digester:         digester,
		Models: []api.ModelRoute{{
			Name:         "local-legal",
			BackendModel: "qwen-local",
			Price: budget.ModelPrice{
				InputMicrosPerMillion:  1000,
				OutputMicrosPerMillion: 2000,
				MaxOutputTokens:        64,
			},
		}},
		MaxRequestBytes:  4096,
		MaxResponseBytes: 1 << 20,
		ResolvedBackend:  "local-backend",
		ConfigHash:       cfgHash,
		Logger:           logger,
		Now:              func() time.Time { return time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC) },
		BudgetTTL:        time.Minute,
	}
	server, err := api.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	return &canaryAPI{handler: server.Handler(), deps: deps}
}

func newDenyServer(t *testing.T, base api.Dependencies) *api.Server {
	t.Helper()
	engine, err := policy.NewEngine(policy.Document{
		Version: "canary-deny",
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
	base.Policy = engine
	server, err := api.New(base)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func doJSON(t *testing.T, handler http.Handler, method, path, authz, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

type recordingAuditor struct {
	mu     sync.Mutex
	events []audit.Event
	seq    int64
}

func (a *recordingAuditor) Append(ctx context.Context, event audit.Event) (audit.AppendReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := event.Validate(); err != nil {
		return audit.AppendReceipt{}, err
	}
	a.seq++
	a.events = append(a.events, event)
	var hash audit.Digest
	copy(hash[:], bytes.Repeat([]byte{byte(a.seq)}, 32))
	return audit.NewAppendReceipt(a.seq, hash, event.EventType), nil
}

type recordingBudget struct {
	mu        sync.Mutex
	reserved  int64
	committed int64
}

func (b *recordingBudget) Reserve(ctx context.Context, request budget.ReserveRequest) (budget.Reservation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reserved += request.ReservedMaxMicros
	return budget.Reservation{
		ID:                "00000000-0000-4000-8000-0000000000d1",
		RunID:             request.RunID,
		PrincipalID:       request.PrincipalID,
		ModelName:         request.ModelName,
		ReservedMaxMicros: request.ReservedMaxMicros,
		State:             budget.StateReserved,
		ExpiresAt:         time.Now().UTC().Add(request.TTL),
	}, nil
}

func (b *recordingBudget) Settle(ctx context.Context, request budget.SettleRequest) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	actual := b.reserved
	if request.ActualMicros != nil {
		actual = *request.ActualMicros
	}
	if actual > b.reserved {
		actual = b.reserved
	}
	b.reserved = 0
	b.committed += actual
	return actual, nil
}

type recordingBackend struct {
	mu             sync.Mutex
	responseCanary string
	errorCanary    string
	failNext       bool
	blockUntil     chan struct{}
	onStart        func()
	lastRaw        []byte
}

func (b *recordingBackend) ChatCompletions(ctx context.Context, req backend.ChatRequest) (backend.ChatResult, error) {
	b.mu.Lock()
	fail := b.failNext
	block := b.blockUntil
	onStart := b.onStart
	b.failNext = false
	b.blockUntil = nil
	b.onStart = nil
	b.mu.Unlock()

	if onStart != nil {
		onStart()
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			// Backend client detaches cancel; still wait for release for test control.
			<-block
		}
	}
	if fail {
		return backend.ChatResult{}, fmt.Errorf("%w: %s", backend.ErrUnavailable, b.errorCanary)
	}
	raw := []byte(fmt.Sprintf(
		`{"id":"chatcmpl-canary","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`,
		b.responseCanary,
	))
	b.mu.Lock()
	b.lastRaw = append([]byte(nil), raw...)
	b.mu.Unlock()
	return backend.ChatResult{
		ID:      "chatcmpl-canary",
		Content: b.responseCanary,
		Usage:   backend.Usage{PromptTokens: 3, CompletionTokens: 2, TotalTokens: 5},
		RawJSON: raw,
	}, nil
}

func (b *recordingBackend) clear() {
	b.mu.Lock()
	b.lastRaw = nil
	b.mu.Unlock()
}

func (b *recordingBackend) snapshotRaw() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lastRaw == nil {
		return nil
	}
	out := make([]byte, len(b.lastRaw))
	copy(out, b.lastRaw)
	return out
}

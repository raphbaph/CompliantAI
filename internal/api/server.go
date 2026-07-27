package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/raphbaph/CompliantAI/internal/audit"
	"github.com/raphbaph/CompliantAI/internal/auth"
	"github.com/raphbaph/CompliantAI/internal/backend"
	"github.com/raphbaph/CompliantAI/internal/budget"
	"github.com/raphbaph/CompliantAI/internal/detect"
	"github.com/raphbaph/CompliantAI/internal/policy"
	"github.com/raphbaph/CompliantAI/internal/safelog"
	"github.com/raphbaph/CompliantAI/internal/version"
)

// Dependencies are the injected collaborators for the V1 HTTP surface.
type Dependencies struct {
	Authenticate     func(ctx context.Context, authorizationHeader string) (auth.Principal, error)
	Policy           *policy.Engine
	Detect           func(text string) (detect.Result, error)
	Budget           BudgetService
	Audit            Auditor
	Backend          BackendClient
	Digester         *audit.ContentDigester
	Models           []ModelRoute
	MaxRequestBytes  int64
	MaxResponseBytes int64
	ResolvedBackend  string
	ConfigHash       audit.Digest
	Logger           *safelog.Logger
	Now              func() time.Time
	BudgetTTL        time.Duration
}

// ModelRoute maps a public model name to backend model and pricing.
type ModelRoute struct {
	Name         string
	BackendModel string
	Price        budget.ModelPrice
}

// BudgetService is the reserve/settle surface used by the API.
type BudgetService interface {
	Reserve(ctx context.Context, request budget.ReserveRequest) (budget.Reservation, error)
	Settle(ctx context.Context, request budget.SettleRequest) (int64, error)
}

// Auditor appends content-free audit events.
type Auditor interface {
	Append(ctx context.Context, event audit.Event) (audit.AppendReceipt, error)
}

// BackendClient invokes the configured inference backend.
type BackendClient interface {
	ChatCompletions(ctx context.Context, request backend.ChatRequest) (backend.ChatResult, error)
}

// Server is the customer-facing HTTP API.
type Server struct {
	deps Dependencies
	mux  *http.ServeMux
}

// New constructs the V1 API server.
func New(deps Dependencies) (*Server, error) {
	if deps.Authenticate == nil || deps.Policy == nil || deps.Detect == nil ||
		deps.Budget == nil || deps.Audit == nil || deps.Backend == nil || deps.Digester == nil ||
		deps.MaxRequestBytes <= 0 || deps.MaxResponseBytes <= 0 || len(deps.Models) == 0 ||
		deps.ResolvedBackend == "" || deps.Now == nil {
		return nil, errMisconfigured
	}
	if deps.BudgetTTL <= 0 {
		deps.BudgetTTL = 2 * time.Minute
	}
	server := &Server{deps: deps, mux: http.NewServeMux()}
	server.mux.HandleFunc("/v1/chat/completions", server.handleChatCompletions)
	server.mux.HandleFunc("/v1/models", server.handleModels)
	return server, nil
}

// Handler returns the root handler with security headers.
func (server *Server) Handler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("Cache-Control", "no-store")
		if request.URL.RawQuery != "" {
			writeError(writer, http.StatusBadRequest, "invalid_request")
			return
		}
		server.mux.ServeHTTP(writer, request)
	})
}

func (server *Server) handleModels(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	principal, err := server.deps.Authenticate(request.Context(), request.Header.Get("Authorization"))
	if err != nil {
		writeAuthError(writer, err)
		return
	}
	type modelObject struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		OwnedBy string `json:"owned_by"`
	}
	out := struct {
		Object string        `json:"object"`
		Data   []modelObject `json:"data"`
	}{Object: "list", Data: []modelObject{}}
	for _, model := range server.deps.Models {
		decision := server.deps.Policy.Evaluate(policy.Request{
			PrincipalID: principal.ID,
			Groups:      principal.Groups,
			Endpoint:    "models.list",
			Model:       model.Name,
		})
		if decision.Effect != policy.EffectAllow {
			continue
		}
		out.Data = append(out.Data, modelObject{ID: model.Name, Object: "model", OwnedBy: "customer"})
	}
	writeJSON(writer, http.StatusOK, out)
}

func (server *Server) handleChatCompletions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	principal, err := server.deps.Authenticate(request.Context(), request.Header.Get("Authorization"))
	if err != nil {
		writeAuthError(writer, err)
		return
	}

	body, err := io.ReadAll(io.LimitReader(request.Body, server.deps.MaxRequestBytes+1))
	_ = request.Body.Close()
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if int64(len(body)) > server.deps.MaxRequestBytes {
		writeError(writer, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	chatReq, err := backend.ParseChatRequest(body)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	// Unknown or unroutable models use the same denial surface as policy deny
	// so configured model names are not revealed by status/code splits.
	route, ok := server.lookupModel(chatReq.Model)
	if !ok {
		decision := server.deps.Policy.Evaluate(policy.Request{
			PrincipalID: principal.ID,
			Groups:      principal.Groups,
			Endpoint:    "chat.completions",
			Model:       chatReq.Model,
		})
		if decision.Effect == policy.EffectAllow {
			decision.Effect = policy.EffectDeny
			decision.ReasonCodes = []string{"no_matching_allow"}
		}
		runID := newUUID()
		now := server.deps.Now().UTC().Truncate(time.Microsecond)
		requestHMAC, err := server.deps.Digester.Sum(body)
		if err != nil {
			writeError(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		classification, err := server.deps.Detect(joinMessageText(chatReq))
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_request")
			return
		}
		if err := server.appendDenied(request.Context(), principal, runID, "unknown_model", decision, requestHMAC, int64(len(body)), classification, now); err != nil {
			writeError(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writeError(writer, http.StatusForbidden, "policy_denied")
		return
	}

	requestHMAC, err := server.deps.Digester.Sum(body)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	classification, err := server.deps.Detect(joinMessageText(chatReq))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}

	decision := server.deps.Policy.Evaluate(policy.Request{
		PrincipalID: principal.ID,
		Groups:      principal.Groups,
		Endpoint:    "chat.completions",
		Model:       route.Name,
	})
	runID := newUUID()
	now := server.deps.Now().UTC().Truncate(time.Microsecond)

	if decision.Effect != policy.EffectAllow {
		if err := server.appendDenied(request.Context(), principal, runID, route.Name, decision, requestHMAC, int64(len(body)), classification, now); err != nil {
			writeError(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writeError(writer, http.StatusForbidden, "policy_denied")
		return
	}

	// Conservative input token estimate from request bytes.
	inputTokens := int64(len(body)/4 + 1)
	reserveMicros, err := budget.EstimateMaxCostMicros(route.Price, inputTokens)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	reservation, err := server.deps.Budget.Reserve(request.Context(), budget.ReserveRequest{
		PrincipalID:       principal.ID,
		RunID:             runID,
		ModelName:         route.Name,
		ReservedMaxMicros: reserveMicros,
		TTL:               server.deps.BudgetTTL,
	})
	if err != nil {
		if errors.Is(err, budget.ErrBudgetDenied) {
			budgetDecision := policy.Decision{
				Effect:        policy.EffectDeny,
				ReasonCodes:   []string{"budget_denied"},
				PolicyVersion: decision.PolicyVersion,
				PolicyDigest:  decision.PolicyDigest,
				Context:       decision.Context,
			}
			if err := server.appendDenied(request.Context(), principal, runID, route.Name, budgetDecision, requestHMAC, int64(len(body)), classification, now); err != nil {
				writeError(writer, http.StatusServiceUnavailable, "unavailable")
				return
			}
			writeError(writer, http.StatusPaymentRequired, "budget_denied")
			return
		}
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}

	startEvent, err := server.buildEvent(principal, runID, audit.EventRunStarted, audit.DecisionAllow, audit.StatusStarted, decision, route.Name, requestHMAC, nil, int64(len(body)), nil, classification, &reserveMicros, nil, nil, now)
	if err != nil {
		_, _ = server.deps.Budget.Settle(request.Context(), budget.SettleRequest{ReservationID: reservation.ID, ActualMicros: int64Ptr(0)})
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	startReceipt, err := server.deps.Audit.Append(request.Context(), startEvent)
	if err != nil || !startReceipt.AuthorizesBackendCall() {
		_, _ = server.deps.Budget.Settle(request.Context(), budget.SettleRequest{ReservationID: reservation.ID, ActualMicros: int64Ptr(0)})
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}

	// Backend invocation uses request context; backend client detaches cancel itself.
	backendReq := chatReq
	backendReq.Model = route.BackendModel
	result, backendErr := server.deps.Backend.ChatCompletions(request.Context(), backendReq)

	// Completion path must continue even if the client later disconnects.
	completeCtx := context.WithoutCancel(request.Context())
	completeNow := server.deps.Now().UTC().Truncate(time.Microsecond)
	zero := int64(0)
	if backendErr != nil {
		_, _ = server.deps.Budget.Settle(completeCtx, budget.SettleRequest{ReservationID: reservation.ID, ActualMicros: &zero})
		code := backend.Code(backendErr)
		_ = server.appendFailed(completeCtx, principal, runID, route.Name, decision, requestHMAC, int64(len(body)), classification, reserveMicros, zero, code, completeNow)
		writeError(writer, http.StatusBadGateway, "backend_"+code)
		return
	}
	if int64(len(result.RawJSON)) > server.deps.MaxResponseBytes {
		_, _ = server.deps.Budget.Settle(completeCtx, budget.SettleRequest{ReservationID: reservation.ID, ActualMicros: &zero})
		_ = server.appendFailed(completeCtx, principal, runID, route.Name, decision, requestHMAC, int64(len(body)), classification, reserveMicros, zero, "response_too_large", completeNow)
		writeError(writer, http.StatusBadGateway, "backend_response_too_large")
		return
	}

	responseHMAC, err := server.deps.Digester.Sum(result.RawJSON)
	if err != nil {
		_, _ = server.deps.Budget.Settle(completeCtx, budget.SettleRequest{ReservationID: reservation.ID, ActualMicros: &zero})
		_ = server.appendFailed(completeCtx, principal, runID, route.Name, decision, requestHMAC, int64(len(body)), classification, reserveMicros, zero, "unavailable", completeNow)
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	promptTokens := int64(result.Usage.PromptTokens)
	if promptTokens <= 0 {
		promptTokens = 1
	}
	actualCost, err := budget.ActualCostMicros(route.Price, promptTokens, int64(result.Usage.CompletionTokens))
	if err != nil || actualCost > reserveMicros {
		// Fail closed to reserved max only when usage pricing is unavailable.
		actualCost = reserveMicros
	}
	settled, err := server.deps.Budget.Settle(completeCtx, budget.SettleRequest{ReservationID: reservation.ID, ActualMicros: &actualCost})
	if err != nil {
		_ = server.appendFailed(completeCtx, principal, runID, route.Name, decision, requestHMAC, int64(len(body)), classification, reserveMicros, zero, "unavailable", completeNow)
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	responseBytes := int64(len(result.RawJSON))
	inTok := int64(result.Usage.PromptTokens)
	outTok := int64(result.Usage.CompletionTokens)
	completeEvent, err := server.buildEvent(principal, runID, audit.EventRunCompleted, audit.DecisionAllow, audit.StatusCompleted, decision, route.Name, requestHMAC, &responseHMAC, int64(len(body)), &responseBytes, classification, &reserveMicros, &settled, nil, completeNow)
	if err != nil {
		_ = server.appendFailed(completeCtx, principal, runID, route.Name, decision, requestHMAC, int64(len(body)), classification, reserveMicros, settled, "unavailable", completeNow)
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	completeEvent.InputTokens = &inTok
	completeEvent.OutputTokens = &outTok
	if _, err := server.deps.Audit.Append(completeCtx, completeEvent); err != nil {
		// Do not return model content if completion audit fails.
		_ = server.appendFailed(completeCtx, principal, runID, route.Name, decision, requestHMAC, int64(len(body)), classification, reserveMicros, settled, "unavailable", completeNow)
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(result.RawJSON)
}

func (server *Server) lookupModel(name string) (ModelRoute, bool) {
	for _, model := range server.deps.Models {
		if model.Name == name {
			return model, true
		}
	}
	return ModelRoute{}, false
}

func (server *Server) appendDenied(ctx context.Context, principal auth.Principal, runID, model string, decision policy.Decision, requestHMAC audit.Digest, requestBytes int64, classification detect.Result, now time.Time) error {
	event, err := server.buildEvent(principal, runID, audit.EventRunDenied, audit.DecisionDeny, audit.StatusDenied, decision, model, requestHMAC, nil, requestBytes, nil, classification, nil, nil, nil, now)
	if err != nil {
		return err
	}
	_, err = server.deps.Audit.Append(ctx, event)
	return err
}

func (server *Server) appendFailed(ctx context.Context, principal auth.Principal, runID, model string, decision policy.Decision, requestHMAC audit.Digest, requestBytes int64, classification detect.Result, reserved, actual int64, code string, now time.Time) error {
	event, err := server.buildEvent(principal, runID, audit.EventRunFailed, audit.DecisionAllow, audit.StatusFailed, decision, model, requestHMAC, nil, requestBytes, nil, classification, &reserved, &actual, &code, now)
	if err != nil {
		return err
	}
	_, err = server.deps.Audit.Append(ctx, event)
	return err
}

func (server *Server) buildEvent(
	principal auth.Principal,
	runID string,
	eventType audit.EventType,
	decision audit.Decision,
	status audit.Status,
	policyDecision policy.Decision,
	model string,
	requestHMAC audit.Digest,
	responseHMAC *audit.Digest,
	requestBytes int64,
	responseBytes *int64,
	classification detect.Result,
	reserved, actual *int64,
	errorCode *string,
	now time.Time,
) (audit.Event, error) {
	policyHash, err := digestFromHex(policyDecision.PolicyDigest)
	if err != nil {
		// Fallback to hashing version string if digest missing in tests.
		policyHash = sha256Digest([]byte(server.deps.Policy.Version()))
	}
	detectorHash, err := digestFromHex(classification.BundleDigest)
	if err != nil {
		detectorHash = sha256Digest([]byte(detect.BundleVersion))
	}
	authMethod := audit.AuthAPIKey
	var oidcIssuerHash *audit.Digest
	if principal.AuthMethod == auth.AuthMethodOIDC {
		authMethod = audit.AuthOIDC
		if principal.OIDCIssuerHash == ([32]byte{}) {
			return audit.Event{}, errInvalidDigest
		}
		digest := audit.Digest(principal.OIDCIssuerHash)
		oidcIssuerHash = &digest
	}
	event := audit.Event{
		SchemaVersion:             1,
		EventID:                   newUUID(),
		RunID:                     runID,
		EventType:                 eventType,
		OccurredAt:                now,
		PrincipalID:               principal.ID,
		AuthMethod:                authMethod,
		OIDCIssuerHash:            oidcIssuerHash,
		PolicyVersionHash:         policyHash,
		Decision:                  decision,
		DecisionReasonCodes:       append([]string{}, policyDecision.ReasonCodes...),
		RequestedModel:            model,
		ResolvedBackend:           server.deps.ResolvedBackend,
		ContentHMACKeyID:          server.deps.Digester.KeyID(),
		RequestHMAC:               requestHMAC,
		ResponseHMAC:              responseHMAC,
		RequestBytes:              requestBytes,
		ResponseBytes:             responseBytes,
		PIICategories:             append([]string{}, classification.PIICategories...),
		PIIMatchCounts:            copyCounts(classification.PIIMatchCounts),
		HealthIndicatorCategories: append([]string{}, classification.HealthIndicatorCategories...),
		SecretCategories:          append([]string{}, classification.SecretCategories...),
		DetectorBundleHash:        detectorHash,
		ReservedCostMicros:        reserved,
		ActualCostMicros:          actual,
		Status:                    status,
		ErrorCode:                 errorCode,
		SoftwareVersion:           version.Version,
		ConfigHash:                server.deps.ConfigHash,
	}
	if event.PIICategories == nil {
		event.PIICategories = []string{}
	}
	if event.PIIMatchCounts == nil {
		event.PIIMatchCounts = map[string]int64{}
	}
	if event.HealthIndicatorCategories == nil {
		event.HealthIndicatorCategories = []string{}
	}
	if event.SecretCategories == nil {
		event.SecretCategories = []string{}
	}
	if event.DecisionReasonCodes == nil {
		event.DecisionReasonCodes = []string{}
	}
	return event, nil
}

func joinMessageText(req backend.ChatRequest) string {
	parts := make([]string, 0, len(req.Messages))
	for _, message := range req.Messages {
		parts = append(parts, message.Content)
	}
	return strings.Join(parts, "\n")
}

func writeAuthError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		writeError(writer, http.StatusUnauthorized, "invalid_credentials")
	default:
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
	}
}

func writeError(writer http.ResponseWriter, status int, code string) {
	writeJSON(writer, status, map[string]any{
		"error": map[string]string{
			"message": code,
			"type":    "gateway_error",
			"code":    code,
		},
	})
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

func digestFromHex(value string) (audit.Digest, error) {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return audit.Digest{}, errInvalidDigest
	}
	var digest audit.Digest
	copy(digest[:], raw)
	return digest, nil
}

func sha256Digest(raw []byte) audit.Digest {
	sum := sha256.Sum256(raw)
	var digest audit.Digest
	copy(digest[:], sum[:])
	return digest
}

func copyCounts(in map[string]int64) map[string]int64 {
	if in == nil {
		return map[string]int64{}
	}
	out := make(map[string]int64, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func int64Ptr(value int64) *int64 { return &value }

var (
	errMisconfigured = errors.New("api misconfigured")
	errInvalidDigest = errors.New("invalid digest")
)

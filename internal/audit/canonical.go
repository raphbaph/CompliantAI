package audit

import (
	"encoding/json"
	"sort"
	"time"
)

// Canonical returns the deterministic JSON representation used for chain hashing.
func Canonical(event Event) ([]byte, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	wire := canonicalEvent{
		SchemaVersion:             event.SchemaVersion,
		EventID:                   event.EventID,
		RunID:                     event.RunID,
		EventType:                 event.EventType,
		OccurredAt:                event.OccurredAt.UTC().Format(time.RFC3339Nano),
		PrincipalID:               event.PrincipalID,
		AuthMethod:                event.AuthMethod,
		OIDCIssuerHash:            digestStringPointer(event.OIDCIssuerHash),
		PolicyVersionHash:         event.PolicyVersionHash.String(),
		Decision:                  event.Decision,
		DecisionReasonCodes:       sortedCopy(event.DecisionReasonCodes),
		RequestedModel:            event.RequestedModel,
		ResolvedBackend:           event.ResolvedBackend,
		ContentHMACKeyID:          event.ContentHMACKeyID,
		RequestHMAC:               event.RequestHMAC.String(),
		ResponseHMAC:              digestStringPointer(event.ResponseHMAC),
		RequestBytes:              event.RequestBytes,
		ResponseBytes:             event.ResponseBytes,
		PIICategories:             sortedCopy(event.PIICategories),
		PIIMatchCounts:            mapCopy(event.PIIMatchCounts),
		HealthIndicatorCategories: sortedCopy(event.HealthIndicatorCategories),
		SecretCategories:          sortedCopy(event.SecretCategories),
		DetectorBundleHash:        event.DetectorBundleHash.String(),
		InputTokens:               event.InputTokens,
		OutputTokens:              event.OutputTokens,
		ReservedCostMicros:        event.ReservedCostMicros,
		ActualCostMicros:          event.ActualCostMicros,
		Status:                    event.Status,
		ErrorCode:                 event.ErrorCode,
		PreviousEventHash:         event.PreviousEventHash.String(),
		SoftwareVersion:           event.SoftwareVersion,
		ConfigHash:                event.ConfigHash.String(),
	}
	return json.Marshal(wire)
}

type canonicalEvent struct {
	SchemaVersion             int              `json:"schema_version"`
	EventID                   string           `json:"event_id"`
	RunID                     string           `json:"run_id"`
	EventType                 EventType        `json:"event_type"`
	OccurredAt                string           `json:"occurred_at"`
	PrincipalID               string           `json:"principal_id"`
	AuthMethod                AuthMethod       `json:"auth_method"`
	OIDCIssuerHash            *string          `json:"oidc_issuer_hash"`
	PolicyVersionHash         string           `json:"policy_version_hash"`
	Decision                  Decision         `json:"decision"`
	DecisionReasonCodes       []string         `json:"decision_reason_codes"`
	RequestedModel            string           `json:"requested_model"`
	ResolvedBackend           string           `json:"resolved_backend"`
	ContentHMACKeyID          string           `json:"content_hmac_key_id"`
	RequestHMAC               string           `json:"request_hmac"`
	ResponseHMAC              *string          `json:"response_hmac"`
	RequestBytes              int64            `json:"request_bytes"`
	ResponseBytes             *int64           `json:"response_bytes"`
	PIICategories             []string         `json:"pii_categories"`
	PIIMatchCounts            map[string]int64 `json:"pii_match_counts"`
	HealthIndicatorCategories []string         `json:"health_indicator_categories"`
	SecretCategories          []string         `json:"secret_categories"`
	DetectorBundleHash        string           `json:"detector_bundle_hash"`
	InputTokens               *int64           `json:"input_tokens"`
	OutputTokens              *int64           `json:"output_tokens"`
	ReservedCostMicros        *int64           `json:"reserved_cost_micros"`
	ActualCostMicros          *int64           `json:"actual_cost_micros"`
	Status                    Status           `json:"status"`
	ErrorCode                 *string          `json:"error_code"`
	PreviousEventHash         string           `json:"previous_event_hash"`
	SoftwareVersion           string           `json:"software_version"`
	ConfigHash                string           `json:"config_hash"`
}

func sortedCopy(values []string) []string {
	copied := append([]string{}, values...)
	sort.Strings(copied)
	return copied
}

func mapCopy(values map[string]int64) map[string]int64 {
	copied := make(map[string]int64, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}

func digestStringPointer(digest *Digest) *string {
	if digest == nil {
		return nil
	}
	encoded := digest.String()
	return &encoded
}

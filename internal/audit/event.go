package audit

import (
	"errors"
	"regexp"
	"time"
)

const maxEventCodes = 64

var (
	// ErrInvalidEvent is returned without rejected values when event metadata is invalid.
	ErrInvalidEvent   = errors.New("invalid audit event")
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)
	codePattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// EventType identifies a fixed audit lifecycle transition.
type EventType string

const (
	EventRunStarted   EventType = "run_started"
	EventRunCompleted EventType = "run_completed"
	EventRunFailed    EventType = "run_failed"
	EventRunDenied    EventType = "run_denied"
)

// AuthMethod identifies the fixed authentication mechanism used for a run.
type AuthMethod string

const (
	AuthOIDC     AuthMethod = "oidc"
	AuthAPIKey   AuthMethod = "api_key"
	AuthWorkload AuthMethod = "workload"
)

// Decision is a fixed policy decision.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// Status is a fixed audit lifecycle status.
type Status string

const (
	StatusStarted   Status = "started"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusDenied    Status = "denied"
)

// Event is the content-free V1 audit event hashed into the append-only chain.
type Event struct {
	SchemaVersion             int              `json:"schema_version"`
	EventID                   string           `json:"event_id"`
	RunID                     string           `json:"run_id"`
	EventType                 EventType        `json:"event_type"`
	OccurredAt                time.Time        `json:"occurred_at"`
	PrincipalID               string           `json:"principal_id"`
	AuthMethod                AuthMethod       `json:"auth_method"`
	OIDCIssuerHash            *Digest          `json:"oidc_issuer_hash"`
	PolicyVersionHash         Digest           `json:"policy_version_hash"`
	Decision                  Decision         `json:"decision"`
	DecisionReasonCodes       []string         `json:"decision_reason_codes"`
	RequestedModel            string           `json:"requested_model"`
	ResolvedBackend           string           `json:"resolved_backend"`
	ContentHMACKeyID          string           `json:"content_hmac_key_id"`
	RequestHMAC               Digest           `json:"request_hmac"`
	ResponseHMAC              *Digest          `json:"response_hmac"`
	RequestBytes              int64            `json:"request_bytes"`
	ResponseBytes             *int64           `json:"response_bytes"`
	PIICategories             []string         `json:"pii_categories"`
	PIIMatchCounts            map[string]int64 `json:"pii_match_counts"`
	HealthIndicatorCategories []string         `json:"health_indicator_categories"`
	SecretCategories          []string         `json:"secret_categories"`
	DetectorBundleHash        Digest           `json:"detector_bundle_hash"`
	InputTokens               *int64           `json:"input_tokens"`
	OutputTokens              *int64           `json:"output_tokens"`
	ReservedCostMicros        *int64           `json:"reserved_cost_micros"`
	ActualCostMicros          *int64           `json:"actual_cost_micros"`
	Status                    Status           `json:"status"`
	ErrorCode                 *string          `json:"error_code"`
	PreviousEventHash         Digest           `json:"previous_event_hash"`
	SoftwareVersion           string           `json:"software_version"`
	ConfigHash                Digest           `json:"config_hash"`
}

// Validate checks the content-free V1 audit contract without echoing rejected values.
func (event Event) Validate() error {
	if event.SchemaVersion != 1 ||
		!uuidPattern.MatchString(event.EventID) ||
		!uuidPattern.MatchString(event.RunID) ||
		!uuidPattern.MatchString(event.PrincipalID) ||
		event.OccurredAt.IsZero() ||
		event.OccurredAt.Year() < 1 ||
		event.OccurredAt.Year() > 9999 ||
		event.OccurredAt.Nanosecond()%1000 != 0 ||
		!validEventState(event.EventType, event.Decision, event.Status) ||
		!validAuthEvidence(event.AuthMethod, event.OIDCIssuerHash) ||
		!identifierPattern.MatchString(event.RequestedModel) ||
		!identifierPattern.MatchString(event.ResolvedBackend) ||
		!identifierPattern.MatchString(event.ContentHMACKeyID) ||
		!identifierPattern.MatchString(event.SoftwareVersion) ||
		isZeroDigest(event.PolicyVersionHash) ||
		isZeroDigest(event.RequestHMAC) ||
		isZeroDigest(event.DetectorBundleHash) ||
		isZeroDigest(event.ConfigHash) ||
		event.RequestBytes < 0 ||
		!validOptionalNonNegative(event.ResponseBytes) ||
		!validOptionalNonNegative(event.InputTokens) ||
		!validOptionalNonNegative(event.OutputTokens) ||
		!validOptionalNonNegative(event.ReservedCostMicros) ||
		!validOptionalNonNegative(event.ActualCostMicros) ||
		!validOptionalDigest(event.ResponseHMAC) ||
		!validOptionalCode(event.ErrorCode) ||
		!validCodeSet(event.DecisionReasonCodes) ||
		!validCodeSet(event.PIICategories) ||
		!validCodeSet(event.HealthIndicatorCategories) ||
		!validCodeSet(event.SecretCategories) ||
		!validCountMap(event.PIIMatchCounts) {
		return ErrInvalidEvent
	}
	return nil
}

func validEventState(eventType EventType, decision Decision, status Status) bool {
	switch eventType {
	case EventRunStarted:
		return decision == DecisionAllow && status == StatusStarted
	case EventRunCompleted:
		return decision == DecisionAllow && status == StatusCompleted
	case EventRunFailed:
		return decision == DecisionAllow && status == StatusFailed
	case EventRunDenied:
		return decision == DecisionDeny && status == StatusDenied
	default:
		return false
	}
}

func validAuthMethod(method AuthMethod) bool {
	switch method {
	case AuthOIDC, AuthAPIKey, AuthWorkload:
		return true
	default:
		return false
	}
}

func validAuthEvidence(method AuthMethod, issuerHash *Digest) bool {
	if !validAuthMethod(method) {
		return false
	}
	if method == AuthOIDC {
		return issuerHash != nil && !isZeroDigest(*issuerHash)
	}
	return issuerHash == nil
}

func validCodeSet(values []string) bool {
	if len(values) > maxEventCodes {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !codePattern.MatchString(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validCountMap(values map[string]int64) bool {
	if len(values) > maxEventCodes {
		return false
	}
	for key, value := range values {
		if !codePattern.MatchString(key) || value < 0 {
			return false
		}
	}
	return true
}

func validOptionalCode(value *string) bool {
	return value == nil || codePattern.MatchString(*value)
}

func validOptionalNonNegative(value *int64) bool {
	return value == nil || *value >= 0
}

func validOptionalDigest(value *Digest) bool {
	return value == nil || !isZeroDigest(*value)
}

func isZeroDigest(value Digest) bool {
	return value == Digest{}
}

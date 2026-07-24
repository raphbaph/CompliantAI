package audit

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCanonicalRequiresAuthenticationSpecificIssuerEvidence(t *testing.T) {
	event := canonicalFixture()
	event.OIDCIssuerHash = nil
	if _, err := Canonical(event); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("OIDC event without issuer hash error = %v, want ErrInvalidEvent", err)
	}

	issuerHash := fixtureDigest(9)
	event = canonicalFixture()
	event.AuthMethod = AuthAPIKey
	event.OIDCIssuerHash = &issuerHash
	if _, err := Canonical(event); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("API-key event with issuer hash error = %v, want ErrInvalidEvent", err)
	}
}

func TestCanonicalRequiresContentHMACKeyIdentity(t *testing.T) {
	event := canonicalFixture()
	event.ContentHMACKeyID = ""
	if _, err := Canonical(event); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("missing key ID error = %v, want ErrInvalidEvent", err)
	}
	event.ContentHMACKeyID = "PROMPT CONTENT CANARY"
	if _, err := Canonical(event); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("content-shaped key ID error = %v, want ErrInvalidEvent", err)
	}
}

func TestCanonicalRejectsInvalidOrContentShapedMetadata(t *testing.T) {
	const canary = "PROMPT CONTENT CANARY {do-not-persist}"
	negative := int64(-1)
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "schema version", mutate: func(event *Event) { event.SchemaVersion = 2 }},
		{name: "timestamp range", mutate: func(event *Event) { event.OccurredAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{name: "timestamp precision", mutate: func(event *Event) { event.OccurredAt = time.Date(2026, 1, 1, 0, 0, 0, 1, time.UTC) }},
		{name: "event ID", mutate: func(event *Event) { event.EventID = canary }},
		{name: "event state", mutate: func(event *Event) { event.Decision = DecisionDeny }},
		{name: "requested model", mutate: func(event *Event) { event.RequestedModel = canary }},
		{name: "decision reason", mutate: func(event *Event) { event.DecisionReasonCodes = []string{canary} }},
		{name: "PII category", mutate: func(event *Event) { event.PIICategories = []string{canary} }},
		{name: "PII count key", mutate: func(event *Event) { event.PIIMatchCounts = map[string]int64{canary: 1} }},
		{name: "negative PII count", mutate: func(event *Event) { event.PIIMatchCounts = map[string]int64{"tax_id": -1} }},
		{name: "software version", mutate: func(event *Event) { event.SoftwareVersion = canary }},
		{name: "error code", mutate: func(event *Event) { event.ErrorCode = stringPointer(canary) }},
		{name: "duplicate category", mutate: func(event *Event) { event.PIICategories = []string{"tax_id", "tax_id"} }},
		{name: "negative token count", mutate: func(event *Event) { event.InputTokens = &negative }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := canonicalFixture()
			test.mutate(&event)
			_, err := Canonical(event)
			if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("Canonical() error = %v, want ErrInvalidEvent", err)
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatal("validation error contains rejected content canary")
			}
		})
	}
}

func stringPointer(value string) *string {
	return &value
}

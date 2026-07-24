package audit

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestCanonicalIsStableAcrossEquivalentOrdering(t *testing.T) {
	first := canonicalFixture()
	second := canonicalFixture()
	second.OccurredAt = first.OccurredAt.In(time.FixedZone("fixture-offset", 2*60*60))
	second.DecisionReasonCodes = []string{"region_allowed", "policy_allowed"}
	second.PIICategories = []string{"tax_id", "email_address"}
	second.HealthIndicatorCategories = []string{"diagnosis_indicator", "medication_indicator"}
	second.SecretCategories = []string{"private_key", "api_credential"}
	second.PIIMatchCounts = map[string]int64{}
	second.PIIMatchCounts["tax_id"] = 1
	second.PIIMatchCounts["email_address"] = 2

	firstBytes, err := Canonical(first)
	if err != nil {
		t.Fatalf("Canonical(first): %v", err)
	}
	secondBytes, err := Canonical(second)
	if err != nil {
		t.Fatalf("Canonical(second): %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("canonical bytes differ:\nfirst:  %s\nsecond: %s", firstBytes, secondBytes)
	}
	if first.DecisionReasonCodes[0] != "policy_allowed" || first.PIICategories[0] != "email_address" {
		t.Fatal("Canonical mutated its input event")
	}
}

func TestCanonicalGoldenVector(t *testing.T) {
	canonical, err := Canonical(canonicalFixture())
	if err != nil {
		t.Fatalf("Canonical(): %v", err)
	}
	golden, err := os.ReadFile("testdata/canonical-event-v1.json")
	if err != nil {
		t.Fatalf("read canonical golden vector: %v", err)
	}
	golden = bytes.TrimSpace(golden)
	if !bytes.Equal(canonical, golden) {
		t.Fatalf("canonical event changed:\ngot:  %s\nwant: %s", canonical, golden)
	}
}

func canonicalFixture() Event {
	issuerHash := fixtureDigest(7)
	responseHMAC := fixtureDigest(6)
	responseBytes := int64(256)
	inputTokens := int64(12)
	outputTokens := int64(8)
	reservedCost := int64(300)
	actualCost := int64(220)
	return Event{
		SchemaVersion:             1,
		EventID:                   "00000000-0000-4000-8000-000000000001",
		RunID:                     "00000000-0000-4000-8000-000000000002",
		EventType:                 EventRunCompleted,
		OccurredAt:                time.Date(2026, time.July, 24, 10, 0, 0, 123456000, time.UTC),
		PrincipalID:               "00000000-0000-4000-8000-000000000003",
		AuthMethod:                AuthOIDC,
		OIDCIssuerHash:            &issuerHash,
		PolicyVersionHash:         fixtureDigest(1),
		Decision:                  DecisionAllow,
		DecisionReasonCodes:       []string{"policy_allowed", "region_allowed"},
		RequestedModel:            "local-legal",
		ResolvedBackend:           "local-backend",
		ContentHMACKeyID:          "content-key-v1",
		RequestHMAC:               fixtureDigest(2),
		ResponseHMAC:              &responseHMAC,
		RequestBytes:              128,
		ResponseBytes:             &responseBytes,
		PIICategories:             []string{"email_address", "tax_id"},
		PIIMatchCounts:            map[string]int64{"email_address": 2, "tax_id": 1},
		HealthIndicatorCategories: []string{"medication_indicator", "diagnosis_indicator"},
		SecretCategories:          []string{"api_credential", "private_key"},
		DetectorBundleHash:        fixtureDigest(3),
		InputTokens:               &inputTokens,
		OutputTokens:              &outputTokens,
		ReservedCostMicros:        &reservedCost,
		ActualCostMicros:          &actualCost,
		Status:                    StatusCompleted,
		PreviousEventHash:         fixtureDigest(4),
		SoftwareVersion:           "v0.1.0",
		ConfigHash:                fixtureDigest(5),
	}
}

func fixtureDigest(value byte) Digest {
	var digest Digest
	for index := range digest {
		digest[index] = value
	}
	return digest
}

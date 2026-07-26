package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// BundleVersion identifies the shipped detector rule set.
const BundleVersion = "detect-bundle-v1"

type hitKey struct {
	category string
	ruleID   string
}

type aggregator struct {
	hits map[hitKey]int
}

func newAggregator() *aggregator {
	return &aggregator{hits: make(map[hitKey]int)}
}

func (agg *aggregator) add(category, ruleID string, count int) {
	if count <= 0 {
		return
	}
	key := hitKey{category: category, ruleID: ruleID}
	agg.hits[key] += count
}

func (agg *aggregator) result() Result {
	findings := make([]Finding, 0, len(agg.hits))
	piiCounts := make(map[string]int64)
	healthSet := make(map[string]struct{})
	secretSet := make(map[string]struct{})

	for key, count := range agg.hits {
		findings = append(findings, Finding{
			Category: key.category,
			Count:    count,
			RuleID:   key.ruleID,
		})
		switch {
		case isPIICategory(key.category):
			piiCounts[key.category] += int64(count)
		case isHealthCategory(key.category):
			healthSet[key.category] = struct{}{}
		case isSecretCategory(key.category):
			secretSet[key.category] = struct{}{}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Category == findings[j].Category {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Category < findings[j].Category
	})

	return Result{
		PIICategories:             sortedKeysFromCounts(piiCounts),
		PIIMatchCounts:            piiCounts,
		HealthIndicatorCategories: sortedKeys(healthSet),
		SecretCategories:          sortedKeys(secretSet),
		Findings:                  findings,
		BundleDigest:              bundleDigest(),
	}
}

// Detect classifies a UTF-8 string in memory and returns content-free findings.
func Detect(text string) (Result, error) {
	return DetectBytes([]byte(text))
}

// DetectBytes classifies bounded UTF-8 input bytes in memory.
func DetectBytes(raw []byte) (Result, error) {
	text, err := normalizeInput(raw)
	if err != nil {
		return Result{}, err
	}
	agg := newAggregator()
	detectPII(text, agg)
	detectHealth(text, agg)
	detectSecrets(text, agg)
	return agg.result(), nil
}

func bundleDigest() string {
	// Stable digest over versioned rule inventory (no content).
	rules := []string{
		BundleVersion,
		"email_basic_v1",
		"phone_e164_de_at_v1",
		"iban_checksum_v1",
		"health_diagnosis_terms_v1",
		"health_medication_terms_v1",
		"health_icd_shape_v1",
		"secret_pem_private_key_v1",
		"secret_api_token_shape_v1",
		"secret_jwt_shape_v1",
	}
	sum := sha256.Sum256([]byte(strings.Join(rules, "\n")))
	return hex.EncodeToString(sum[:])
}

func isPIICategory(category string) bool {
	switch category {
	case "email_address", "phone_number", "iban":
		return true
	default:
		return false
	}
}

func isHealthCategory(category string) bool {
	switch category {
	case "diagnosis_indicator", "medication_indicator", "icd_code":
		return true
	default:
		return false
	}
}

func isSecretCategory(category string) bool {
	switch category {
	case "api_credential", "private_key", "jwt_shape":
		return true
	default:
		return false
	}
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sortedKeysFromCounts(counts map[string]int64) []string {
	out := make([]string, 0, len(counts))
	for key := range counts {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

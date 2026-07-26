package detect_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/raphbaph/CompliantAI/internal/detect"
)

func TestDetectFindsSupportedPIIHealthAndSecrets(t *testing.T) {
	input := strings.Join([]string{
		"Contact: max.mustermann@example.com",
		"DE phone +49 151 23456789",
		"AT phone +43 664 1234567",
		"IBAN DE89 3704 0044 0532 0130 00",
		"AT IBAN AT61 1904 3002 3457 3201",
		"Diagnosis: Type 2 diabetes mellitus",
		"Medikation: Metformin 500mg",
		"ICD-10: E11.9",
		"api key sk-testABCDEFGHIJKLMNOPQRSTUV",
		"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg==\n-----END PRIVATE KEY-----",
		"token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
	}, "\n")

	result, err := detect.Detect(input)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	assertCategoryCount(t, result, "email_address", 1)
	assertCategoryCount(t, result, "phone_number", 2)
	assertCategoryCount(t, result, "iban", 2)
	assertHasCategory(t, result.HealthIndicatorCategories, "diagnosis_indicator")
	assertHasCategory(t, result.HealthIndicatorCategories, "medication_indicator")
	assertHasCategory(t, result.HealthIndicatorCategories, "icd_code")
	assertHasCategory(t, result.SecretCategories, "api_credential")
	assertHasCategory(t, result.SecretCategories, "private_key")
	assertHasCategory(t, result.SecretCategories, "jwt_shape")
	if result.BundleDigest == "" || len(result.BundleDigest) != 64 {
		t.Fatalf("bundle digest = %q", result.BundleDigest)
	}
	// Findings must not retain match values.
	serialized := result.String()
	for _, canary := range []string{
		"max.mustermann@example.com",
		"DE89370400440532013000",
		"Metformin",
		"sk-testABCDEFGHIJKLMNOPQRSTUV",
		"BEGIN PRIVATE KEY",
		"eyJhbGciOiJSUzI1NiJ9",
	} {
		if strings.Contains(serialized, canary) {
			t.Fatalf("result retained match material %q via String(): %s", canary, serialized)
		}
	}
	for _, finding := range result.Findings {
		if finding.Category == "" || finding.RuleID == "" || finding.Count <= 0 {
			t.Fatalf("invalid finding %#v", finding)
		}
		if strings.Contains(finding.Category, "@") || strings.Contains(finding.RuleID, "@") {
			t.Fatalf("finding leaked content: %#v", finding)
		}
	}
}

func TestDetectGermanAndAustrianFixtures(t *testing.T) {
	fixtures := loadFixture(t, "de_at_samples.txt")
	result, err := detect.Detect(fixtures)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	assertCategoryCount(t, result, "email_address", 2)
	assertCategoryCount(t, result, "phone_number", 2)
	assertCategoryCount(t, result, "iban", 2)
	assertHasCategory(t, result.HealthIndicatorCategories, "diagnosis_indicator")
	assertHasCategory(t, result.HealthIndicatorCategories, "medication_indicator")
	assertHasCategory(t, result.SecretCategories, "api_credential")
}

func TestDetectRejectsInvalidIBANChecksum(t *testing.T) {
	// Valid structure-ish DE IBAN with wrong checksum digits.
	input := "IBAN DE00 3704 0044 0532 0130 00 and good DE89 3704 0044 0532 0130 00"
	result, err := detect.Detect(input)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	assertCategoryCount(t, result, "iban", 1)
}

func TestDetectFalsePositiveRegressions(t *testing.T) {
	input := strings.Join([]string{
		"please email me later",
		"call room 151",
		"version E11",
		"not a jwt eyJhbGciOi.onlytwo",
		"IBAN XX00 0000 0000 0000 0000 00",
	}, "\n")
	result, err := detect.Detect(input)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(result.PIICategories) != 0 || len(result.HealthIndicatorCategories) != 0 || len(result.SecretCategories) != 0 {
		t.Fatalf("unexpected findings: %#v", result)
	}
}

func TestDetectInvalidUTF8AndLargeInputFailSafely(t *testing.T) {
	_, err := detect.DetectBytes([]byte{0xff, 0xfe, 0xfd})
	if err != detect.ErrInvalidInput {
		t.Fatalf("invalid UTF-8 error = %v, want ErrInvalidInput", err)
	}
	if err != nil && (strings.Contains(err.Error(), "\xff") || bytes.Contains([]byte(err.Error()), []byte{0xff})) {
		t.Fatalf("error leaked input bytes: %q", err)
	}

	large := strings.Repeat("a", detect.MaxInputBytes+1)
	_, err = detect.Detect(large)
	if err != detect.ErrInputTooLarge {
		t.Fatalf("large input error = %v, want ErrInputTooLarge", err)
	}
	if strings.Contains(err.Error(), "aaaa") {
		t.Fatalf("large-input error leaked content")
	}
}

func TestDetectNoMatchSurvivesAggregation(t *testing.T) {
	input := "secret sk-leakCANARYVALUE1234567890 and email leak.canary@example.org"
	result, err := detect.Detect(input)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	blob := result.String()
	if strings.Contains(blob, "sk-leak") || strings.Contains(blob, "leak.canary") {
		t.Fatalf("aggregated result retained match value: %s", blob)
	}
}

func FuzzDetect(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte("DE89370400440532013000"))
	f.Add([]byte{0xff, 0x00, 0xfe})
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := detect.DetectBytes(data)
		if err != nil {
			msg := err.Error()
			if bytes.Contains([]byte(msg), data) && len(data) > 0 {
				t.Fatalf("error contained input")
			}
			switch err {
			case detect.ErrInvalidInput, detect.ErrInputTooLarge:
				return
			default:
				t.Fatalf("unexpected error type: %v", err)
			}
		}
		serialized := result.String()
		if len(data) > 8 && bytes.Contains([]byte(serialized), data) {
			t.Fatalf("result serialization contained raw input")
		}
		for _, finding := range result.Findings {
			if finding.Category == "" || finding.RuleID == "" || finding.Count <= 0 {
				t.Fatalf("invalid finding %#v", finding)
			}
		}
	})
}

func assertCategoryCount(t *testing.T, result detect.Result, category string, want int64) {
	t.Helper()
	got, ok := result.PIIMatchCounts[category]
	if !ok || got != want {
		t.Fatalf("category %s count = %d present=%v, want %d (counts=%v categories=%v)", category, got, ok, want, result.PIIMatchCounts, result.PIICategories)
	}
	assertHasCategory(t, result.PIICategories, category)
}

func assertHasCategory(t *testing.T, categories []string, want string) {
	t.Helper()
	for _, category := range categories {
		if category == want {
			return
		}
	}
	t.Fatalf("categories %#v missing %q", categories, want)
}

func loadFixture(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "tests", "fixtures", "detect", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(raw)
}

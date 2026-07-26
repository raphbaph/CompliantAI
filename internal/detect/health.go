package detect

import (
	"regexp"
	"strings"
)

var (
	icdPattern = regexp.MustCompile(`(?i)\b(?:ICD(?:-?10)?\s*[:#]?\s*)?([A-TV-Z]\d{2}(?:\.\d{1,4})?)\b`)
)

// Indicator terms are matched case-insensitively as whole words.
// These are heuristic indicators only, not legal classifications.
var (
	diagnosisTerms = []string{
		"diagnosis", "diagnose", "diabetes", "hypertonie", "hypertension",
		"depression", "asthma", "migraene", "migraine",
	}
	medicationTerms = []string{
		"medication", "medikation", "prescription", "rezept",
		"metformin", "bisoprolol", "insulin", "ibuprofen", "amoxicillin",
	}
)

func detectHealth(text string, sink *aggregator) {
	lower := strings.ToLower(text)

	if containsAnyWord(lower, diagnosisTerms) {
		sink.add("diagnosis_indicator", "health_diagnosis_terms_v1", 1)
	}
	if containsAnyWord(lower, medicationTerms) {
		sink.add("medication_indicator", "health_medication_terms_v1", 1)
	}

	// ICD-like codes: require ICD marker or dotted form to reduce false positives like "E11".
	for _, match := range icdPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		full := match[0]
		code := match[1]
		if !strings.Contains(strings.ToUpper(full), "ICD") && !strings.Contains(code, ".") {
			continue
		}
		sink.add("icd_code", "health_icd_shape_v1", 1)
	}
}

func containsAnyWord(lowerText string, terms []string) bool {
	for _, term := range terms {
		if containsWord(lowerText, term) {
			return true
		}
	}
	return false
}

func containsWord(lowerText, term string) bool {
	start := 0
	for {
		idx := strings.Index(lowerText[start:], term)
		if idx < 0 {
			return false
		}
		abs := start + idx
		beforeOK := abs == 0 || !isWordChar(rune(lowerText[abs-1]))
		after := abs + len(term)
		afterOK := after == len(lowerText) || !isWordChar(rune(lowerText[after]))
		if beforeOK && afterOK {
			return true
		}
		start = abs + len(term)
	}
}

func isWordChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r >= 0x80
}

package detect

import "errors"

// MaxInputBytes bounds detector input to keep classification in memory-safe.
const MaxInputBytes = 1 << 20

var (
	// ErrInvalidInput is returned for invalid UTF-8 without echoing bytes.
	ErrInvalidInput = errors.New("detector input invalid")
	// ErrInputTooLarge is returned when input exceeds MaxInputBytes.
	ErrInputTooLarge = errors.New("detector input too large")
)

// Finding is a content-free detector hit aggregated by category and rule.
type Finding struct {
	Category string
	Count    int
	RuleID   string
}

// Result is the content-free classification output for audit/policy consumers.
type Result struct {
	PIICategories             []string
	PIIMatchCounts            map[string]int64
	HealthIndicatorCategories []string
	SecretCategories          []string
	Findings                  []Finding
	BundleDigest              string
}

// String returns a redacted summary that never includes match values.
func (result Result) String() string {
	return "detect.Result{content_free}"
}

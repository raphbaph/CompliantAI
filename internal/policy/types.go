package policy

import (
	"errors"
	"regexp"
)

// Effect is a fixed allow/deny policy effect.
type Effect string

const (
	// EffectAllow permits a matching request.
	EffectAllow Effect = "allow"
	// EffectDeny denies a matching request with precedence over allows.
	EffectDeny Effect = "deny"
)

// Stable decision reason codes. Values must satisfy the audit code contract.
const (
	ReasonPolicyAllowed   = "policy_allowed"
	ReasonNoMatchingAllow = "no_matching_allow"
	ReasonExplicitDeny    = "explicit_deny"
)

var (
	// ErrInvalidDocument is returned without rejected values when a policy document is invalid.
	ErrInvalidDocument = errors.New("invalid policy document")

	versionPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	ruleIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	principalPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	groupPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	endpointPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	modelPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

const (
	maxRules            = 256
	maxSelectorsPerRule = 64
)

// Document is the typed V1 inference authorization policy.
// It is immutable after Engine construction; V1 has no hot reload.
type Document struct {
	Version string `json:"version" yaml:"version"`
	Rules   []Rule `json:"rules" yaml:"rules"`
}

// Rule is one exact-scope authorization statement.
// A rule matches when identity (principal and/or group), endpoint, and model all match.
// At least one of Principals or Groups must be non-empty.
type Rule struct {
	ID         string   `json:"id" yaml:"id"`
	Effect     Effect   `json:"effect" yaml:"effect"`
	Principals []string `json:"principals,omitempty" yaml:"principals,omitempty"`
	Groups     []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	Endpoints  []string `json:"endpoints" yaml:"endpoints"`
	Models     []string `json:"models" yaml:"models"`
}

// Request is the content-free authorization input.
type Request struct {
	PrincipalID string
	Groups      []string
	Endpoint    string
	Model       string
}

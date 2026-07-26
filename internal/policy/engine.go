package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
)

// Engine is an immutable, default-deny authorization evaluator.
// V1 does not support hot reload; construct a new engine after process restart.
type Engine struct {
	version string
	digest  string
	rules   []Rule
}

// NewEngine validates and freezes a policy document.
func NewEngine(document Document) (*Engine, error) {
	normalized, err := normalizeDocument(document)
	if err != nil {
		return nil, err
	}
	digest, err := digestDocument(normalized)
	if err != nil {
		return nil, ErrInvalidDocument
	}
	rules := make([]Rule, len(normalized.Rules))
	copy(rules, normalized.Rules)
	return &Engine{
		version: normalized.Version,
		digest:  digest,
		rules:   rules,
	}, nil
}

// Version returns the explicit policy version string.
func (engine *Engine) Version() string {
	if engine == nil {
		return ""
	}
	return engine.version
}

// Digest returns the canonical SHA-256 hex digest of the frozen policy document.
func (engine *Engine) Digest() string {
	if engine == nil {
		return ""
	}
	return engine.digest
}

// Evaluate applies default-deny authorization with deny precedence.
func (engine *Engine) Evaluate(request Request) Decision {
	context := DecisionContext{
		PrincipalID:    request.PrincipalID,
		Groups:         cloneStrings(request.Groups),
		Endpoint:       request.Endpoint,
		Model:          request.Model,
		MatchedRuleIDs: []string{},
	}
	if engine == nil {
		return denyDecision("", "", context, ReasonNoMatchingAllow)
	}

	if !principalPattern.MatchString(request.PrincipalID) ||
		!endpointPattern.MatchString(request.Endpoint) ||
		!modelPattern.MatchString(request.Model) ||
		!validRequestGroups(request.Groups) {
		return denyDecision(engine.version, engine.digest, context, ReasonNoMatchingAllow)
	}

	matchedAllow := false
	matchedDeny := false
	matchedIDs := make([]string, 0, 4)
	for _, rule := range engine.rules {
		if !ruleMatches(rule, request) {
			continue
		}
		matchedIDs = append(matchedIDs, rule.ID)
		switch rule.Effect {
		case EffectDeny:
			matchedDeny = true
		case EffectAllow:
			matchedAllow = true
		}
	}
	sort.Strings(matchedIDs)
	context.MatchedRuleIDs = matchedIDs

	if matchedDeny {
		return denyDecision(engine.version, engine.digest, context, ReasonExplicitDeny)
	}
	if matchedAllow {
		return Decision{
			Effect:        EffectAllow,
			ReasonCodes:   []string{ReasonPolicyAllowed},
			PolicyVersion: engine.version,
			PolicyDigest:  engine.digest,
			Context:       context,
		}
	}
	return denyDecision(engine.version, engine.digest, context, ReasonNoMatchingAllow)
}

func denyDecision(version, digest string, context DecisionContext, reason string) Decision {
	return Decision{
		Effect:        EffectDeny,
		ReasonCodes:   []string{reason},
		PolicyVersion: version,
		PolicyDigest:  digest,
		Context:       context,
	}
}

func ruleMatches(rule Rule, request Request) bool {
	if !contains(rule.Endpoints, request.Endpoint) || !contains(rule.Models, request.Model) {
		return false
	}
	principalOK := len(rule.Principals) == 0 || contains(rule.Principals, request.PrincipalID)
	groupOK := len(rule.Groups) == 0 || intersects(rule.Groups, request.Groups)
	// Identity requires an explicit principal and/or group selector to match.
	if len(rule.Principals) == 0 && len(rule.Groups) == 0 {
		return false
	}
	if len(rule.Principals) > 0 && len(rule.Groups) > 0 {
		return principalOK && groupOK
	}
	if len(rule.Principals) > 0 {
		return principalOK
	}
	return groupOK
}

func normalizeDocument(document Document) (Document, error) {
	if !versionPattern.MatchString(document.Version) || len(document.Rules) == 0 || len(document.Rules) > maxRules {
		return Document{}, ErrInvalidDocument
	}
	normalized := Document{
		Version: document.Version,
		Rules:   make([]Rule, 0, len(document.Rules)),
	}
	seenIDs := make(map[string]struct{}, len(document.Rules))
	for _, rule := range document.Rules {
		clean, err := normalizeRule(rule)
		if err != nil {
			return Document{}, err
		}
		if _, exists := seenIDs[clean.ID]; exists {
			return Document{}, ErrInvalidDocument
		}
		seenIDs[clean.ID] = struct{}{}
		normalized.Rules = append(normalized.Rules, clean)
	}
	// Canonical rule order for stable digests.
	sort.SliceStable(normalized.Rules, func(i, j int) bool {
		return normalized.Rules[i].ID < normalized.Rules[j].ID
	})
	return normalized, nil
}

func normalizeRule(rule Rule) (Rule, error) {
	if !ruleIDPattern.MatchString(rule.ID) {
		return Rule{}, ErrInvalidDocument
	}
	if rule.Effect != EffectAllow && rule.Effect != EffectDeny {
		return Rule{}, ErrInvalidDocument
	}
	principals, err := normalizeSelector(rule.Principals, principalPattern, maxSelectorsPerRule)
	if err != nil {
		return Rule{}, err
	}
	groups, err := normalizeSelector(rule.Groups, groupPattern, maxSelectorsPerRule)
	if err != nil {
		return Rule{}, err
	}
	if len(principals) == 0 && len(groups) == 0 {
		return Rule{}, ErrInvalidDocument
	}
	endpoints, err := normalizeSelector(rule.Endpoints, endpointPattern, maxSelectorsPerRule)
	if err != nil || len(endpoints) == 0 {
		return Rule{}, ErrInvalidDocument
	}
	models, err := normalizeSelector(rule.Models, modelPattern, maxSelectorsPerRule)
	if err != nil || len(models) == 0 {
		return Rule{}, ErrInvalidDocument
	}
	return Rule{
		ID:         rule.ID,
		Effect:     rule.Effect,
		Principals: principals,
		Groups:     groups,
		Endpoints:  endpoints,
		Models:     models,
	}, nil
}

func normalizeSelector(values []string, pattern *regexp.Regexp, max int) ([]string, error) {
	if values == nil {
		return []string{}, nil
	}
	if len(values) > max {
		return nil, ErrInvalidDocument
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !pattern.MatchString(value) {
			return nil, ErrInvalidDocument
		}
		if _, exists := seen[value]; exists {
			return nil, ErrInvalidDocument
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func digestDocument(document Document) (string, error) {
	// Marshal canonical normalized struct; fields are already sorted.
	payload, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func validRequestGroups(groups []string) bool {
	if groups == nil {
		return false
	}
	if len(groups) > maxSelectorsPerRule {
		return false
	}
	seen := make(map[string]struct{}, len(groups))
	previous := ""
	for index, group := range groups {
		if !groupPattern.MatchString(group) {
			return false
		}
		if _, exists := seen[group]; exists {
			return false
		}
		seen[group] = struct{}{}
		if index > 0 && group <= previous {
			return false
		}
		previous = group
	}
	return true
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func intersects(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(left))
	for _, value := range left {
		set[value] = struct{}{}
	}
	for _, value := range right {
		if _, ok := set[value]; ok {
			return true
		}
	}
	return false
}

func cloneStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

package auth

import (
	"errors"
	"regexp"
	"sort"
)

// AuthMethod identifies the credential type that established a principal.
type AuthMethod string

const (
	// AuthMethodAPIKey identifies a principal authenticated by a transitional API key.
	AuthMethodAPIKey AuthMethod = "api_key"
	// AuthMethodOIDC identifies a principal authenticated by a validated customer OIDC JWT.
	AuthMethodOIDC AuthMethod = "oidc"

	maxOIDCGroups     = 32
	maxOIDCGroupBytes = 128
)

var (
	// ErrInvalidPrincipal is returned without exposing rejected identity data.
	ErrInvalidPrincipal  = errors.New("invalid principal")
	principalUUIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	apiKeyPrefixPattern    = regexp.MustCompile(`^[0-9a-f]{8}$`)
	oidcGroupPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	oidcGroupClaimPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_./-]{0,63}$`)
)

// Principal is the minimal authenticated identity passed to later policy and audit stages.
type Principal struct {
	ID             string
	AuthMethod     AuthMethod
	APIKeyIDPrefix string
	Groups         []string
}

// Validate checks the bounded content-free principal contract.
func (principal Principal) Validate() error {
	if !principalUUIDPattern.MatchString(principal.ID) {
		return ErrInvalidPrincipal
	}
	switch principal.AuthMethod {
	case AuthMethodAPIKey:
		if !apiKeyPrefixPattern.MatchString(principal.APIKeyIDPrefix) || principal.Groups == nil || len(principal.Groups) != 0 {
			return ErrInvalidPrincipal
		}
		return nil
	case AuthMethodOIDC:
		if principal.APIKeyIDPrefix != "" || !validOIDCGroups(principal.Groups) {
			return ErrInvalidPrincipal
		}
		return nil
	default:
		return ErrInvalidPrincipal
	}
}

func validOIDCGroups(groups []string) bool {
	if groups == nil {
		return false
	}
	if len(groups) > maxOIDCGroups {
		return false
	}
	seen := make(map[string]struct{}, len(groups))
	previous := ""
	for index, group := range groups {
		if group == "" || len(group) > maxOIDCGroupBytes || !oidcGroupPattern.MatchString(group) {
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

func normalizeOIDCGroups(groups []string) ([]string, bool) {
	if groups == nil {
		return []string{}, true
	}
	if len(groups) > maxOIDCGroups {
		return nil, false
	}
	normalized := make([]string, 0, len(groups))
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		if group == "" || len(group) > maxOIDCGroupBytes || !oidcGroupPattern.MatchString(group) {
			return nil, false
		}
		if _, exists := seen[group]; exists {
			continue
		}
		seen[group] = struct{}{}
		normalized = append(normalized, group)
	}
	sort.Strings(normalized)
	return normalized, true
}

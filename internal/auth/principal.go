package auth

import (
	"errors"
	"regexp"
)

// AuthMethod identifies the credential type that established a principal.
type AuthMethod string

const (
	// AuthMethodAPIKey identifies a principal authenticated by a transitional API key.
	AuthMethodAPIKey AuthMethod = "api_key"
)

var (
	// ErrInvalidPrincipal is returned without exposing rejected identity data.
	ErrInvalidPrincipal  = errors.New("invalid principal")
	principalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
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
	if !principalUUIDPattern.MatchString(principal.ID) || principal.AuthMethod != AuthMethodAPIKey || len(principal.APIKeyIDPrefix) != 8 || len(principal.Groups) != 0 {
		return ErrInvalidPrincipal
	}
	return nil
}

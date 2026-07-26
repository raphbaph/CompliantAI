package auth

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	maxOIDCSubjectBytes = 256
	maxBearerTokenBytes = 8192
)

// ErrOIDCPrincipalNotFound is the store sentinel for an unknown issuer/subject pair.
var ErrOIDCPrincipalNotFound = errors.New("OIDC principal not found")

// OIDCPrincipalRecord is the bounded principal state needed after JWT validation.
type OIDCPrincipalRecord struct {
	ID     string
	Active bool
}

// OIDCPrincipalStore resolves a validated issuer/subject pair to a local principal.
type OIDCPrincipalStore interface {
	LookupOIDCPrincipal(ctx context.Context, issuer, subject string) (OIDCPrincipalRecord, error)
}

// OIDCAuthenticationLogger records bounded content-free successful OIDC authentication.
type OIDCAuthenticationLogger interface {
	OIDCAuthenticationSuccess(principalID string) error
}

// PublicKeyProvider supplies signing keys by JWT kid.
type PublicKeyProvider interface {
	PublicKey(ctx context.Context, kid string) (crypto.PublicKey, error)
}

// OIDCAuthenticatorConfig configures fail-closed local OIDC JWT validation.
type OIDCAuthenticatorConfig struct {
	Issuer     string
	Audience   string
	GroupClaim string
	Keys       PublicKeyProvider
	Store      OIDCPrincipalStore
	Logger     OIDCAuthenticationLogger
	Now        func() time.Time
	Leeway     time.Duration
}

// OIDCAuthenticator validates customer OIDC bearer JWTs and maps them to principals.
type OIDCAuthenticator struct {
	issuer     string
	audience   string
	groupClaim string
	keys       PublicKeyProvider
	store      OIDCPrincipalStore
	logger     OIDCAuthenticationLogger
	now        func() time.Time
	leeway     time.Duration
}

// NewOIDCAuthenticator creates a fail-closed OIDC authenticator.
func NewOIDCAuthenticator(cfg OIDCAuthenticatorConfig) (*OIDCAuthenticator, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.GroupClaim == "" || cfg.Keys == nil || cfg.Store == nil || cfg.Logger == nil || cfg.Now == nil {
		return nil, ErrAuthenticationUnavailable
	}
	if !oidcGroupClaimPattern.MatchString(cfg.GroupClaim) {
		return nil, ErrAuthenticationUnavailable
	}
	leeway := cfg.Leeway
	if leeway < 0 || leeway > 2*time.Minute {
		return nil, ErrAuthenticationUnavailable
	}
	return &OIDCAuthenticator{
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		groupClaim: cfg.GroupClaim,
		keys:       cfg.Keys,
		store:      cfg.Store,
		logger:     cfg.Logger,
		now:        cfg.Now,
		leeway:     leeway,
	}, nil
}

// AuthenticateOIDC validates a bearer JWT and returns the mapped active principal.
func (authenticator *OIDCAuthenticator) AuthenticateOIDC(ctx context.Context, bearer string) (Principal, error) {
	if authenticator == nil || authenticator.keys == nil || authenticator.store == nil || authenticator.logger == nil || authenticator.now == nil {
		return Principal{}, ErrAuthenticationUnavailable
	}
	if bearer == "" || len(bearer) > maxBearerTokenBytes || strings.Count(bearer, ".") != 2 {
		return Principal{}, ErrUnauthenticated
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(bearer, claims, func(token *jwt.Token) (any, error) {
		if token == nil {
			return nil, ErrUnauthenticated
		}
		alg, _ := token.Header["alg"].(string)
		switch alg {
		case "RS256", "ES256":
		default:
			return nil, ErrUnauthenticated
		}
		if token.Method == nil || token.Method.Alg() != alg {
			return nil, ErrUnauthenticated
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" || len(kid) > 128 {
			return nil, ErrUnauthenticated
		}
		key, keyErr := authenticator.keys.PublicKey(ctx, kid)
		if keyErr != nil {
			return nil, keyErr
		}
		if key == nil {
			return nil, ErrUnauthenticated
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256", "ES256"}), jwt.WithIssuedAt(), jwt.WithExpirationRequired(), jwt.WithIssuer(authenticator.issuer), jwt.WithAudience(authenticator.audience), jwt.WithLeeway(authenticator.leeway), jwt.WithTimeFunc(authenticator.now))
	if err != nil {
		if errors.Is(err, ErrAuthenticationUnavailable) {
			return Principal{}, ErrAuthenticationUnavailable
		}
		return Principal{}, ErrUnauthenticated
	}
	if token == nil || !token.Valid {
		return Principal{}, ErrUnauthenticated
	}

	subject, err := claims.GetSubject()
	if err != nil || subject == "" || len(subject) > maxOIDCSubjectBytes || strings.ContainsAny(subject, "\r\n\x00") {
		return Principal{}, ErrUnauthenticated
	}
	groups, ok := extractOIDCGroups(claims, authenticator.groupClaim)
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	normalizedGroups, ok := normalizeOIDCGroups(groups)
	if !ok {
		return Principal{}, ErrUnauthenticated
	}

	record, err := authenticator.store.LookupOIDCPrincipal(ctx, authenticator.issuer, subject)
	if errors.Is(err, ErrOIDCPrincipalNotFound) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, ErrAuthenticationUnavailable
	}
	if !record.Active || !principalUUIDPattern.MatchString(record.ID) {
		return Principal{}, ErrUnauthenticated
	}

	principal := Principal{
		ID:         record.ID,
		AuthMethod: AuthMethodOIDC,
		Groups:     normalizedGroups,
	}
	if principal.Validate() != nil {
		return Principal{}, ErrUnauthenticated
	}
	if err := authenticator.logger.OIDCAuthenticationSuccess(principal.ID); err != nil {
		return Principal{}, ErrAuthenticationUnavailable
	}
	return principal, nil
}

func extractOIDCGroups(claims jwt.MapClaims, claimName string) ([]string, bool) {
	raw, exists := claims[claimName]
	if !exists || raw == nil {
		return []string{}, true
	}
	switch value := raw.(type) {
	case string:
		if value == "" {
			return []string{}, true
		}
		return []string{value}, true
	case []string:
		out := make([]string, len(value))
		copy(out, value)
		return out, true
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	default:
		return nil, false
	}
}
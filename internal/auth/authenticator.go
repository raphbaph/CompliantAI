package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

var (
	// ErrUnauthenticated is returned for every caller-controlled API-key rejection.
	ErrUnauthenticated = errors.New("authentication failed")
	// ErrAuthenticationUnavailable reports a fail-closed authentication-store failure.
	ErrAuthenticationUnavailable = errors.New("authentication unavailable")
	// ErrAPIKeyNotFound is the store sentinel for an unknown public key identifier.
	ErrAPIKeyNotFound = errors.New("API key not found")
)

var (
	dummyAPIKeyID       = strings.Repeat("0", apiKeyIDBytes*2)
	dummyAPIKeySecret   = make([]byte, apiKeySecretBytes)
	dummyAPIKeyBearer   = apiKeyBearerPrefix + "." + dummyAPIKeyID + "." + base64.RawURLEncoding.EncodeToString(dummyAPIKeySecret)
	dummyAPIKeyVerifier = encodeVerifier(dummyAPIKeyID, dummyAPIKeySecret)
)

// APIKeyRecord is the bounded credential state needed for runtime verification.
type APIKeyRecord struct {
	KeyID           string
	SecretVerifier  string
	PrincipalID     string
	PrincipalActive bool
	ExpiresAt       time.Time
	Disabled        bool
}

// APIKeyStore supplies credential state and atomically records successful use.
type APIKeyStore interface {
	LookupAPIKey(ctx context.Context, keyID string) (APIKeyRecord, error)
	MarkAPIKeyUsed(ctx context.Context, keyID, principalID string) error
}

// AuthenticationLogger records bounded content-free successful-authentication evidence.
type AuthenticationLogger interface {
	APIKeyAuthenticationSuccess(principalID, keyIDPrefix string) error
}

// APIKeyAuthenticator resolves transitional API-key bearers to principals.
type APIKeyAuthenticator struct {
	store  APIKeyStore
	logger AuthenticationLogger
	now    func() time.Time
}

// NewAPIKeyAuthenticator creates a fail-closed API-key authenticator.
func NewAPIKeyAuthenticator(store APIKeyStore, logger AuthenticationLogger, now func() time.Time) (*APIKeyAuthenticator, error) {
	if store == nil || logger == nil || now == nil {
		return nil, ErrAuthenticationUnavailable
	}
	return &APIKeyAuthenticator{store: store, logger: logger, now: now}, nil
}

// AuthenticateAPIKey verifies a bearer and records successful use before returning a principal.
func (authenticator *APIKeyAuthenticator) AuthenticateAPIKey(ctx context.Context, bearer string) (Principal, error) {
	if authenticator == nil || authenticator.store == nil || authenticator.logger == nil || authenticator.now == nil {
		return Principal{}, ErrAuthenticationUnavailable
	}
	keyID, secret, parsed := parseBearer(bearer)
	verificationBearer := bearer
	if !parsed {
		keyID = dummyAPIKeyID
		verificationBearer = dummyAPIKeyBearer
	} else {
		clear(secret)
	}

	record, err := authenticator.store.LookupAPIKey(ctx, keyID)
	found := true
	if errors.Is(err, ErrAPIKeyNotFound) {
		found = false
		record = APIKeyRecord{KeyID: dummyAPIKeyID, SecretVerifier: dummyAPIKeyVerifier}
	} else if err != nil {
		return Principal{}, ErrAuthenticationUnavailable
	}
	verified := VerifyAPIKey(verificationBearer, record.SecretVerifier)
	if !parsed || !found || record.KeyID != keyID || !verified || !record.PrincipalActive || record.Disabled || record.ExpiresAt.IsZero() || !authenticator.now().Before(record.ExpiresAt) {
		return Principal{}, ErrUnauthenticated
	}
	principal := Principal{ID: record.PrincipalID, AuthMethod: AuthMethodAPIKey, APIKeyIDPrefix: keyID[:8], Groups: []string{}}
	if principal.Validate() != nil {
		return Principal{}, ErrUnauthenticated
	}
	if err := authenticator.store.MarkAPIKeyUsed(ctx, keyID, principal.ID); err != nil {
		if errors.Is(err, ErrAPIKeyNotFound) {
			return Principal{}, ErrUnauthenticated
		}
		return Principal{}, ErrAuthenticationUnavailable
	}
	if err := authenticator.logger.APIKeyAuthenticationSuccess(principal.ID, principal.APIKeyIDPrefix); err != nil {
		return Principal{}, ErrAuthenticationUnavailable
	}
	return principal, nil
}

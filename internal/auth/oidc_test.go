package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type oidcStoreStub struct {
	record    OIDCPrincipalRecord
	err       error
	issuer    string
	subject   string
	lookups   int
}

type oidcLoggerStub struct {
	principalID string
	err         error
}

type staticKeyProvider struct {
	keys map[string]crypto.PublicKey
	err  error
}

func (store *oidcStoreStub) LookupOIDCPrincipal(_ context.Context, issuer, subject string) (OIDCPrincipalRecord, error) {
	store.lookups++
	store.issuer = issuer
	store.subject = subject
	return store.record, store.err
}

func (logger *oidcLoggerStub) OIDCAuthenticationSuccess(principalID string) error {
	logger.principalID = principalID
	return logger.err
}

func (provider staticKeyProvider) PublicKey(_ context.Context, kid string) (crypto.PublicKey, error) {
	if provider.err != nil {
		return nil, provider.err
	}
	key, ok := provider.keys[kid]
	if !ok {
		return nil, ErrUnauthenticated
	}
	return key, nil
}

func TestOIDCAuthenticatorAcceptsValidToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, time.July, 26, 15, 0, 0, 0, time.UTC)
	const (
		issuer      = "https://idp.example.com"
		audience    = "compliant-ai-gateway"
		subject     = "user-subject-1"
		principalID = "00000000-0000-4000-8000-000000000021"
	)
	token := signedOIDCToken(t, privateKey, "kid-1", jwt.MapClaims{
		"iss":    issuer,
		"aud":    audience,
		"sub":    subject,
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"groups": []string{"medical-readers", "legal-reviewers"},
	})
	store := &oidcStoreStub{record: OIDCPrincipalRecord{ID: principalID, Active: true}}
	logger := &oidcLoggerStub{}
	authenticator, err := NewOIDCAuthenticator(OIDCAuthenticatorConfig{
		Issuer:     issuer,
		Audience:   audience,
		GroupClaim: "groups",
		Keys:       staticKeyProvider{keys: map[string]crypto.PublicKey{"kid-1": &privateKey.PublicKey}},
		Store:      store,
		Logger:     logger,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator() error = %v", err)
	}

	principal, err := authenticator.AuthenticateOIDC(context.Background(), token)
	if err != nil {
		t.Fatalf("AuthenticateOIDC() error = %v", err)
	}
	if principal.ID != principalID || principal.AuthMethod != AuthMethodOIDC || principal.APIKeyIDPrefix != "" {
		t.Fatalf("principal = %#v", principal)
	}
	if len(principal.Groups) != 2 || principal.Groups[0] != "legal-reviewers" || principal.Groups[1] != "medical-readers" {
		t.Fatalf("groups = %#v", principal.Groups)
	}
	if store.issuer != issuer || store.subject != subject || store.lookups != 1 {
		t.Fatalf("store lookup = issuer %q subject %q lookups %d", store.issuer, store.subject, store.lookups)
	}
	if logger.principalID != principalID {
		t.Fatalf("logger principal = %q", logger.principalID)
	}
}

func TestOIDCAuthenticatorRejectsCallerControlledFailuresIdentically(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	now := time.Date(2026, time.July, 26, 15, 0, 0, 0, time.UTC)
	const (
		issuer      = "https://idp.example.com"
		audience    = "compliant-ai-gateway"
		subject     = "user-subject-2"
		principalID = "00000000-0000-4000-8000-000000000022"
	)
	validClaims := jwt.MapClaims{
		"iss":    issuer,
		"aud":    audience,
		"sub":    subject,
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"groups": []string{"legal-reviewers"},
	}
	validToken := signedOIDCToken(t, privateKey, "kid-1", validClaims)

	tests := []struct {
		name  string
		token string
		keys  map[string]crypto.PublicKey
		store oidcStoreStub
	}{
		{
			name:  "wrong issuer",
			token: signedOIDCToken(t, privateKey, "kid-1", withClaim(validClaims, "iss", "https://evil.example")),
			keys:  map[string]crypto.PublicKey{"kid-1": &privateKey.PublicKey},
			store: oidcStoreStub{record: OIDCPrincipalRecord{ID: principalID, Active: true}},
		},
		{
			name:  "wrong audience",
			token: signedOIDCToken(t, privateKey, "kid-1", withClaim(validClaims, "aud", "other-audience")),
			keys:  map[string]crypto.PublicKey{"kid-1": &privateKey.PublicKey},
			store: oidcStoreStub{record: OIDCPrincipalRecord{ID: principalID, Active: true}},
		},
		{
			name:  "expired",
			token: signedOIDCToken(t, privateKey, "kid-1", withClaim(validClaims, "exp", now.Add(-time.Minute).Unix())),
			keys:  map[string]crypto.PublicKey{"kid-1": &privateKey.PublicKey},
			store: oidcStoreStub{record: OIDCPrincipalRecord{ID: principalID, Active: true}},
		},
		{
			name:  "none algorithm",
			token: unsignedNoneToken(t, validClaims),
			keys:  map[string]crypto.PublicKey{"kid-1": &privateKey.PublicKey},
			store: oidcStoreStub{record: OIDCPrincipalRecord{ID: principalID, Active: true}},
		},
		{
			name:  "unknown kid",
			token: signedOIDCToken(t, privateKey, "missing", validClaims),
			keys:  map[string]crypto.PublicKey{"kid-1": &privateKey.PublicKey},
			store: oidcStoreStub{record: OIDCPrincipalRecord{ID: principalID, Active: true}},
		},
		{
			name:  "invalid signature",
			token: signedOIDCToken(t, otherKey, "kid-1", validClaims),
			keys:  map[string]crypto.PublicKey{"kid-1": &privateKey.PublicKey},
			store: oidcStoreStub{record: OIDCPrincipalRecord{ID: principalID, Active: true}},
		},
		{
			name:  "unknown principal",
			token: validToken,
			keys:  map[string]crypto.PublicKey{"kid-1": &privateKey.PublicKey},
			store: oidcStoreStub{err: ErrOIDCPrincipalNotFound},
		},
		{
			name:  "disabled principal",
			token: validToken,
			keys:  map[string]crypto.PublicKey{"kid-1": &privateKey.PublicKey},
			store: oidcStoreStub{record: OIDCPrincipalRecord{ID: principalID, Active: false}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logger := &oidcLoggerStub{}
			store := test.store
			authenticator, err := NewOIDCAuthenticator(OIDCAuthenticatorConfig{
				Issuer:     issuer,
				Audience:   audience,
				GroupClaim: "groups",
				Keys:       staticKeyProvider{keys: test.keys},
				Store:      &store,
				Logger:     logger,
				Now:        func() time.Time { return now },
			})
			if err != nil {
				t.Fatalf("NewOIDCAuthenticator() error = %v", err)
			}
			principal, err := authenticator.AuthenticateOIDC(context.Background(), test.token)
			if err != ErrUnauthenticated {
				t.Fatalf("error = %v, want ErrUnauthenticated", err)
			}
			if principal.ID != "" || principal.AuthMethod != "" || principal.Groups != nil {
				t.Fatalf("rejected principal = %#v", principal)
			}
			if logger.principalID != "" {
				t.Fatalf("logger recorded success for rejection")
			}
			if strings.Contains(err.Error(), "eyJ") || strings.Contains(err.Error(), subject) {
				t.Fatalf("error leaked token material: %q", err)
			}
		})
	}
}

func TestOIDCAuthenticatorNeverLogsRawTokenOrClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, time.July, 26, 15, 0, 0, 0, time.UTC)
	const canary = "JWT-CLAIM-CANARY-secret-value"
	token := signedOIDCToken(t, privateKey, "kid-1", jwt.MapClaims{
		"iss":         "https://idp.example.com",
		"aud":         "compliant-ai-gateway",
		"sub":         "user-subject-3",
		"exp":         now.Add(time.Hour).Unix(),
		"iat":         now.Unix(),
		"groups":      []string{"legal-reviewers"},
		"email":       canary,
		"displayName": canary,
	})
	logger := &oidcLoggerStub{}
	authenticator, err := NewOIDCAuthenticator(OIDCAuthenticatorConfig{
		Issuer:     "https://idp.example.com",
		Audience:   "compliant-ai-gateway",
		GroupClaim: "groups",
		Keys:       staticKeyProvider{keys: map[string]crypto.PublicKey{"kid-1": &privateKey.PublicKey}},
		Store:      &oidcStoreStub{record: OIDCPrincipalRecord{ID: "00000000-0000-4000-8000-000000000023", Active: true}},
		Logger:     logger,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator() error = %v", err)
	}
	if _, err := authenticator.AuthenticateOIDC(context.Background(), token); err != nil {
		t.Fatalf("AuthenticateOIDC() error = %v", err)
	}
	if logger.principalID == "" || strings.Contains(logger.principalID, canary) || strings.Contains(logger.principalID, "eyJ") {
		t.Fatalf("logger retained non-allowlisted material: %q", logger.principalID)
	}
}

func signedOIDCToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func unsignedNoneToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	token.Header["kid"] = "kid-1"
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}
	return signed
}

func withClaim(base jwt.MapClaims, key string, value any) jwt.MapClaims {
	cloned := make(jwt.MapClaims, len(base)+1)
	for claimKey, claimValue := range base {
		cloned[claimKey] = claimValue
	}
	cloned[key] = value
	return cloned
}

func TestOIDCAuthenticatorMapsInfrastructureFailures(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, time.July, 26, 15, 0, 0, 0, time.UTC)
	token := signedOIDCToken(t, privateKey, "kid-1", jwt.MapClaims{
		"iss": "https://idp.example.com",
		"aud": "compliant-ai-gateway",
		"sub": "user-subject-4",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	})
	authenticator, err := NewOIDCAuthenticator(OIDCAuthenticatorConfig{
		Issuer:     "https://idp.example.com",
		Audience:   "compliant-ai-gateway",
		GroupClaim: "groups",
		Keys:       staticKeyProvider{err: ErrAuthenticationUnavailable},
		Store:      &oidcStoreStub{record: OIDCPrincipalRecord{ID: "00000000-0000-4000-8000-000000000024", Active: true}},
		Logger:     &oidcLoggerStub{},
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator() error = %v", err)
	}
	principal, err := authenticator.AuthenticateOIDC(context.Background(), token)
	if !errors.Is(err, ErrAuthenticationUnavailable) {
		t.Fatalf("error = %v, want ErrAuthenticationUnavailable", err)
	}
	if principal.ID != "" {
		t.Fatalf("principal = %#v", principal)
	}
}

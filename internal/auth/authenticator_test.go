package auth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type apiKeyStoreStub struct {
	record       APIKeyRecord
	lookupErr    error
	markErr      error
	lookedUpID   string
	markedKeyID  string
	markedUserID string
}

type authenticationLoggerStub struct {
	principalID string
	keyPrefix   string
	err         error
}

func (logger *authenticationLoggerStub) APIKeyAuthenticationSuccess(principalID, keyPrefix string) error {
	logger.principalID = principalID
	logger.keyPrefix = keyPrefix
	return logger.err
}

func (store *apiKeyStoreStub) LookupAPIKey(_ context.Context, keyID string) (APIKeyRecord, error) {
	store.lookedUpID = keyID
	return store.record, store.lookupErr
}

func (store *apiKeyStoreStub) MarkAPIKeyUsed(_ context.Context, keyID, principalID string) error {
	store.markedKeyID = keyID
	store.markedUserID = principalID
	return store.markErr
}

func TestAPIKeyAuthenticatorReturnsCorrectPrincipalAfterUseIsRecorded(t *testing.T) {
	credential, err := generateAPIKey(bytes.NewReader(bytes.Repeat([]byte{0x44}, apiKeyIDBytes+apiKeySecretBytes)))
	if err != nil {
		t.Fatalf("generate API key: %v", err)
	}
	bearer, err := credential.Reveal()
	if err != nil {
		t.Fatalf("reveal API key: %v", err)
	}
	const principalID = "00000000-0000-4000-8000-000000000009"
	now := time.Date(2026, time.July, 24, 18, 30, 0, 0, time.UTC)
	store := &apiKeyStoreStub{record: APIKeyRecord{
		KeyID:           credential.KeyID(),
		SecretVerifier:  credential.Verifier(),
		PrincipalID:     principalID,
		PrincipalActive: true,
		ExpiresAt:       now.Add(time.Hour),
	}}
	logger := &authenticationLoggerStub{}
	authenticator, err := NewAPIKeyAuthenticator(store, logger, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewAPIKeyAuthenticator() error = %v", err)
	}

	principal, err := authenticator.AuthenticateAPIKey(context.Background(), bearer)
	if err != nil {
		t.Fatalf("AuthenticateAPIKey() error = %v", err)
	}
	if principal.ID != principalID || principal.AuthMethod != AuthMethodAPIKey || principal.APIKeyIDPrefix != credential.KeyID()[:8] {
		t.Fatalf("principal = %#v", principal)
	}
	if store.lookedUpID != credential.KeyID() || store.markedKeyID != credential.KeyID() || store.markedUserID != principalID {
		t.Fatalf("store calls = lookup %q, mark %q/%q", store.lookedUpID, store.markedKeyID, store.markedUserID)
	}
	if logger.principalID != principalID || logger.keyPrefix != credential.KeyID()[:8] {
		t.Fatalf("authentication log = %q/%q", logger.principalID, logger.keyPrefix)
	}
}

func TestAPIKeyAuthenticatorRejectsCallerControlledFailuresIdentically(t *testing.T) {
	now := time.Date(2026, time.July, 24, 18, 30, 0, 0, time.UTC)
	credential, err := generateAPIKey(bytes.NewReader(bytes.Repeat([]byte{0x45}, apiKeyIDBytes+apiKeySecretBytes)))
	if err != nil {
		t.Fatalf("generate API key: %v", err)
	}
	bearer, err := credential.Reveal()
	if err != nil {
		t.Fatalf("reveal API key: %v", err)
	}
	validRecord := APIKeyRecord{
		KeyID:           credential.KeyID(),
		SecretVerifier:  credential.Verifier(),
		PrincipalID:     "00000000-0000-4000-8000-000000000010",
		PrincipalActive: true,
		ExpiresAt:       now.Add(time.Hour),
	}

	tests := []struct {
		name   string
		bearer string
		mutate func(*apiKeyStoreStub)
	}{
		{name: "wrong secret", bearer: bearer[:len(bearer)-1] + "A"},
		{name: "malformed", bearer: "not-a-bearer"},
		{name: "unknown", bearer: bearer, mutate: func(store *apiKeyStoreStub) { store.lookupErr = ErrAPIKeyNotFound }},
		{name: "missing expiry", bearer: bearer, mutate: func(store *apiKeyStoreStub) { store.record.ExpiresAt = time.Time{} }},
		{name: "expired", bearer: bearer, mutate: func(store *apiKeyStoreStub) { store.record.ExpiresAt = now }},
		{name: "disabled key", bearer: bearer, mutate: func(store *apiKeyStoreStub) { store.record.Disabled = true }},
		{name: "disabled principal", bearer: bearer, mutate: func(store *apiKeyStoreStub) { store.record.PrincipalActive = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &apiKeyStoreStub{record: validRecord}
			if test.mutate != nil {
				test.mutate(store)
			}
			authenticator, err := NewAPIKeyAuthenticator(store, &authenticationLoggerStub{}, func() time.Time { return now })
			if err != nil {
				t.Fatalf("NewAPIKeyAuthenticator() error = %v", err)
			}
			principal, err := authenticator.AuthenticateAPIKey(context.Background(), test.bearer)
			if !errors.Is(err, ErrUnauthenticated) || err != ErrUnauthenticated {
				t.Fatalf("AuthenticateAPIKey() error = %v, want exact ErrUnauthenticated", err)
			}
			if principal.ID != "" || principal.AuthMethod != "" || principal.APIKeyIDPrefix != "" || principal.Groups != nil {
				t.Fatalf("rejected principal = %#v, want zero value", principal)
			}
			if store.markedKeyID != "" || store.markedUserID != "" {
				t.Fatalf("rejected credential marked as used: %q/%q", store.markedKeyID, store.markedUserID)
			}
		})
	}
}

func TestAPIKeyAuthenticatorTreatsConcurrentRevocationAsUnauthenticated(t *testing.T) {
	now := time.Date(2026, time.July, 24, 18, 30, 0, 0, time.UTC)
	credential, err := generateAPIKey(bytes.NewReader(bytes.Repeat([]byte{0x46}, apiKeyIDBytes+apiKeySecretBytes)))
	if err != nil {
		t.Fatalf("generate API key: %v", err)
	}
	bearer, err := credential.Reveal()
	if err != nil {
		t.Fatalf("reveal API key: %v", err)
	}
	store := &apiKeyStoreStub{
		record: APIKeyRecord{
			KeyID:           credential.KeyID(),
			SecretVerifier:  credential.Verifier(),
			PrincipalID:     "00000000-0000-4000-8000-000000000012",
			PrincipalActive: true,
			ExpiresAt:       now.Add(time.Hour),
		},
		markErr: ErrAPIKeyNotFound,
	}
	logger := &authenticationLoggerStub{}
	authenticator, err := NewAPIKeyAuthenticator(store, logger, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	if _, err := authenticator.AuthenticateAPIKey(context.Background(), bearer); err != ErrUnauthenticated {
		t.Fatalf("concurrent revocation error = %v, want exact ErrUnauthenticated", err)
	}
	if logger.principalID != "" || logger.keyPrefix != "" {
		t.Fatalf("concurrently revoked key logged success: %q/%q", logger.principalID, logger.keyPrefix)
	}
}

func TestAPIKeyAuthenticatorFailsClosedOnInfrastructureErrors(t *testing.T) {
	now := time.Date(2026, time.July, 24, 18, 30, 0, 0, time.UTC)
	credential, err := generateAPIKey(bytes.NewReader(bytes.Repeat([]byte{0x47}, apiKeyIDBytes+apiKeySecretBytes)))
	if err != nil {
		t.Fatalf("generate API key: %v", err)
	}
	bearer, err := credential.Reveal()
	if err != nil {
		t.Fatalf("reveal API key: %v", err)
	}
	validRecord := APIKeyRecord{
		KeyID:           credential.KeyID(),
		SecretVerifier:  credential.Verifier(),
		PrincipalID:     "00000000-0000-4000-8000-000000000013",
		PrincipalActive: true,
		ExpiresAt:       now.Add(time.Hour),
	}
	for _, test := range []struct {
		name   string
		store  *apiKeyStoreStub
		logger *authenticationLoggerStub
	}{
		{name: "lookup failure", store: &apiKeyStoreStub{lookupErr: errors.New("store canary")}, logger: &authenticationLoggerStub{}},
		{name: "mark failure", store: &apiKeyStoreStub{record: validRecord, markErr: errors.New("mark canary")}, logger: &authenticationLoggerStub{}},
		{name: "log failure", store: &apiKeyStoreStub{record: validRecord}, logger: &authenticationLoggerStub{err: errors.New("log canary")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticator, err := NewAPIKeyAuthenticator(test.store, test.logger, func() time.Time { return now })
			if err != nil {
				t.Fatalf("new authenticator: %v", err)
			}
			principal, err := authenticator.AuthenticateAPIKey(context.Background(), bearer)
			if err != ErrAuthenticationUnavailable {
				t.Fatalf("infrastructure error = %v, want exact ErrAuthenticationUnavailable", err)
			}
			if principal.ID != "" || strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), bearer) {
				t.Fatalf("infrastructure failure leaked state: principal=%#v error=%q", principal, err)
			}
		})
	}
}

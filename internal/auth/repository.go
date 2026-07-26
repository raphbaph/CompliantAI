package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	lookupAPIKeySQL = `SELECT key_id, secret_verifier, principal_id::text, principal_active, expires_at, disabled
		FROM lookup_api_key_auth($1::text)`
	markAPIKeyUsedSQL      = `SELECT mark_api_key_used($1::text, $2::uuid)`
	createAPIKeySQL        = `SELECT admin_create_api_key($1::text, $2::text, $3::uuid, $4::timestamptz)`
	disableAPIKeySQL       = `SELECT admin_disable_api_key($1::text)`
	lookupOIDCPrincipalSQL = `SELECT principal_id::text, principal_active FROM lookup_oidc_principal($1::text, $2::text)`
)

var (
	// ErrAPIKeyAdministration is a fixed error for API-key creation and revocation failures.
	ErrAPIKeyAdministration = errors.New("API key administration failed")
	generatedKeyIDPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// PostgresAPIKeyStore uses role-appropriate approved PostgreSQL functions.
type PostgresAPIKeyStore struct {
	pool *pgxpool.Pool
}

// NewPostgresAPIKeyStore binds API-key operations to an existing role-scoped pool.
func NewPostgresAPIKeyStore(pool *pgxpool.Pool) (*PostgresAPIKeyStore, error) {
	if pool == nil {
		return nil, ErrAuthenticationUnavailable
	}
	return &PostgresAPIKeyStore{pool: pool}, nil
}

// LookupAPIKey reads bounded verifier state through the runtime authentication function.
func (store *PostgresAPIKeyStore) LookupAPIKey(ctx context.Context, keyID string) (APIKeyRecord, error) {
	if store == nil || store.pool == nil || !generatedKeyIDPattern.MatchString(keyID) {
		return APIKeyRecord{}, ErrAuthenticationUnavailable
	}
	var record APIKeyRecord
	var expiresAt pgtype.Timestamptz
	err := store.pool.QueryRow(ctx, lookupAPIKeySQL, keyID).Scan(
		&record.KeyID,
		&record.SecretVerifier,
		&record.PrincipalID,
		&record.PrincipalActive,
		&expiresAt,
		&record.Disabled,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKeyRecord{}, ErrAPIKeyNotFound
	}
	if err != nil {
		return APIKeyRecord{}, ErrAuthenticationUnavailable
	}
	if expiresAt.InfinityModifier != pgtype.Finite {
		return APIKeyRecord{}, ErrAuthenticationUnavailable
	}
	if expiresAt.Valid {
		record.ExpiresAt = expiresAt.Time.UTC()
		if record.ExpiresAt.Year() < 1 || record.ExpiresAt.Year() > 9999 || record.ExpiresAt.Nanosecond()%1000 != 0 {
			return APIKeyRecord{}, ErrAuthenticationUnavailable
		}
	}
	if record.KeyID != keyID || !generatedKeyIDPattern.MatchString(record.KeyID) || !principalUUIDPattern.MatchString(record.PrincipalID) {
		return APIKeyRecord{}, ErrAuthenticationUnavailable
	}
	decodedVerifier, ok := decodeVerifier(record.SecretVerifier)
	if !ok {
		return APIKeyRecord{}, ErrAuthenticationUnavailable
	}
	clear(decodedVerifier)
	return record, nil
}

// MarkAPIKeyUsed atomically rechecks active state and records successful use.
func (store *PostgresAPIKeyStore) MarkAPIKeyUsed(ctx context.Context, keyID, principalID string) error {
	if store == nil || store.pool == nil || !generatedKeyIDPattern.MatchString(keyID) || !principalUUIDPattern.MatchString(principalID) {
		return ErrAuthenticationUnavailable
	}
	var marked bool
	if err := store.pool.QueryRow(ctx, markAPIKeyUsedSQL, keyID, principalID).Scan(&marked); err != nil {
		return ErrAuthenticationUnavailable
	}
	if !marked {
		return ErrAPIKeyNotFound
	}
	return nil
}

// CreateAndPublishAPIKey keeps the new key uncommitted until publication succeeds.
func (store *PostgresAPIKeyStore) CreateAndPublishAPIKey(ctx context.Context, principalID string, expiresAt time.Time, publish func(keyID, bearer string) error) error {
	if store == nil || store.pool == nil || publish == nil || !principalUUIDPattern.MatchString(principalID) || expiresAt.IsZero() || expiresAt.Location() != time.UTC || expiresAt.Year() < 1 || expiresAt.Year() > 9999 || expiresAt.Nanosecond()%1000 != 0 {
		return ErrAPIKeyAdministration
	}
	credential, err := generateAPIKey(rand.Reader)
	if err != nil {
		return ErrAPIKeyAdministration
	}
	defer credential.Destroy()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ErrAPIKeyAdministration
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, createAPIKeySQL, credential.KeyID(), credential.Verifier(), principalID, expiresAt); err != nil {
		return ErrAPIKeyAdministration
	}
	bearer, err := credential.Reveal()
	if err != nil {
		return ErrAPIKeyAdministration
	}
	if err := publish(credential.KeyID(), bearer); err != nil {
		return ErrAPIKeyAdministration
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrAPIKeyAdministration
	}
	return nil
}

// DisableAPIKey revokes a generated key through the approved administration function.
func (store *PostgresAPIKeyStore) DisableAPIKey(ctx context.Context, keyID string) error {
	if store == nil || store.pool == nil || !generatedKeyIDPattern.MatchString(keyID) {
		return ErrAPIKeyAdministration
	}
	if _, err := store.pool.Exec(ctx, disableAPIKeySQL, keyID); err != nil {
		return ErrAPIKeyAdministration
	}
	return nil
}

// LookupOIDCPrincipal resolves a validated issuer/subject pair through the runtime function.
func (store *PostgresAPIKeyStore) LookupOIDCPrincipal(ctx context.Context, issuer, subject string) (OIDCPrincipalRecord, error) {
	if store == nil || store.pool == nil || issuer == "" || subject == "" || len(issuer) > 512 || len(subject) > maxOIDCSubjectBytes {
		return OIDCPrincipalRecord{}, ErrAuthenticationUnavailable
	}
	if strings.ContainsAny(issuer, "\r\n\x00") || strings.ContainsAny(subject, "\r\n\x00") {
		return OIDCPrincipalRecord{}, ErrAuthenticationUnavailable
	}
	var record OIDCPrincipalRecord
	err := store.pool.QueryRow(ctx, lookupOIDCPrincipalSQL, issuer, subject).Scan(&record.ID, &record.Active)
	if errors.Is(err, pgx.ErrNoRows) {
		return OIDCPrincipalRecord{}, ErrOIDCPrincipalNotFound
	}
	if err != nil {
		return OIDCPrincipalRecord{}, ErrAuthenticationUnavailable
	}
	if !principalUUIDPattern.MatchString(record.ID) {
		return OIDCPrincipalRecord{}, ErrAuthenticationUnavailable
	}
	return record, nil
}

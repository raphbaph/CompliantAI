package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raphbaph/CompliantAI/internal/auth"
	"github.com/raphbaph/CompliantAI/internal/safelog"
)

type blockingAPIKeyStore struct {
	store      auth.APIKeyStore
	lookupDone chan struct{}
	release    chan struct{}
}

func (store *blockingAPIKeyStore) LookupAPIKey(ctx context.Context, keyID string) (auth.APIKeyRecord, error) {
	record, err := store.store.LookupAPIKey(ctx, keyID)
	close(store.lookupDone)
	<-store.release
	return record, err
}

func (store *blockingAPIKeyStore) MarkAPIKeyUsed(ctx context.Context, keyID, principalID string) error {
	return store.store.MarkAPIKeyUsed(ctx, keyID, principalID)
}

func TestAPIKeyAuthentication(t *testing.T) {
	if os.Getenv("TEST_GATEWAY_DSN") == "" || os.Getenv("TEST_SECURITY_ADMIN_DSN") == "" || os.Getenv("TEST_BOOTSTRAP_DSN") == "" {
		t.Skip("live PostgreSQL test DSNs are not set")
	}
	ctx := context.Background()
	securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")
	defer securityAdmin.Close()
	gateway := openTestPool(t, ctx, "TEST_GATEWAY_DSN")
	defer gateway.Close()
	bootstrap := openTestPool(t, ctx, "TEST_BOOTSTRAP_DSN")
	defer bootstrap.Close()

	var principalID string
	if err := securityAdmin.QueryRow(ctx,
		`SELECT admin_create_principal($1, $2, $3)`,
		"https://idp.customer.example", "api-key-auth-"+newTestUUID(t), "API Key Authentication Fixture",
	).Scan(&principalID); err != nil {
		t.Fatalf("create principal: %v", err)
	}

	temporaryDirectory := t.TempDir()
	toolPath := filepath.Join(temporaryDirectory, "agentboxctl")
	build := exec.CommandContext(ctx, "go", "build", "-o", toolPath, "./cmd/agentboxctl")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agentboxctl: %v: %s", err, output)
	}
	adminDSNFile := writeCheckpointTestFile(t, temporaryDirectory, "security-admin.dsn", os.Getenv("TEST_SECURITY_ADMIN_DSN")+"\n", 0o600)
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	createStdout, createStderr, err := runCheckpointTool(ctx, toolPath,
		"api-key", "create",
		"--dsn-file", adminDSNFile,
		"--principal-id", principalID,
		"--expires-at", expiresAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatalf("agentboxctl api-key create: %v, stderr=%q", err, createStderr)
	}
	if createStderr != "" {
		t.Fatalf("api-key create stderr = %q", createStderr)
	}
	var created struct {
		KeyID  string `json:"key_id"`
		Bearer string `json:"bearer"`
	}
	if err := json.Unmarshal([]byte(createStdout), &created); err != nil || created.KeyID == "" || created.Bearer == "" {
		t.Fatalf("decode api-key create output: %v, output=%q", err, createStdout)
	}
	bearer := created.Bearer

	var persistedVerifier string
	if err := bootstrap.QueryRow(ctx, `SELECT secret_verifier FROM api_keys WHERE key_id = $1`, created.KeyID).Scan(&persistedVerifier); err != nil {
		t.Fatalf("read persisted verifier: %v", err)
	}
	if !auth.VerifyAPIKey(bearer, persistedVerifier) || auth.VerifyAPIKey(persistedVerifier, persistedVerifier) || strings.Contains(persistedVerifier, bearer) {
		t.Fatal("database did not persist exactly the non-bearer verifier")
	}

	runtimeStore, err := auth.NewPostgresAPIKeyStore(gateway)
	if err != nil {
		t.Fatalf("new runtime API-key store: %v", err)
	}
	var logOutput bytes.Buffer
	authenticator, err := auth.NewAPIKeyAuthenticator(runtimeStore, safelog.New(&logOutput), time.Now)
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	principal, err := authenticator.AuthenticateAPIKey(ctx, bearer)
	if err != nil {
		t.Fatalf("authenticate valid API key: %v", err)
	}
	if principal.ID != principalID || principal.APIKeyIDPrefix != created.KeyID[:8] {
		t.Fatalf("authenticated principal = %#v", principal)
	}
	if strings.Contains(logOutput.String(), bearer) || strings.Contains(logOutput.String(), persistedVerifier) {
		t.Fatal("authentication log contains bearer or verifier")
	}
	var used bool
	if err := bootstrap.QueryRow(ctx, `SELECT last_used_at IS NOT NULL FROM api_keys WHERE key_id = $1`, created.KeyID).Scan(&used); err != nil {
		t.Fatalf("read last-used state: %v", err)
	}
	if !used {
		t.Fatal("successful authentication did not update last_used_at")
	}

	bearerParts := strings.Split(bearer, ".")
	wrongSecret := bearer[:len(bearer)-1] + "A"
	if wrongSecret == bearer {
		wrongSecret = bearer[:len(bearer)-1] + "B"
	}
	for name, candidate := range map[string]string{
		"malformed":    "not-an-api-key",
		"noncanonical": strings.ToUpper(bearerParts[0]) + "." + bearerParts[1] + "." + bearerParts[2],
		"unknown":      bearerParts[0] + "." + strings.Repeat("f", 32) + "." + bearerParts[2],
		"wrong secret": wrongSecret,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := authenticator.AuthenticateAPIKey(ctx, candidate); err != auth.ErrUnauthenticated {
				t.Fatalf("authentication error = %v, want exact ErrUnauthenticated", err)
			}
		})
	}
	expiredAuthenticator, err := auth.NewAPIKeyAuthenticator(runtimeStore, safelog.New(io.Discard), func() time.Time { return expiresAt.Add(time.Second) })
	if err != nil {
		t.Fatalf("new expired-key authenticator: %v", err)
	}
	if _, err := expiredAuthenticator.AuthenticateAPIKey(ctx, bearer); err != auth.ErrUnauthenticated {
		t.Fatalf("expired API key error = %v, want exact ErrUnauthenticated", err)
	}
	if _, err := bootstrap.Exec(ctx, `UPDATE principals SET status = 'disabled', disabled_at = statement_timestamp() WHERE id = $1`, principalID); err != nil {
		t.Fatalf("disable principal: %v", err)
	}
	if _, err := authenticator.AuthenticateAPIKey(ctx, bearer); err != auth.ErrUnauthenticated {
		t.Fatalf("disabled-principal API key error = %v, want exact ErrUnauthenticated", err)
	}
	if _, err := bootstrap.Exec(ctx, `UPDATE principals SET status = 'active', disabled_at = NULL WHERE id = $1`, principalID); err != nil {
		t.Fatalf("restore principal: %v", err)
	}

	securityStore, err := auth.NewPostgresAPIKeyStore(securityAdmin)
	if err != nil {
		t.Fatalf("new security-admin API-key store: %v", err)
	}
	var raceKeyID, raceBearer string
	if err := securityStore.CreateAndPublishAPIKey(ctx, principalID, time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), func(keyID, bearer string) error {
		raceKeyID, raceBearer = keyID, bearer
		return nil
	}); err != nil {
		t.Fatalf("create revocation-race API key: %v", err)
	}
	blockingStore := &blockingAPIKeyStore{store: runtimeStore, lookupDone: make(chan struct{}), release: make(chan struct{})}
	raceAuthenticator, err := auth.NewAPIKeyAuthenticator(blockingStore, safelog.New(io.Discard), time.Now)
	if err != nil {
		t.Fatalf("new revocation-race authenticator: %v", err)
	}
	raceResult := make(chan error, 1)
	go func() {
		_, authenticateErr := raceAuthenticator.AuthenticateAPIKey(ctx, raceBearer)
		raceResult <- authenticateErr
	}()
	<-blockingStore.lookupDone
	if err := securityStore.DisableAPIKey(ctx, raceKeyID); err != nil {
		t.Fatalf("disable revocation-race API key: %v", err)
	}
	close(blockingStore.release)
	if err := <-raceResult; err != auth.ErrUnauthenticated {
		t.Fatalf("concurrently revoked API key error = %v, want exact ErrUnauthenticated", err)
	}

	disableStdout, disableStderr, err := runCheckpointTool(ctx, toolPath,
		"api-key", "disable", "--dsn-file", adminDSNFile, "--key-id", created.KeyID,
	)
	if err != nil {
		t.Fatalf("agentboxctl api-key disable: %v, stderr=%q", err, disableStderr)
	}
	if disableStderr != "" || !strings.Contains(disableStdout, `"disabled":true`) {
		t.Fatalf("api-key disable stdout/stderr = %q/%q", disableStdout, disableStderr)
	}
	if _, err := authenticator.AuthenticateAPIKey(ctx, bearer); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("disabled API key error = %v, want ErrUnauthenticated", err)
	}

	if _, err := bootstrap.Exec(ctx, `UPDATE api_keys SET disabled_at = NULL, expires_at = NULL, last_used_at = NULL WHERE key_id = $1`, created.KeyID); err != nil {
		t.Fatalf("prepare missing-expiry atomic-gate fixture: %v", err)
	}
	var markedWithoutExpiry bool
	if err := gateway.QueryRow(ctx, `SELECT mark_api_key_used($1::text, $2::uuid)`, created.KeyID, principalID).Scan(&markedWithoutExpiry); err != nil {
		t.Fatalf("call atomic API-key use gate: %v", err)
	}
	if markedWithoutExpiry {
		t.Fatal("atomic API-key use gate accepted a missing expiry")
	}
	if _, err := authenticator.AuthenticateAPIKey(ctx, bearer); err != auth.ErrUnauthenticated {
		t.Fatalf("missing-expiry API key error = %v, want exact ErrUnauthenticated", err)
	}
}

func TestAPIKeyCreatePublishFailureRollsBack(t *testing.T) {
	if os.Getenv("TEST_SECURITY_ADMIN_DSN") == "" || os.Getenv("TEST_BOOTSTRAP_DSN") == "" {
		t.Skip("live PostgreSQL test DSNs are not set")
	}
	ctx := context.Background()
	securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")
	defer securityAdmin.Close()
	bootstrap := openTestPool(t, ctx, "TEST_BOOTSTRAP_DSN")
	defer bootstrap.Close()

	var principalID string
	if err := securityAdmin.QueryRow(ctx,
		`SELECT admin_create_principal($1, $2, $3)`,
		"https://idp.customer.example", "api-key-publish-failure-"+newTestUUID(t), "API Key Publish Failure Fixture",
	).Scan(&principalID); err != nil {
		t.Fatalf("create principal: %v", err)
	}
	store, err := auth.NewPostgresAPIKeyStore(securityAdmin)
	if err != nil {
		t.Fatalf("new API-key store: %v", err)
	}
	var createdKeyID string
	err = store.CreateAndPublishAPIKey(ctx, principalID, time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), func(keyID, bearer string) error {
		createdKeyID = keyID
		var partialOutput bytes.Buffer
		_, _ = partialOutput.WriteString(bearer[:len(bearer)/2])
		return errors.New("output failure canary")
	})
	if err != auth.ErrAPIKeyAdministration {
		t.Fatalf("CreateAndPublishAPIKey() error = %v, want exact ErrAPIKeyAdministration", err)
	}
	var count int
	if err := bootstrap.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE key_id = $1`, createdKeyID).Scan(&count); err != nil {
		t.Fatalf("count rolled-back API key: %v", err)
	}
	if count != 0 {
		t.Fatalf("API-key rows after publication failure = %d, want 0", count)
	}
}

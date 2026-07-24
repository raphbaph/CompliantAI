package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/raphbaph/CompliantAI/internal/audit"
)

func TestAuditCheckpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bootstrap := openTestPool(t, ctx, "TEST_BOOTSTRAP_DSN")
	gateway := openTestPool(t, ctx, "TEST_GATEWAY_DSN")
	auditReader := openTestPool(t, ctx, "TEST_AUDIT_READER_DSN")
	securityAdmin := openTestPool(t, ctx, "TEST_SECURITY_ADMIN_DSN")

	var principalID string
	if err := bootstrap.QueryRow(ctx,
		`SELECT admin_create_principal($1, $2, $3)`,
		"checkpoint-principal-"+newTestUUID(t),
		"Checkpoint Integration Principal",
		"active",
	).Scan(&principalID); err != nil {
		t.Fatalf("create checkpoint principal: %v", err)
	}
	for identifierType, identifierValue := range map[string]string{
		"model":            "checkpoint-model",
		"backend":          "checkpoint-backend",
		"software_version": "checkpoint-test",
		"content_hmac_key": "checkpoint-content-key-v1",
	} {
		if _, err := bootstrap.Exec(ctx,
			`SELECT admin_register_audit_identifier($1, $2)`, identifierType, identifierValue,
		); err != nil {
			t.Fatalf("register %s: %v", identifierType, err)
		}
	}

	writer, err := audit.NewRepository(gateway)
	if err != nil {
		t.Fatalf("new event writer: %v", err)
	}
	event := chainEventFixture(t, principalID)
	event.RequestedModel = "checkpoint-model"
	event.ResolvedBackend = "checkpoint-backend"
	event.SoftwareVersion = "checkpoint-test"
	event.ContentHMACKeyID = "checkpoint-content-key-v1"
	receipt, err := writer.Append(ctx, event)
	if err != nil {
		t.Fatalf("append checkpoint event: %v", err)
	}

	adminRepository, err := audit.NewRepository(securityAdmin)
	if err != nil {
		t.Fatalf("new checkpoint repository: %v", err)
	}
	head, err := adminRepository.ChainHead(ctx)
	if err != nil {
		t.Fatalf("read chain head through approved function: %v", err)
	}
	if head.Sequence != receipt.Sequence() || head.EventHash != receipt.EventHash() {
		t.Fatalf("chain head = %#v, receipt sequence = %d", head, receipt.Sequence())
	}
	for _, pool := range []*pgxpool.Pool{gateway, auditReader} {
		var sequence int64
		var eventHash []byte
		err := pool.QueryRow(ctx, `SELECT sequence, event_hash FROM get_audit_chain_head()`).Scan(&sequence, &eventHash)
		assertSQLState(t, err, "42501")
	}

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	verificationKey, err := audit.NewCheckpointVerificationKey("checkpoint-key-v1", privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("new checkpoint verification key: %v", err)
	}
	for _, invalidTimestamp := range []string{"infinity", "-infinity", "10000-01-01 00:00:00+00"} {
		t.Run("reject checkpoint timestamp "+invalidTimestamp, func(t *testing.T) {
			transaction, err := securityAdmin.Begin(ctx)
			if err != nil {
				t.Fatalf("begin timestamp probe: %v", err)
			}
			defer func() { _ = transaction.Rollback(ctx) }()
			_, err = transaction.Exec(ctx,
				`SELECT store_audit_checkpoint($1, $2, $3, $4, $5::text::timestamptz)`,
				head.Sequence,
				head.EventHash[:],
				"checkpoint-time-probe-v1",
				bytes.Repeat([]byte{0x55}, ed25519.SignatureSize),
				invalidTimestamp,
			)
			assertSQLStateMessage(t, err, "22023", "invalid audit checkpoint")
		})
	}
	temporaryDirectory := t.TempDir()
	adminDSNFile := writeCheckpointTestFile(t, temporaryDirectory, "security-admin.dsn", os.Getenv("TEST_SECURITY_ADMIN_DSN"), 0o600)
	readerDSNFile := writeCheckpointTestFile(t, temporaryDirectory, "audit-reader.dsn", os.Getenv("TEST_AUDIT_READER_DSN"), 0o600)
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal checkpoint private key: %v", err)
	}
	privateKeyFile := writeCheckpointTestFile(
		t,
		temporaryDirectory,
		"checkpoint-private.pem",
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
		0o600,
	)
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("marshal checkpoint public key: %v", err)
	}
	publicKeyFile := writeCheckpointTestFile(
		t,
		temporaryDirectory,
		"checkpoint-public.pem",
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		0o644,
	)
	toolPath := filepath.Join(temporaryDirectory, "agentboxctl")
	build := exec.CommandContext(ctx, "go", "build", "-o", toolPath, "./cmd/agentboxctl")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agentboxctl: %v: %s", err, output)
	}

	checkpointStdout, checkpointStderr, err := runCheckpointTool(ctx, toolPath,
		"checkpoint",
		"--dsn-file", adminDSNFile,
		"--private-key-file", privateKeyFile,
		"--key-id", "checkpoint-key-v1",
	)
	if err != nil {
		t.Fatalf("agentboxctl checkpoint: %v, stderr=%q", err, checkpointStderr)
	}
	wantCheckpointOutput := fmt.Sprintf("{\"sequence\":%d,\"signing_key_id\":\"checkpoint-key-v1\"}\n", head.Sequence)
	if checkpointStdout != wantCheckpointOutput {
		t.Fatalf("checkpoint stdout = %q, want %q", checkpointStdout, wantCheckpointOutput)
	}
	const warning = "WARNING: file-based checkpoint signing does not protect against host administrators\n"
	if checkpointStderr != warning {
		t.Fatalf("checkpoint warning = %q", checkpointStderr)
	}

	readerRepository, err := audit.NewRepository(auditReader)
	if err != nil {
		t.Fatalf("new audit reader repository: %v", err)
	}
	persistedCheckpoint, err := readerRepository.LoadCheckpoint(ctx, head.Sequence)
	if err != nil {
		t.Fatalf("load checkpoint without write access: %v", err)
	}
	records, err := readerRepository.RecordsThrough(ctx, head.Sequence)
	if err != nil {
		t.Fatalf("load checkpoint records without write access: %v", err)
	}
	exported, err := audit.MarshalExport(records, persistedCheckpoint)
	if err != nil {
		t.Fatalf("marshal persisted export: %v", err)
	}
	if err := audit.VerifyExport(exported, verificationKey); err != nil {
		t.Fatalf("verify persisted export offline: %v", err)
	}

	exportPath := filepath.Join(temporaryDirectory, "audit-export.json")
	exportStdout, exportStderr, err := runCheckpointTool(ctx, toolPath,
		"export",
		"--dsn-file", readerDSNFile,
		"--sequence", fmt.Sprintf("%d", head.Sequence),
		"--output", exportPath,
	)
	if err != nil {
		t.Fatalf("agentboxctl export: %v, stderr=%q", err, exportStderr)
	}
	wantExportOutput := fmt.Sprintf("{\"sequence\":%d,\"exported\":true}\n", head.Sequence)
	if exportStdout != wantExportOutput || exportStderr != "" {
		t.Fatalf("export stdout=%q stderr=%q", exportStdout, exportStderr)
	}
	verifyStdout, verifyStderr, err := runCheckpointTool(ctx, toolPath,
		"verify",
		"--input", exportPath,
		"--public-key-file", publicKeyFile,
		"--key-id", "checkpoint-key-v1",
	)
	if err != nil || verifyStdout != "{\"valid\":true}\n" || verifyStderr != "" {
		t.Fatalf("agentboxctl verify: err=%v stdout=%q stderr=%q", err, verifyStdout, verifyStderr)
	}
	if strings.Contains(checkpointStdout+checkpointStderr+exportStdout+exportStderr+verifyStdout+verifyStderr, string(privateKey)) {
		t.Fatal("agentboxctl output contained private key material")
	}

	for _, pool := range []*pgxpool.Pool{gateway, auditReader, securityAdmin} {
		_, err := pool.Exec(ctx,
			`INSERT INTO audit_checkpoints (sequence, chain_head_hash, signing_key_id, signature, created_at) VALUES ($1, $2, $3, $4, $5)`,
			persistedCheckpoint.Sequence, persistedCheckpoint.ChainHeadHash[:], persistedCheckpoint.SigningKeyID, persistedCheckpoint.Signature, persistedCheckpoint.CreatedAt,
		)
		assertSQLState(t, err, "42501")
	}
	for _, pool := range []*pgxpool.Pool{gateway, auditReader} {
		_, err := pool.Exec(ctx,
			`SELECT store_audit_checkpoint($1, $2, $3, $4, $5)`,
			persistedCheckpoint.Sequence,
			persistedCheckpoint.ChainHeadHash[:],
			persistedCheckpoint.SigningKeyID,
			persistedCheckpoint.Signature,
			persistedCheckpoint.CreatedAt,
		)
		assertSQLState(t, err, "42501")
	}

	if err := adminRepository.StoreCheckpoint(ctx, persistedCheckpoint); !errors.Is(err, audit.ErrCheckpointStore) {
		t.Fatalf("duplicate checkpoint error = %v", err)
	}
	changed := persistedCheckpoint
	changed.Sequence++
	if err := adminRepository.StoreCheckpoint(ctx, changed); !errors.Is(err, audit.ErrCheckpointStore) {
		t.Fatalf("mismatched checkpoint error = %v", err)
	}
	_, err = securityAdmin.Exec(ctx,
		`SELECT store_audit_checkpoint($1, $2, $3, $4, $5)`,
		changed.Sequence,
		changed.ChainHeadHash[:],
		"checkpoint-key-v1",
		changed.Signature,
		changed.CreatedAt,
	)
	assertSQLStateMessage(t, err, "22023", "invalid audit checkpoint")
}

func writeCheckpointTestFile(t *testing.T, directory string, name string, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func runCheckpointTool(ctx context.Context, path string, arguments ...string) (string, string, error) {
	var stdout, stderr strings.Builder
	command := exec.CommandContext(ctx, path, arguments...)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/raphbaph/CompliantAI/internal/audit"
	"github.com/raphbaph/CompliantAI/internal/auth"
)

type failingOutputWriter struct{}

func (failingOutputWriter) Write([]byte) (int, error) {
	return 0, errors.New("output failure canary")
}

type apiKeyCreatorStub struct {
	publishErr error
}

func (stub *apiKeyCreatorStub) CreateAndPublishAPIKey(_ context.Context, _ string, _ time.Time, publish func(string, string) error) error {
	stub.publishErr = publish(strings.Repeat("a", 32), "output-failure-test-bearer")
	if stub.publishErr != nil {
		return auth.ErrAPIKeyAdministration
	}
	return nil
}

func TestRunVerifyAcceptsSignedExport(t *testing.T) {
	exportPath, publicKeyPath := writeVerificationFixtures(t)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{
		"verify",
		"--input", exportPath,
		"--public-key-file", publicKeyPath,
		"--key-id", "checkpoint-key-v1",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run verify code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "{\"valid\":true}\n" {
		t.Fatalf("verify stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("verify stderr = %q", stderr.String())
	}
}

func TestRunVerifyFailureIsContentFree(t *testing.T) {
	exportPath, publicKeyPath := writeVerificationFixtures(t)
	encoded, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("read export fixture: %v", err)
	}
	const canary = "PROMPT-CONTENT-CANARY-CLI"
	encoded = bytes.Replace(encoded, []byte(`"cli-model"`), []byte(`"`+canary+`"`), 1)
	if err := os.WriteFile(exportPath, encoded, 0o600); err != nil {
		t.Fatalf("write tampered export: %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{
		"verify",
		"--input", exportPath,
		"--public-key-file", publicKeyPath,
		"--key-id", "checkpoint-key-v1",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run verify code = %d", code)
	}
	if stdout.Len() != 0 || stderr.String() != "{\"valid\":false,\"first_affected_sequence\":1}\n" {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), canary) {
		t.Fatal("verify error exposed tampered content")
	}
}

func TestRunPreservesVersionOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--version"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("version code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"version"`) || !strings.Contains(stdout.String(), `"commit"`) {
		t.Fatalf("version stdout = %q", stdout.String())
	}
}

func TestReadSecretFileRequiresExact0600Mode(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o700} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "database.dsn")
			if err := os.WriteFile(path, []byte("postgres://local/example"), mode); err != nil {
				t.Fatalf("write DSN fixture: %v", err)
			}
			if secret, err := readSecretFile(path); err == nil {
				clear(secret)
				t.Fatalf("readSecretFile() accepted mode %04o", mode)
			}
		})
	}
}

func TestTask8FileReadersRejectSymlinks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("postgres://local/example"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if content, err := readBoundedRegularFile(link, 1024); err == nil {
		clear(content)
		t.Fatal("bounded reader accepted symlink")
	}
	if secret, err := readSecretFile(link); err == nil {
		clear(secret)
		t.Fatal("secret reader accepted symlink")
	}
}

func TestRunAPIKeyCreateRejectsInvalidArgumentsWithoutEchoingThem(t *testing.T) {
	const canary = "API-KEY-CLI-CANARY-secret"
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run(context.Background(), []string{
		"api-key", "create",
		"--dsn-file", canary,
		"--principal-id", "invalid",
		"--expires-at", "invalid",
	}, &stdout, &stderr)
	if exitCode != 1 {
		t.Fatalf("run(api-key create) exit = %d, want 1", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("run(api-key create) stdout = %q, want empty", stdout.String())
	}
	if stderr.String() != "API key creation failed\n" {
		t.Fatalf("run(api-key create) stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), canary) {
		t.Fatal("API-key creation error echoed an argument")
	}
}

func TestAPIKeyCLIPropagatesOutputFailuresToTransactionalCreation(t *testing.T) {
	creator := &apiKeyCreatorStub{}
	err := createAndPublishAPIKey(context.Background(), creator, "00000000-0000-4000-8000-000000000019", time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), failingOutputWriter{})
	if err != auth.ErrAPIKeyAdministration {
		t.Fatalf("createAndPublishAPIKey() error = %v, want exact ErrAPIKeyAdministration", err)
	}
	if creator.publishErr == nil || !strings.Contains(creator.publishErr.Error(), "output failure canary") {
		t.Fatalf("transactional publish error = %v, want output failure", creator.publishErr)
	}
	if err := writeAPIKeyDisableConfirmation(failingOutputWriter{}, strings.Repeat("a", 32)); err == nil || !strings.Contains(err.Error(), "output failure canary") {
		t.Fatalf("disable confirmation error = %v, want output failure", err)
	}
}

func writeVerificationFixtures(t *testing.T) (string, string) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	signer, err := audit.NewEd25519Signer("checkpoint-key-v1", privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	event := cliAuditEventFixture()
	eventHash, err := audit.EventHash(event)
	if err != nil {
		t.Fatalf("hash event: %v", err)
	}
	records := []audit.Record{{Sequence: 1, Event: event, EventHash: eventHash}}
	checkpoint, err := audit.CreateCheckpoint(
		context.Background(),
		1,
		eventHash,
		time.Date(2026, time.July, 24, 16, 0, 0, 0, time.UTC),
		&signer,
	)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	exported, err := audit.MarshalExport(records, checkpoint)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	exportPath := filepath.Join(t.TempDir(), "audit-export.json")
	if err := os.WriteFile(exportPath, exported, 0o600); err != nil {
		t.Fatalf("write export fixture: %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicKeyPath := filepath.Join(t.TempDir(), "checkpoint-public-key.pem")
	if err := os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatalf("write public key fixture: %v", err)
	}
	return exportPath, publicKeyPath
}

func cliAuditEventFixture() audit.Event {
	digest := func(value byte) audit.Digest {
		var result audit.Digest
		for index := range result {
			result[index] = value
		}
		return result
	}
	return audit.Event{
		SchemaVersion:             1,
		EventID:                   "00000000-0000-4000-8000-000000000001",
		RunID:                     "00000000-0000-4000-8000-000000000002",
		EventType:                 audit.EventRunStarted,
		OccurredAt:                time.Date(2026, time.July, 24, 15, 59, 0, 0, time.UTC),
		PrincipalID:               "00000000-0000-4000-8000-000000000003",
		AuthMethod:                audit.AuthAPIKey,
		PolicyVersionHash:         digest(1),
		Decision:                  audit.DecisionAllow,
		DecisionReasonCodes:       []string{"policy_allowed"},
		RequestedModel:            "cli-model",
		ResolvedBackend:           "cli-backend",
		ContentHMACKeyID:          "content-key-v1",
		RequestHMAC:               digest(2),
		RequestBytes:              64,
		PIICategories:             []string{},
		PIIMatchCounts:            map[string]int64{},
		HealthIndicatorCategories: []string{},
		SecretCategories:          []string{},
		DetectorBundleHash:        digest(3),
		Status:                    audit.StatusStarted,
		PreviousEventHash:         audit.Digest{},
		SoftwareVersion:           "cli-test",
		ConfigHash:                digest(4),
	}
}

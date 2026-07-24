package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/raphbaph/CompliantAI/internal/audit"
	"github.com/raphbaph/CompliantAI/internal/version"
)

const (
	maximumAuditExportBytes = 512 * 1024 * 1024
	maximumDSNBytes         = 16 * 1024
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, arguments []string, stdout io.Writer, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--version" {
		if err := json.NewEncoder(stdout).Encode(version.Current()); err != nil {
			_, _ = fmt.Fprintln(stderr, "failed to encode build metadata")
			return 1
		}
		return 0
	}
	if len(arguments) == 0 {
		_, _ = fmt.Fprintln(stderr, "agentboxctl command required")
		return 2
	}
	switch arguments[0] {
	case "checkpoint":
		return runCheckpoint(ctx, arguments[1:], stdout, stderr)
	case "export":
		return runExport(ctx, arguments[1:], stdout, stderr)
	case "verify":
		return runVerify(ctx, arguments[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintln(stderr, "unknown agentboxctl command")
		return 2
	}
}

func runCheckpoint(ctx context.Context, arguments []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("checkpoint", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dsnPath := flags.String("dsn-file", "", "security-admin PostgreSQL DSN file")
	privateKeyPath := flags.String("private-key-file", "", "Ed25519 PKCS#8 private key PEM file")
	keyID := flags.String("key-id", "", "checkpoint signing key identity")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *dsnPath == "" || *privateKeyPath == "" || *keyID == "" {
		_, _ = fmt.Fprintln(stderr, "checkpoint command failed")
		return 1
	}
	_, _ = fmt.Fprintln(stderr, "WARNING: file-based checkpoint signing does not protect against host administrators")

	signer, err := audit.LoadEd25519SignerFile(*keyID, *privateKeyPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "checkpoint command failed")
		return 1
	}
	defer signer.Destroy()
	repository, closeRepository, err := openAuditRepository(ctx, *dsnPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "checkpoint command failed")
		return 1
	}
	defer closeRepository()
	head, err := repository.ChainHead(ctx)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "checkpoint command failed")
		return 1
	}
	checkpoint, err := audit.CreateCheckpoint(
		ctx,
		head.Sequence,
		head.EventHash,
		time.Now().UTC().Truncate(time.Microsecond),
		&signer,
	)
	if err != nil || repository.StoreCheckpoint(ctx, checkpoint) != nil {
		_, _ = fmt.Fprintln(stderr, "checkpoint command failed")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(struct {
		Sequence     int64  `json:"sequence"`
		SigningKeyID string `json:"signing_key_id"`
	}{Sequence: checkpoint.Sequence, SigningKeyID: checkpoint.SigningKeyID}); err != nil {
		_, _ = fmt.Fprintln(stderr, "checkpoint command failed")
		return 1
	}
	return 0
}

func runExport(ctx context.Context, arguments []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dsnPath := flags.String("dsn-file", "", "audit-reader PostgreSQL DSN file")
	sequence := flags.Int64("sequence", 0, "signed checkpoint sequence")
	outputPath := flags.String("output", "", "exclusive output JSON file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *dsnPath == "" || *sequence <= 0 || *outputPath == "" {
		_, _ = fmt.Fprintln(stderr, "audit export failed")
		return 1
	}
	repository, closeRepository, err := openAuditRepository(ctx, *dsnPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "audit export failed")
		return 1
	}
	defer closeRepository()
	checkpoint, err := repository.LoadCheckpoint(ctx, *sequence)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "audit export failed")
		return 1
	}
	records, err := repository.RecordsThrough(ctx, *sequence)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "audit export failed")
		return 1
	}
	exported, err := audit.MarshalExport(records, checkpoint)
	if err != nil || writeExclusiveFile(*outputPath, exported) != nil {
		_, _ = fmt.Fprintln(stderr, "audit export failed")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(struct {
		Sequence int64 `json:"sequence"`
		Exported bool  `json:"exported"`
	}{Sequence: *sequence, Exported: true}); err != nil {
		_, _ = fmt.Fprintln(stderr, "audit export failed")
		return 1
	}
	return 0
}

func runVerify(ctx context.Context, arguments []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "", "audit export JSON file")
	publicKeyPath := flags.String("public-key-file", "", "trusted Ed25519 public key PEM file")
	keyID := flags.String("key-id", "", "trusted signing key identity")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *inputPath == "" || *publicKeyPath == "" || *keyID == "" {
		_, _ = fmt.Fprintln(stderr, "audit verification failed")
		return 1
	}
	select {
	case <-ctx.Done():
		_, _ = fmt.Fprintln(stderr, "audit verification failed")
		return 1
	default:
	}
	verificationKey, err := audit.LoadCheckpointVerificationKeyFile(*keyID, *publicKeyPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "audit verification failed")
		return 1
	}
	exported, err := readBoundedRegularFile(*inputPath, maximumAuditExportBytes)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "audit verification failed")
		return 1
	}
	if err := audit.VerifyExport(exported, verificationKey); err != nil {
		var verificationError *audit.VerificationError
		if errors.As(err, &verificationError) && verificationError.Sequence > 0 {
			if encodeErr := json.NewEncoder(stderr).Encode(struct {
				Valid                 bool  `json:"valid"`
				FirstAffectedSequence int64 `json:"first_affected_sequence"`
			}{Valid: false, FirstAffectedSequence: verificationError.Sequence}); encodeErr == nil {
				return 1
			}
		}
		_, _ = fmt.Fprintln(stderr, "audit verification failed")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(struct {
		Valid bool `json:"valid"`
	}{Valid: true}); err != nil {
		_, _ = fmt.Fprintln(stderr, "audit verification failed")
		return 1
	}
	return 0
}

func openAuditRepository(ctx context.Context, dsnPath string) (*audit.Repository, func(), error) {
	dsn, err := readSecretFile(dsnPath)
	if err != nil {
		return nil, func() {}, os.ErrInvalid
	}
	defer clear(dsn)
	pool, err := pgxpool.New(ctx, string(dsn))
	if err != nil {
		return nil, func() {}, os.ErrInvalid
	}
	repository, err := audit.NewRepository(pool)
	if err != nil {
		pool.Close()
		return nil, func() {}, os.ErrInvalid
	}
	return repository, pool.Close, nil
}

func readSecretFile(path string) ([]byte, error) {
	secret, err := readBoundedRegularFileWithMode(path, maximumDSNBytes, 0o600)
	if err != nil {
		return nil, os.ErrInvalid
	}
	if len(secret) > 0 && secret[len(secret)-1] == '\n' {
		secret = secret[:len(secret)-1]
		if len(secret) > 0 && secret[len(secret)-1] == '\r' {
			secret = secret[:len(secret)-1]
		}
	}
	if len(secret) == 0 || strings.ContainsAny(string(secret), "\r\n\x00") {
		clear(secret)
		return nil, os.ErrInvalid
	}
	return secret, nil
}

func writeExclusiveFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return os.ErrInvalid
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return os.ErrInvalid
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return os.ErrInvalid
	}
	if err := file.Close(); err != nil {
		return os.ErrInvalid
	}
	complete = true
	return nil
}

func readBoundedRegularFile(path string, maximumBytes int64) ([]byte, error) {
	return readBoundedRegularFileWithMode(path, maximumBytes, 0)
}

func readBoundedRegularFileWithMode(path string, maximumBytes int64, requiredMode os.FileMode) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, os.ErrInvalid
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || requiredMode != 0 && openedInfo.Mode().Perm() != requiredMode {
		return nil, os.ErrInvalid
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil || int64(len(encoded)) > maximumBytes {
		return nil, os.ErrInvalid
	}
	return encoded, nil
}

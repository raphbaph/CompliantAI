package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckpointSignAndVerify(t *testing.T) {
	signer, verificationKey := checkpointTestKeys(t)
	createdAt := time.Date(2026, time.July, 24, 14, 0, 1, 123456000, time.UTC)
	head := Digest{31: 1}

	checkpoint, err := CreateCheckpoint(context.Background(), 42, head, createdAt, &signer)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	if checkpoint.SchemaVersion != 1 || checkpoint.Sequence != 42 || checkpoint.ChainHeadHash != head {
		t.Fatalf("unexpected checkpoint: %#v", checkpoint)
	}
	if checkpoint.SigningKeyID != "checkpoint-key-v1" || !checkpoint.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected checkpoint identity: %#v", checkpoint)
	}
	if len(checkpoint.Signature) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d", len(checkpoint.Signature))
	}
	if err := VerifyCheckpoint(checkpoint, verificationKey); err != nil {
		t.Fatalf("verify checkpoint: %v", err)
	}
}

func TestCheckpointMutationInvalidatesSignature(t *testing.T) {
	signer, verificationKey := checkpointTestKeys(t)
	checkpoint, err := CreateCheckpoint(
		context.Background(),
		42,
		Digest{31: 1},
		time.Date(2026, time.July, 24, 14, 0, 1, 123456000, time.UTC),
		&signer,
	)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Checkpoint)
	}{
		{name: "sequence", mutate: func(value *Checkpoint) { value.Sequence++ }},
		{name: "chain head", mutate: func(value *Checkpoint) { value.ChainHeadHash[0]++ }},
		{name: "key identity", mutate: func(value *Checkpoint) { value.SigningKeyID = "checkpoint-key-v2" }},
		{name: "created timestamp", mutate: func(value *Checkpoint) { value.CreatedAt = value.CreatedAt.Add(time.Microsecond) }},
		{name: "signature", mutate: func(value *Checkpoint) { value.Signature[0]++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := checkpoint
			mutated.Signature = append([]byte(nil), checkpoint.Signature...)
			test.mutate(&mutated)
			if err := VerifyCheckpoint(mutated, verificationKey); !errors.Is(err, ErrCheckpointVerification) {
				t.Fatalf("VerifyCheckpoint() error = %v", err)
			}
		})
	}
}

func TestCheckpointSignerCopiesAndRedactsPrivateKey(t *testing.T) {
	seed := bytes.Repeat([]byte{0x41}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	original := append([]byte(nil), privateKey...)
	signer, err := NewEd25519Signer("checkpoint-key-v1", privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if _, ok := any(signer).(CheckpointSigner); ok {
		t.Fatal("signer value implements CheckpointSigner and permits private-key copies")
	}
	clear(privateKey)

	checkpoint, err := CreateCheckpoint(
		context.Background(),
		1,
		Digest{0: 1},
		time.Date(2026, time.July, 24, 14, 0, 1, 0, time.UTC),
		&signer,
	)
	if err != nil {
		t.Fatalf("sign after caller key mutation: %v", err)
	}
	verificationKey, err := NewCheckpointVerificationKey("checkpoint-key-v1", original[ed25519.SeedSize:])
	if err != nil {
		t.Fatalf("new verification key: %v", err)
	}
	if err := VerifyCheckpoint(checkpoint, verificationKey); err != nil {
		t.Fatalf("verify after caller key mutation: %v", err)
	}

	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"}
	encodedSecrets := []string{
		hex.EncodeToString(original),
		strings.ToUpper(hex.EncodeToString(original)),
		base64.StdEncoding.EncodeToString(original),
		"65 65 65 65",
	}
	for _, format := range formats {
		for _, value := range []any{signer, &signer} {
			formatted := fmt.Sprintf(format, value)
			for _, secret := range encodedSecrets {
				if strings.Contains(formatted, secret) {
					t.Fatalf("format %q exposed private key material: %q", format, formatted)
				}
			}
		}
	}
}

func TestCheckpointSignerDestroyFailsClosed(t *testing.T) {
	signer, _ := checkpointTestKeys(t)
	signer.Destroy()
	if signer.KeyID() != "" {
		t.Fatal("destroyed signer retained key identity")
	}
	if _, err := CreateCheckpoint(
		context.Background(),
		1,
		Digest{},
		time.Date(2026, time.July, 24, 14, 0, 1, 0, time.UTC),
		&signer,
	); !errors.Is(err, ErrCheckpointSigning) {
		t.Fatalf("destroyed signer error = %v", err)
	}
}

func TestCheckpointFailsClosedForInvalidSignerAndInputs(t *testing.T) {
	validSigner, validVerificationKey := checkpointTestKeys(t)
	validTime := time.Date(2026, time.July, 24, 14, 0, 1, 0, time.UTC)

	var zeroSigner Ed25519Signer
	if _, err := CreateCheckpoint(context.Background(), 1, Digest{}, validTime, &zeroSigner); !errors.Is(err, ErrCheckpointSigning) {
		t.Fatalf("zero signer error = %v", err)
	}
	if _, err := CreateCheckpoint(context.Background(), 0, Digest{}, validTime, &validSigner); !errors.Is(err, ErrCheckpointSigning) {
		t.Fatalf("zero sequence error = %v", err)
	}
	if _, err := CreateCheckpoint(context.Background(), 1, Digest{}, validTime, &validSigner); !errors.Is(err, ErrCheckpointSigning) {
		t.Fatalf("zero chain head error = %v", err)
	}
	if _, err := CreateCheckpoint(context.Background(), 1, Digest{}, validTime.In(time.FixedZone("offset", 3600)), &validSigner); !errors.Is(err, ErrCheckpointSigning) {
		t.Fatalf("non-UTC timestamp error = %v", err)
	}
	if _, err := CreateCheckpoint(context.Background(), 1, Digest{}, validTime.Add(time.Nanosecond), &validSigner); !errors.Is(err, ErrCheckpointSigning) {
		t.Fatalf("nanosecond timestamp error = %v", err)
	}
	if _, err := NewEd25519Signer("BAD KEY", make(ed25519.PrivateKey, ed25519.PrivateKeySize)); !errors.Is(err, ErrCheckpointSigning) {
		t.Fatalf("invalid signing key ID error = %v", err)
	}
	if _, err := NewCheckpointVerificationKey("checkpoint-key-v1", make([]byte, ed25519.PublicKeySize-1)); !errors.Is(err, ErrCheckpointVerification) {
		t.Fatalf("short public key error = %v", err)
	}

	invalid := Checkpoint{
		SchemaVersion: 1,
		Sequence:      1,
		CreatedAt:     validTime,
		SigningKeyID:  "checkpoint-key-v1",
		Signature:     make([]byte, ed25519.SignatureSize),
	}
	if err := VerifyCheckpoint(invalid, validVerificationKey); !errors.Is(err, ErrCheckpointVerification) {
		t.Fatalf("forged signature error = %v", err)
	}
	if strings.Contains(ErrCheckpointSigning.Error(), "BAD KEY") || strings.Contains(ErrCheckpointVerification.Error(), "BAD KEY") {
		t.Fatal("checkpoint errors contain rejected input")
	}
}

func TestCheckpointSignerLoadsStrictPKCS8File(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "checkpoint-signing-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write private key fixture: %v", err)
	}

	signer, err := LoadEd25519SignerFile("checkpoint-key-v1", path)
	if err != nil {
		t.Fatalf("load signer file: %v", err)
	}
	checkpoint, err := CreateCheckpoint(
		context.Background(),
		1,
		Digest{0: 1},
		time.Date(2026, time.July, 24, 14, 0, 1, 0, time.UTC),
		&signer,
	)
	if err != nil {
		t.Fatalf("sign with loaded key: %v", err)
	}
	verificationKey, err := NewCheckpointVerificationKey("checkpoint-key-v1", privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("new verification key: %v", err)
	}
	if err := VerifyCheckpoint(checkpoint, verificationKey); err != nil {
		t.Fatalf("verify loaded-key checkpoint: %v", err)
	}
}

func TestCheckpointSignerFileRejectsUnsafeOrMalformedInput(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x39}, ed25519.SeedSize))
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8 key: %v", err)
	}
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	tests := []struct {
		name string
		mode os.FileMode
		data []byte
	}{
		{name: "group readable", mode: 0o640, data: validPEM},
		{name: "world readable", mode: 0o604, data: validPEM},
		{name: "leading content", mode: 0o600, data: append([]byte("PRIVATE-CONTENT-CANARY"), validPEM...)},
		{name: "trailing content", mode: 0o600, data: append(append([]byte(nil), validPEM...), []byte("PRIVATE-CONTENT-CANARY")...)},
		{name: "wrong PEM type", mode: 0o600, data: pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: der})},
		{name: "malformed", mode: 0o600, data: []byte("PRIVATE-CONTENT-CANARY")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "checkpoint-signing-key.pem")
			if err := os.WriteFile(path, test.data, test.mode); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			_, err := LoadEd25519SignerFile("checkpoint-key-v1", path)
			if !errors.Is(err, ErrCheckpointSigning) {
				t.Fatalf("LoadEd25519SignerFile() error = %v", err)
			}
			if strings.Contains(err.Error(), "PRIVATE-CONTENT-CANARY") || strings.Contains(err.Error(), path) {
				t.Fatalf("load error exposed key content or path: %v", err)
			}
		})
	}
}

func TestCheckpointVerificationKeyLoadsStrictPKIXFile(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal PKIX key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "checkpoint-public-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write public key fixture: %v", err)
	}

	verificationKey, err := LoadCheckpointVerificationKeyFile("checkpoint-key-v1", path)
	if err != nil {
		t.Fatalf("load verification key: %v", err)
	}
	signer, err := NewEd25519Signer("checkpoint-key-v1", privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	checkpoint, err := CreateCheckpoint(
		context.Background(),
		1,
		Digest{0: 1},
		time.Date(2026, time.July, 24, 14, 0, 1, 0, time.UTC),
		&signer,
	)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	if err := VerifyCheckpoint(checkpoint, verificationKey); err != nil {
		t.Fatalf("verify with loaded public key: %v", err)
	}
}

func TestCheckpointVerificationKeyFileRejectsMalformedInput(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("marshal PKIX key: %v", err)
	}
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	tests := []struct {
		name string
		data []byte
	}{
		{name: "leading content", data: append([]byte("PUBLIC-CONTENT-CANARY"), validPEM...)},
		{name: "trailing content", data: append(append([]byte(nil), validPEM...), []byte("PUBLIC-CONTENT-CANARY")...)},
		{name: "wrong PEM type", data: pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: der})},
		{name: "malformed", data: []byte("PUBLIC-CONTENT-CANARY")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "checkpoint-public-key.pem")
			if err := os.WriteFile(path, test.data, 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			_, err := LoadCheckpointVerificationKeyFile("checkpoint-key-v1", path)
			if !errors.Is(err, ErrCheckpointVerification) {
				t.Fatalf("LoadCheckpointVerificationKeyFile() error = %v", err)
			}
			if strings.Contains(err.Error(), "PUBLIC-CONTENT-CANARY") || strings.Contains(err.Error(), path) {
				t.Fatalf("load error exposed public-key content or path: %v", err)
			}
		})
	}
}

func TestCheckpointKeyFilesRejectSymlinks(t *testing.T) {
	directory := t.TempDir()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x67}, ed25519.SeedSize))
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	privateTarget := filepath.Join(directory, "private-target.pem")
	publicTarget := filepath.Join(directory, "public-target.pem")
	if err := os.WriteFile(privateTarget, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatalf("write private target: %v", err)
	}
	if err := os.WriteFile(publicTarget, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatalf("write public target: %v", err)
	}
	privateLink := filepath.Join(directory, "private-link.pem")
	publicLink := filepath.Join(directory, "public-link.pem")
	if err := os.Symlink(privateTarget, privateLink); err != nil {
		t.Fatalf("create private symlink: %v", err)
	}
	if err := os.Symlink(publicTarget, publicLink); err != nil {
		t.Fatalf("create public symlink: %v", err)
	}
	if _, err := LoadEd25519SignerFile("checkpoint-key-v1", privateLink); !errors.Is(err, ErrCheckpointSigning) {
		t.Fatalf("private symlink error = %v", err)
	}
	if _, err := LoadCheckpointVerificationKeyFile("checkpoint-key-v1", publicLink); !errors.Is(err, ErrCheckpointVerification) {
		t.Fatalf("public symlink error = %v", err)
	}
}

func checkpointTestKeys(t *testing.T) (Ed25519Signer, CheckpointVerificationKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x23}, ed25519.SeedSize))
	signer, err := NewEd25519Signer("checkpoint-key-v1", privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	verificationKey, err := NewCheckpointVerificationKey("checkpoint-key-v1", privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("new verification key: %v", err)
	}
	return signer, verificationKey
}

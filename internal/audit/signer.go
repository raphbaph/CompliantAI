package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

const checkpointSigningDomain = "compliantai:audit-checkpoint:v1\x00"

var (
	// ErrCheckpointSigning reports a fixed, content-free checkpoint signing failure.
	ErrCheckpointSigning = errors.New("checkpoint signing failed")
	// ErrCheckpointVerification reports a fixed, content-free checkpoint verification failure.
	ErrCheckpointVerification = errors.New("checkpoint verification failed")
)

// Checkpoint binds a persisted chain position to a signing-key identity and timestamp.
type Checkpoint struct {
	SchemaVersion int       `json:"schema_version"`
	Sequence      int64     `json:"sequence"`
	ChainHeadHash Digest    `json:"chain_head_hash"`
	SigningKeyID  string    `json:"signing_key_id"`
	CreatedAt     time.Time `json:"created_at"`
	Signature     []byte    `json:"signature"`
}

// CheckpointSigner permits file, TPM, HSM, or KMS implementations without changing checkpoint bytes.
type CheckpointSigner interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

// Ed25519Signer keeps copied demo-mode private key material behind the signer interface.
type Ed25519Signer struct {
	privateKey  [ed25519.PrivateKeySize]byte
	keyID       string
	initialized bool
}

// String returns a fixed marker and never renders private key material.
func (signer Ed25519Signer) String() string {
	return "<checkpoint-signer>"
}

// Format prevents verbose and Go-syntax formatting from exposing private key material.
func (signer Ed25519Signer) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, signer.String())
}

// NewEd25519Signer binds a strict public key identity to copied Ed25519 private key material.
func NewEd25519Signer(keyID string, privateKey ed25519.PrivateKey) (Ed25519Signer, error) {
	if !identifierPattern.MatchString(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return Ed25519Signer{}, ErrCheckpointSigning
	}
	derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	defer clear(derived)
	if subtle.ConstantTimeCompare(derived, privateKey) != 1 {
		return Ed25519Signer{}, ErrCheckpointSigning
	}
	signer := Ed25519Signer{keyID: keyID, initialized: true}
	copy(signer.privateKey[:], privateKey)
	return signer, nil
}

// LoadEd25519SignerFile loads one demo-mode PKCS#8 private key from a restrictive regular file.
func LoadEd25519SignerFile(keyID string, path string) (Ed25519Signer, error) {
	file, openedInfo, err := openRegularFileNoFollow(path)
	if err != nil {
		return Ed25519Signer{}, ErrCheckpointSigning
	}
	defer func() { _ = file.Close() }()
	if openedInfo.Mode().Perm()&0o077 != 0 {
		return Ed25519Signer{}, ErrCheckpointSigning
	}

	const maximumPEMBytes = 16 * 1024
	encoded, err := io.ReadAll(io.LimitReader(file, maximumPEMBytes+1))
	if err != nil || len(encoded) > maximumPEMBytes {
		clear(encoded)
		return Ed25519Signer{}, ErrCheckpointSigning
	}
	defer clear(encoded)
	if !bytes.HasPrefix(encoded, []byte("-----BEGIN PRIVATE KEY-----\n")) {
		return Ed25519Signer{}, ErrCheckpointSigning
	}
	block, remaining := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(remaining) != 0 {
		return Ed25519Signer{}, ErrCheckpointSigning
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Ed25519Signer{}, ErrCheckpointSigning
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return Ed25519Signer{}, ErrCheckpointSigning
	}
	defer clear(privateKey)
	return NewEd25519Signer(keyID, privateKey)
}

// KeyID returns the non-secret identity bound into each checkpoint signature.
func (signer *Ed25519Signer) KeyID() string {
	if signer == nil || !signer.initialized {
		return ""
	}
	return signer.keyID
}

// Destroy clears this signer value's copied private key material.
func (signer *Ed25519Signer) Destroy() {
	if signer == nil {
		return
	}
	clear(signer.privateKey[:])
	signer.keyID = ""
	signer.initialized = false
}

// Sign signs domain-separated canonical checkpoint bytes.
func (signer *Ed25519Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if signer == nil || !signer.initialized || ctx == nil {
		return nil, ErrCheckpointSigning
	}
	select {
	case <-ctx.Done():
		return nil, ErrCheckpointSigning
	default:
	}
	message := make([]byte, 0, len(checkpointSigningDomain)+len(payload))
	message = append(message, checkpointSigningDomain...)
	message = append(message, payload...)
	return ed25519.Sign(signer.privateKey[:], message), nil
}

// CheckpointVerificationKey is a trusted public key and its expected checkpoint identity.
type CheckpointVerificationKey struct {
	publicKey   [ed25519.PublicKeySize]byte
	keyID       string
	initialized bool
}

// NewCheckpointVerificationKey copies a trusted Ed25519 public key and binds its strict identity.
func NewCheckpointVerificationKey(keyID string, publicKey ed25519.PublicKey) (CheckpointVerificationKey, error) {
	if !identifierPattern.MatchString(keyID) || len(publicKey) != ed25519.PublicKeySize {
		return CheckpointVerificationKey{}, ErrCheckpointVerification
	}
	key := CheckpointVerificationKey{keyID: keyID, initialized: true}
	copy(key.publicKey[:], publicKey)
	return key, nil
}

// LoadCheckpointVerificationKeyFile loads one trusted Ed25519 key from a strict PKIX PEM file.
func LoadCheckpointVerificationKeyFile(keyID string, path string) (CheckpointVerificationKey, error) {
	file, _, err := openRegularFileNoFollow(path)
	if err != nil {
		return CheckpointVerificationKey{}, ErrCheckpointVerification
	}
	defer func() { _ = file.Close() }()

	const maximumPEMBytes = 16 * 1024
	encoded, err := io.ReadAll(io.LimitReader(file, maximumPEMBytes+1))
	if err != nil || len(encoded) > maximumPEMBytes {
		return CheckpointVerificationKey{}, ErrCheckpointVerification
	}
	if !bytes.HasPrefix(encoded, []byte("-----BEGIN PUBLIC KEY-----\n")) {
		return CheckpointVerificationKey{}, ErrCheckpointVerification
	}
	block, remaining := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(remaining) != 0 {
		return CheckpointVerificationKey{}, ErrCheckpointVerification
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return CheckpointVerificationKey{}, ErrCheckpointVerification
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return CheckpointVerificationKey{}, ErrCheckpointVerification
	}
	return NewCheckpointVerificationKey(keyID, publicKey)
}

func openRegularFileNoFollow(path string) (*os.File, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, os.ErrInvalid
	}
	return file, info, nil
}

// CreateCheckpoint signs one canonical chain-head statement.
func CreateCheckpoint(
	ctx context.Context,
	sequence int64,
	chainHeadHash Digest,
	createdAt time.Time,
	signer CheckpointSigner,
) (Checkpoint, error) {
	if signer == nil {
		return Checkpoint{}, ErrCheckpointSigning
	}
	checkpoint := Checkpoint{
		SchemaVersion: 1,
		Sequence:      sequence,
		ChainHeadHash: chainHeadHash,
		SigningKeyID:  signer.KeyID(),
		CreatedAt:     createdAt,
	}
	payload, err := canonicalCheckpointPayload(checkpoint)
	if err != nil {
		return Checkpoint{}, ErrCheckpointSigning
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Checkpoint{}, ErrCheckpointSigning
	}
	checkpoint.Signature = append([]byte(nil), signature...)
	return checkpoint, nil
}

// VerifyCheckpoint verifies checkpoint structure, trusted key identity, and Ed25519 signature.
func VerifyCheckpoint(checkpoint Checkpoint, key CheckpointVerificationKey) error {
	if !key.initialized || checkpoint.SigningKeyID != key.keyID || len(checkpoint.Signature) != ed25519.SignatureSize {
		return ErrCheckpointVerification
	}
	payload, err := canonicalCheckpointPayload(checkpoint)
	if err != nil {
		return ErrCheckpointVerification
	}
	message := make([]byte, 0, len(checkpointSigningDomain)+len(payload))
	message = append(message, checkpointSigningDomain...)
	message = append(message, payload...)
	if !ed25519.Verify(key.publicKey[:], message, checkpoint.Signature) {
		return ErrCheckpointVerification
	}
	return nil
}

type canonicalCheckpoint struct {
	SchemaVersion int    `json:"schema_version"`
	Sequence      int64  `json:"sequence"`
	ChainHeadHash string `json:"chain_head_hash"`
	SigningKeyID  string `json:"signing_key_id"`
	CreatedAt     string `json:"created_at"`
}

func canonicalCheckpointPayload(checkpoint Checkpoint) ([]byte, error) {
	if checkpoint.SchemaVersion != 1 ||
		checkpoint.Sequence <= 0 ||
		checkpoint.ChainHeadHash == (Digest{}) ||
		!identifierPattern.MatchString(checkpoint.SigningKeyID) ||
		checkpoint.CreatedAt.IsZero() ||
		checkpoint.CreatedAt.Location() != time.UTC ||
		checkpoint.CreatedAt.Year() < 1 ||
		checkpoint.CreatedAt.Year() > 9999 ||
		checkpoint.CreatedAt.Nanosecond()%1000 != 0 {
		return nil, ErrCheckpointSigning
	}
	return json.Marshal(canonicalCheckpoint{
		SchemaVersion: checkpoint.SchemaVersion,
		Sequence:      checkpoint.Sequence,
		ChainHeadHash: checkpoint.ChainHeadHash.String(),
		SigningKeyID:  checkpoint.SigningKeyID,
		CreatedAt:     checkpoint.CreatedAt.Format(time.RFC3339Nano),
	})
}

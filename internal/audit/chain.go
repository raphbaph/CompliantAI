package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// ContentHMACKeySize is the required deployment content-evidence key size.
	ContentHMACKeySize = 32
	contentHMACDomain  = "compliantai:content-hmac:v1\x00"
	auditChainDomain   = "compliantai:audit-chain:v1\x00"
)

var (
	// ErrInvalidContentHMACKey reports an invalid content-evidence key without exposing it.
	ErrInvalidContentHMACKey = errors.New("invalid content HMAC key")
	// ErrContentHMACUnavailable reports use of an uninitialized digester.
	ErrContentHMACUnavailable = errors.New("content HMAC unavailable")
)

// Digest is a fixed-size SHA-256 or HMAC-SHA-256 value.
type Digest [sha256.Size]byte

// String returns the lowercase hexadecimal digest representation.
func (digest Digest) String() string {
	return hex.EncodeToString(digest[:])
}

// ContentDigester computes deployment-keyed evidence over exact content bytes.
type ContentDigester struct {
	key         [ContentHMACKeySize]byte
	keyID       string
	initialized bool
}

// String returns a fixed marker and never renders key material.
func (digester ContentDigester) String() string {
	return "<content-digester>"
}

// Format prevents verbose and Go-syntax formatting from exposing key material.
func (digester ContentDigester) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, digester.String())
}

// NewContentDigester binds a server-defined key ID to a copied 256-bit deployment key.
func NewContentDigester(keyID string, key []byte) (*ContentDigester, error) {
	if !identifierPattern.MatchString(keyID) || len(key) != ContentHMACKeySize {
		return nil, ErrInvalidContentHMACKey
	}
	digester := &ContentDigester{}
	copy(digester.key[:], key)
	digester.keyID = keyID
	digester.initialized = true
	return digester, nil
}

// KeyID returns the non-secret identifier required to verify retained evidence after rotation.
func (digester *ContentDigester) KeyID() string {
	if digester == nil || !digester.initialized {
		return ""
	}
	return digester.keyID
}

// Sum computes HMAC-SHA-256 over the versioned domain and exact content bytes.
func (digester *ContentDigester) Sum(content []byte) (Digest, error) {
	if digester == nil || !digester.initialized {
		return Digest{}, ErrContentHMACUnavailable
	}
	mac := hmac.New(sha256.New, digester.key[:])
	_, _ = mac.Write([]byte(contentHMACDomain))
	_, _ = mac.Write(content)
	var digest Digest
	copy(digest[:], mac.Sum(nil))
	return digest, nil
}

// Verify reports whether exact content bytes match keyed evidence.
func (digester *ContentDigester) Verify(content []byte, expected Digest) bool {
	actual, err := digester.Sum(content)
	if err != nil {
		return false
	}
	return hmac.Equal(actual[:], expected[:])
}

// EventHash computes the unkeyed V1 chain-integrity hash for a canonical event.
func EventHash(event Event) (Digest, error) {
	canonical, err := Canonical(event)
	if err != nil {
		return Digest{}, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(auditChainDomain))
	_, _ = hash.Write(canonical)
	var digest Digest
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

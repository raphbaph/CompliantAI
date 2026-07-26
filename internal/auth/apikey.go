package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	apiKeyIDBytes        = 16
	apiKeySecretBytes    = 32
	apiKeyBearerPrefix   = "cai_api_v1"
	apiKeyVerifierPrefix = "hmac-sha256:"
)

var (
	// ErrAPIKeyGeneration is returned without exposing random-source or key material details.
	ErrAPIKeyGeneration = errors.New("API key generation failed")
	// ErrAPIKeyUnavailable reports that a generated bearer was already revealed or destroyed.
	ErrAPIKeyUnavailable = errors.New("API key bearer unavailable")
)

var apiKeyVerifierDomain = []byte("compliantai:api-key-verifier:v1\x00")

// generatedAPIKey holds a newly generated API key until its bearer is revealed once.
// It remains package-private so credential state cannot cross the authentication boundary.
type generatedAPIKey struct {
	state *apiKeySecretState
}

type apiKeySecretState struct {
	mu       sync.Mutex
	keyID    string
	verifier string
	secret   []byte
}

func generateAPIKey(random io.Reader) (*generatedAPIKey, error) {
	material := make([]byte, apiKeyIDBytes+apiKeySecretBytes)
	if _, err := io.ReadFull(random, material); err != nil {
		clear(material)
		return nil, ErrAPIKeyGeneration
	}
	defer clear(material)

	keyID := hex.EncodeToString(material[:apiKeyIDBytes])
	secret := append([]byte(nil), material[apiKeyIDBytes:]...)
	return &generatedAPIKey{
		state: &apiKeySecretState{
			keyID:    keyID,
			verifier: encodeVerifier(keyID, secret),
			secret:   secret,
		},
	}, nil
}

// String redacts generated credential material under ordinary formatting.
func (generatedAPIKey) String() string { return "[REDACTED API KEY]" }

// GoString redacts generated credential material under Go-syntax formatting.
func (generatedAPIKey) GoString() string { return "auth.generatedAPIKey{[REDACTED]}" }

// Format redacts generated credential material under every formatting verb.
func (generatedAPIKey) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED API KEY]")
}

// KeyID returns the non-secret public key identifier.
func (credential *generatedAPIKey) KeyID() string {
	if credential == nil || credential.state == nil {
		return ""
	}
	credential.state.mu.Lock()
	defer credential.state.mu.Unlock()
	return credential.state.keyID
}

// Verifier returns the non-bearer verifier intended for approved persistence.
func (credential *generatedAPIKey) Verifier() string {
	if credential == nil || credential.state == nil {
		return ""
	}
	credential.state.mu.Lock()
	defer credential.state.mu.Unlock()
	return credential.state.verifier
}

// Reveal releases the full bearer exactly once and clears the held secret bytes.
func (credential *generatedAPIKey) Reveal() (string, error) {
	if credential == nil || credential.state == nil {
		return "", ErrAPIKeyUnavailable
	}
	credential.state.mu.Lock()
	defer credential.state.mu.Unlock()
	if len(credential.state.secret) != apiKeySecretBytes {
		return "", ErrAPIKeyUnavailable
	}
	encodedSecretBytes := base64.RawURLEncoding.EncodedLen(len(credential.state.secret))
	bearerBytes := make([]byte, len(apiKeyBearerPrefix)+1+len(credential.state.keyID)+1+encodedSecretBytes)
	offset := copy(bearerBytes, apiKeyBearerPrefix)
	bearerBytes[offset] = '.'
	offset++
	offset += copy(bearerBytes[offset:], credential.state.keyID)
	bearerBytes[offset] = '.'
	offset++
	base64.RawURLEncoding.Encode(bearerBytes[offset:], credential.state.secret)
	bearer := string(bearerBytes)
	clear(bearerBytes)
	clear(credential.state.secret)
	credential.state.secret = nil
	return bearer, nil
}

// Destroy clears an unrevealed secret without returning it.
func (credential *generatedAPIKey) Destroy() {
	if credential == nil {
		return
	}
	if credential.state != nil {
		credential.state.mu.Lock()
		defer credential.state.mu.Unlock()
		clear(credential.state.secret)
		credential.state.secret = nil
	}
}

// VerifyAPIKey checks a bearer against a persisted non-bearer verifier.
func VerifyAPIKey(bearer, storedVerifier string) bool {
	keyID, secret, ok := parseBearer(bearer)
	if !ok {
		return false
	}
	defer clear(secret)

	provided, ok := decodeVerifier(storedVerifier)
	if !ok {
		return false
	}
	defer clear(provided)

	expected := verifierDigest(keyID, secret)
	defer clear(expected)
	return hmac.Equal(expected, provided)
}

func parseBearer(bearer string) (string, []byte, bool) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 || parts[0] != apiKeyBearerPrefix || len(parts[1]) != apiKeyIDBytes*2 {
		return "", nil, false
	}
	keyIDBytes, err := hex.DecodeString(parts[1])
	if err != nil || hex.EncodeToString(keyIDBytes) != parts[1] {
		clear(keyIDBytes)
		return "", nil, false
	}
	clear(keyIDBytes)
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != apiKeySecretBytes || base64.RawURLEncoding.EncodeToString(secret) != parts[2] {
		clear(secret)
		return "", nil, false
	}
	return parts[1], secret, true
}

func encodeVerifier(keyID string, secret []byte) string {
	return apiKeyVerifierPrefix + hex.EncodeToString(verifierDigest(keyID, secret))
}

func decodeVerifier(encoded string) ([]byte, bool) {
	if !strings.HasPrefix(encoded, apiKeyVerifierPrefix) || len(encoded) != len(apiKeyVerifierPrefix)+sha256.Size*2 {
		return nil, false
	}
	digest, err := hex.DecodeString(encoded[len(apiKeyVerifierPrefix):])
	if err != nil || hex.EncodeToString(digest) != encoded[len(apiKeyVerifierPrefix):] {
		clear(digest)
		return nil, false
	}
	return digest, true
}

func verifierDigest(keyID string, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(apiKeyVerifierDomain)
	_, _ = mac.Write([]byte(keyID))
	return mac.Sum(nil)
}

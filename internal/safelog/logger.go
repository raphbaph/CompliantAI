package safelog

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sync"
	"time"
)

// AuthorizationErrorCode is a fixed, content-free authorization failure code.
type AuthorizationErrorCode string

const (
	AuthMissingCredentials AuthorizationErrorCode = "missing_credentials"
	AuthInvalidCredentials AuthorizationErrorCode = "invalid_credentials"
	AuthPolicyDenied       AuthorizationErrorCode = "policy_denied"
	AuthBudgetDenied       AuthorizationErrorCode = "budget_denied"
	AuthInternalFailure    AuthorizationErrorCode = "internal_failure"
)

// BackendErrorCode is a fixed, content-free inference backend failure code.
type BackendErrorCode string

const (
	BackendTimeout          BackendErrorCode = "timeout"
	BackendUnavailable      BackendErrorCode = "unavailable"
	BackendInvalidResponse  BackendErrorCode = "invalid_response"
	BackendResponseTooLarge BackendErrorCode = "response_too_large"
	BackendUsageInvalid     BackendErrorCode = "usage_invalid"
)

// ErrWrite is returned when a structured event cannot be written.
var ErrWrite = errors.New("safe log write failed")

var (
	principalIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyIDPrefixPattern = regexp.MustCompile(`^[0-9a-f]{8}$`)
)

// Logger writes schema-bound content-free operational events as JSON Lines.
type Logger struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

// New creates a schema-bound logger writing to output.
func New(output io.Writer) *Logger {
	if output == nil {
		return &Logger{}
	}
	return &Logger{encoder: json.NewEncoder(output)}
}

// AuthorizationFailure records an authorization failure using a fixed code.
func (logger *Logger) AuthorizationFailure(code AuthorizationErrorCode) error {
	return logger.write(errorEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Event:     "authorization_failure",
		Code:      string(normalizeAuthorizationCode(code)),
	})
}

// BackendFailure records an inference backend failure using a fixed code.
func (logger *Logger) BackendFailure(code BackendErrorCode) error {
	return logger.write(errorEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Event:     "backend_failure",
		Code:      string(normalizeBackendCode(code)),
	})
}

// APIKeyAuthenticationSuccess records only bounded non-secret API-key identity evidence.
func (logger *Logger) APIKeyAuthenticationSuccess(principalID, keyIDPrefix string) error {
	if !principalIDPattern.MatchString(principalID) || !keyIDPrefixPattern.MatchString(keyIDPrefix) {
		return ErrWrite
	}
	return logger.writeAuthenticationSuccess(authenticationSuccessEvent{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		Event:       "authentication_success",
		AuthMethod:  "api_key",
		PrincipalID: principalID,
		KeyIDPrefix: keyIDPrefix,
	})
}

func normalizeAuthorizationCode(code AuthorizationErrorCode) AuthorizationErrorCode {
	switch code {
	case AuthMissingCredentials,
		AuthInvalidCredentials,
		AuthPolicyDenied,
		AuthBudgetDenied,
		AuthInternalFailure:
		return code
	default:
		return "unknown"
	}
}

func normalizeBackendCode(code BackendErrorCode) BackendErrorCode {
	switch code {
	case BackendTimeout,
		BackendUnavailable,
		BackendInvalidResponse,
		BackendResponseTooLarge,
		BackendUsageInvalid:
		return code
	default:
		return "unknown"
	}
}

type errorEvent struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
	Code      string `json:"code"`
}

type authenticationSuccessEvent struct {
	Timestamp   string `json:"timestamp"`
	Event       string `json:"event"`
	AuthMethod  string `json:"auth_method"`
	PrincipalID string `json:"principal_id"`
	KeyIDPrefix string `json:"key_id_prefix"`
}

func (logger *Logger) write(event errorEvent) error {
	if logger == nil || logger.encoder == nil {
		return ErrWrite
	}

	logger.mu.Lock()
	defer logger.mu.Unlock()

	if err := logger.encoder.Encode(event); err != nil {
		return ErrWrite
	}
	return nil
}

func (logger *Logger) writeAuthenticationSuccess(event authenticationSuccessEvent) error {
	if logger == nil || logger.encoder == nil {
		return ErrWrite
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if err := logger.encoder.Encode(event); err != nil {
		return ErrWrite
	}
	return nil
}

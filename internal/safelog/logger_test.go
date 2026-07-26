package safelog

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuthorizationFailureEmitsApprovedFields(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output)

	if err := logger.AuthorizationFailure(AuthMissingCredentials); err != nil {
		t.Fatalf("AuthorizationFailure() error = %v", err)
	}

	assertErrorEvent(t, output.Bytes(), "authorization_failure", "missing_credentials")
}

func TestBackendFailureEmitsApprovedFields(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output)

	if err := logger.BackendFailure(BackendTimeout); err != nil {
		t.Fatalf("BackendFailure() error = %v", err)
	}

	assertErrorEvent(t, output.Bytes(), "backend_failure", "timeout")
}

func TestAPIKeyAuthenticationSuccessEmitsOnlyApprovedIdentityFields(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output)
	const principalID = "00000000-0000-4000-8000-000000000011"
	const keyIDPrefix = "a1b2c3d4"
	const secretCanary = "cai_api_v1.a1b2c3d4.API-KEY-CANARY-secret"

	if err := logger.APIKeyAuthenticationSuccess(principalID, keyIDPrefix); err != nil {
		t.Fatalf("APIKeyAuthenticationSuccess() error = %v", err)
	}
	if strings.Contains(output.String(), secretCanary) || strings.Contains(output.String(), "secret_verifier") {
		t.Fatal("authentication success log contains credential material")
	}
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode authentication event: %v", err)
	}
	want := map[string]any{
		"event":         "authentication_success",
		"auth_method":   "api_key",
		"principal_id":  principalID,
		"key_id_prefix": keyIDPrefix,
	}
	if len(event) != len(want)+1 {
		t.Fatalf("authentication event fields = %#v", event)
	}
	for key, value := range want {
		if event[key] != value {
			t.Fatalf("authentication event %s = %#v, want %#v", key, event[key], value)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, event["timestamp"].(string)); err != nil {
		t.Fatalf("authentication timestamp: %v", err)
	}
}

func TestConcurrentWritesProduceCompleteJSONLines(t *testing.T) {
	const eventCount = 64
	var output bytes.Buffer
	logger := New(&output)
	var wait sync.WaitGroup
	errorsCh := make(chan error, eventCount)

	for index := 0; index < eventCount; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			if index%2 == 0 {
				errorsCh <- logger.AuthorizationFailure(AuthPolicyDenied)
				return
			}
			errorsCh <- logger.BackendFailure(BackendUnavailable)
		}(index)
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != eventCount {
		t.Fatalf("JSONL record count = %d, want %d", len(lines), eventCount)
	}
	for index, line := range lines {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("record %d is malformed JSON: %v", index, err)
		}
		if len(event) != 3 || event["timestamp"] == nil || event["event"] == nil || event["code"] == nil {
			t.Fatalf("record %d has unexpected schema: %#v", index, event)
		}
	}
}

func TestUninitializedLoggerReturnsErrWrite(t *testing.T) {
	var zero Logger
	var nilLogger *Logger
	loggers := []*Logger{&zero, nilLogger, New(nil)}

	for index, logger := range loggers {
		if err := logger.AuthorizationFailure(AuthMissingCredentials); !errors.Is(err, ErrWrite) {
			t.Fatalf("logger %d AuthorizationFailure() error = %v, want ErrWrite", index, err)
		}
		if err := logger.BackendFailure(BackendTimeout); !errors.Is(err, ErrWrite) {
			t.Fatalf("logger %d BackendFailure() error = %v, want ErrWrite", index, err)
		}
	}
}

func TestLoggerExposesOnlyTypedEventMethods(t *testing.T) {
	loggerType := reflect.TypeOf((*Logger)(nil))
	wantMethods := map[string][]reflect.Type{
		"AuthorizationFailure":        {reflect.TypeOf(AuthorizationErrorCode(""))},
		"BackendFailure":              {reflect.TypeOf(BackendErrorCode(""))},
		"APIKeyAuthenticationSuccess": {reflect.TypeOf(""), reflect.TypeOf("")},
	}

	if loggerType.NumMethod() != len(wantMethods) {
		t.Fatalf("Logger exported method count = %d, want %d", loggerType.NumMethod(), len(wantMethods))
	}
	for name, wantArguments := range wantMethods {
		method, exists := loggerType.MethodByName(name)
		if !exists {
			t.Fatalf("Logger method %q is missing", name)
		}
		if method.Type.NumIn() != len(wantArguments)+1 {
			t.Fatalf("Logger.%s input signature = %v", name, method.Type)
		}
		for index, wantArgument := range wantArguments {
			if method.Type.In(index+1) != wantArgument {
				t.Fatalf("Logger.%s input %d = %v, want %v", name, index, method.Type.In(index+1), wantArgument)
			}
		}
		if method.Type.NumOut() != 1 || method.Type.Out(0) != reflect.TypeOf((*error)(nil)).Elem() {
			t.Fatalf("Logger.%s output signature = %v, want error", name, method.Type)
		}
	}
}

func TestDeclaredCodesArePreserved(t *testing.T) {
	authCodes := []AuthorizationErrorCode{
		AuthMissingCredentials,
		AuthInvalidCredentials,
		AuthPolicyDenied,
		AuthBudgetDenied,
		AuthInternalFailure,
	}
	backendCodes := []BackendErrorCode{
		BackendTimeout,
		BackendUnavailable,
		BackendInvalidResponse,
		BackendResponseTooLarge,
		BackendUsageInvalid,
	}

	for _, code := range authCodes {
		var output bytes.Buffer
		if err := New(&output).AuthorizationFailure(code); err != nil {
			t.Fatalf("AuthorizationFailure(%q): %v", code, err)
		}
		assertErrorEvent(t, output.Bytes(), "authorization_failure", string(code))
	}
	for _, code := range backendCodes {
		var output bytes.Buffer
		if err := New(&output).BackendFailure(code); err != nil {
			t.Fatalf("BackendFailure(%q): %v", code, err)
		}
		assertErrorEvent(t, output.Bytes(), "backend_failure", string(code))
	}
}

func TestUnknownCodesCannotInjectContent(t *testing.T) {
	canaries := []string{
		"PROMPT-CANARY-private-client-question",
		"RESPONSE-CANARY-private-model-answer",
		"API-KEY-CANARY-sk-secret",
		"JWT-CANARY-eyJhbGciOi",
		"BACKEND-ERROR-CANARY-upstream-body",
	}
	var output bytes.Buffer
	logger := New(&output)

	for index, canary := range canaries {
		var err error
		if index%2 == 0 {
			err = logger.AuthorizationFailure(AuthorizationErrorCode(canary))
		} else {
			err = logger.BackendFailure(BackendErrorCode(canary))
		}
		if err != nil {
			t.Fatalf("write canary event %d: %v", index, err)
		}
	}

	logs := output.String()
	for _, canary := range canaries {
		if strings.Contains(logs, canary) {
			t.Fatalf("captured logs contain canary %q", canary)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("decode event: %v", err)
		}
		if got := event["code"]; got != "unknown" {
			t.Fatalf("unknown code normalized to %#v, want unknown", got)
		}
	}
}

func assertErrorEvent(t *testing.T, encoded []byte, wantEvent, wantCode string) {
	t.Helper()

	var event map[string]any
	if err := json.Unmarshal(encoded, &event); err != nil {
		t.Fatalf("decode log event: %v", err)
	}
	wantKeys := map[string]bool{"timestamp": true, "event": true, "code": true}
	if len(event) != len(wantKeys) {
		t.Fatalf("event fields = %#v, want only %#v", event, wantKeys)
	}
	for key := range event {
		if !wantKeys[key] {
			t.Fatalf("unexpected event field %q", key)
		}
	}
	if got := event["event"]; got != wantEvent {
		t.Fatalf("event = %#v, want %q", got, wantEvent)
	}
	if got := event["code"]; got != wantCode {
		t.Fatalf("code = %#v, want %q", got, wantCode)
	}
	if _, err := time.Parse(time.RFC3339Nano, event["timestamp"].(string)); err != nil {
		t.Fatalf("timestamp is not RFC3339Nano: %v", err)
	}
}

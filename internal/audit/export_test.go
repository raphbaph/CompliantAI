package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestCheckpointExportVerifiesOffline(t *testing.T) {
	records := chainRecords(t, 4)
	signer, verificationKey := checkpointTestKeys(t)
	checkpoint, err := CreateCheckpoint(
		context.Background(),
		records[len(records)-1].Sequence,
		records[len(records)-1].EventHash,
		time.Date(2026, time.July, 24, 15, 0, 0, 0, time.UTC),
		&signer,
	)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}

	encoded, err := MarshalExport(records, checkpoint)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	encodedAgain, err := MarshalExport(records, checkpoint)
	if err != nil {
		t.Fatalf("marshal export again: %v", err)
	}
	if !bytes.Equal(encoded, encodedAgain) {
		t.Fatal("export bytes are not deterministic")
	}
	if err := VerifyExport(encoded, verificationKey); err != nil {
		t.Fatalf("verify export without database access: %v", err)
	}

	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x23}, ed25519.SeedSize))
	secretEncodings := []string{
		base64.StdEncoding.EncodeToString(privateKey),
		base64.RawStdEncoding.EncodeToString(privateKey),
	}
	for _, secret := range secretEncodings {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("export contains private key material")
		}
	}
	assertNoForbiddenExportKeys(t, encoded)
}

func TestCheckpointExportMatchesStrictJSONSchema(t *testing.T) {
	records := chainRecords(t, 2)
	signer, _ := checkpointTestKeys(t)
	checkpoint, err := CreateCheckpoint(
		context.Background(),
		2,
		records[1].EventHash,
		time.Date(2026, time.July, 24, 15, 0, 0, 0, time.UTC),
		&signer,
	)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	exported, err := MarshalExport(records, checkpoint)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	for path, schemaURL := range map[string]string{
		"../../schemas/audit-event-v1.schema.json":  "https://compliantai.example/schemas/audit-event-v1.schema.json",
		"../../schemas/audit-export-v1.schema.json": "https://compliantai.example/schemas/audit-export-v1.schema.json",
	} {
		encodedSchema, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read schema: %v", err)
		}
		var document any
		if err := json.Unmarshal(encodedSchema, &document); err != nil {
			t.Fatalf("parse schema: %v", err)
		}
		if err := compiler.AddResource(schemaURL, document); err != nil {
			t.Fatalf("add schema resource: %v", err)
		}
	}
	schema, err := compiler.Compile("https://compliantai.example/schemas/audit-export-v1.schema.json")
	if err != nil {
		t.Fatalf("compile export schema: %v", err)
	}
	var instance any
	if err := json.Unmarshal(exported, &instance); err != nil {
		t.Fatalf("parse export: %v", err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("validate export: %v", err)
	}
	checkpointDocument := instance.(map[string]any)["checkpoint"].(map[string]any)
	checkpointDocument["signing_key_id"] = "Checkpoint@Key+v1"
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("schema identifier parity: %v", err)
	}
	originalHead := checkpointDocument["chain_head_hash"]
	checkpointDocument["chain_head_hash"] = strings.Repeat("0", 64)
	if err := schema.Validate(instance); err == nil {
		t.Fatal("schema accepted an all-zero checkpoint head")
	}
	checkpointDocument["chain_head_hash"] = originalHead
	recordDocument := instance.(map[string]any)["records"].([]any)[0].(map[string]any)
	originalEventHash := recordDocument["event_hash"]
	recordDocument["event_hash"] = strings.Repeat("0", 64)
	if err := schema.Validate(instance); err == nil {
		t.Fatal("schema accepted an all-zero event hash")
	}
	recordDocument["event_hash"] = originalEventHash

	tampered := instance.(map[string]any)
	tampered["records"].([]any)[0].(map[string]any)["prompt"] = "PLAINTEXT-CANARY"
	if err := schema.Validate(tampered); err == nil {
		t.Fatal("schema accepted an added plaintext-bearing field")
	}
}

func TestCheckpointExportReportsFirstAffectedSequence(t *testing.T) {
	records := chainRecords(t, 4)
	signer, verificationKey := checkpointTestKeys(t)
	checkpoint, err := CreateCheckpoint(
		context.Background(),
		4,
		records[3].EventHash,
		time.Date(2026, time.July, 24, 15, 0, 0, 0, time.UTC),
		&signer,
	)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	encoded, err := MarshalExport(records, checkpoint)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	original := decodeExportTestEnvelope(t, encoded)

	tests := []struct {
		name         string
		mutate       func(exportTestEnvelope) exportTestEnvelope
		wantSequence int64
	}{
		{
			name: "edited event",
			mutate: func(value exportTestEnvelope) exportTestEnvelope {
				value.Records[1] = bytes.Replace(value.Records[1], []byte(`"local-legal"`), []byte(`"local-medic"`), 1)
				return value
			},
			wantSequence: 2,
		},
		{
			name: "deleted event",
			mutate: func(value exportTestEnvelope) exportTestEnvelope {
				value.Records = append(value.Records[:1], value.Records[2:]...)
				return value
			},
			wantSequence: 2,
		},
		{
			name: "deleted final event",
			mutate: func(value exportTestEnvelope) exportTestEnvelope {
				value.Records = value.Records[:len(value.Records)-1]
				return value
			},
			wantSequence: 4,
		},
		{
			name: "inserted event",
			mutate: func(value exportTestEnvelope) exportTestEnvelope {
				value.Records = append(value.Records[:1], append([]json.RawMessage{value.Records[1]}, value.Records[1:]...)...)
				return value
			},
			wantSequence: 2,
		},
		{
			name: "reordered events",
			mutate: func(value exportTestEnvelope) exportTestEnvelope {
				value.Records[0], value.Records[1] = value.Records[1], value.Records[0]
				return value
			},
			wantSequence: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := exportTestEnvelope{
				SchemaVersion: original.SchemaVersion,
				Records:       append([]json.RawMessage(nil), original.Records...),
				Checkpoint:    append(json.RawMessage(nil), original.Checkpoint...),
			}
			mutated, err := json.Marshal(test.mutate(value))
			if err != nil {
				t.Fatalf("marshal mutated export: %v", err)
			}
			err = VerifyExport(mutated, verificationKey)
			var verificationError *VerificationError
			if !errors.As(err, &verificationError) || verificationError.Sequence != test.wantSequence {
				t.Fatalf("VerifyExport() error = %v, want sequence %d", err, test.wantSequence)
			}
		})
	}
}

func TestCheckpointExportRejectsMisalignedOrUntrustedCheckpoint(t *testing.T) {
	records := chainRecords(t, 2)
	signer, verificationKey := checkpointTestKeys(t)
	checkpoint, err := CreateCheckpoint(
		context.Background(),
		2,
		records[1].EventHash,
		time.Date(2026, time.July, 24, 15, 0, 0, 0, time.UTC),
		&signer,
	)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}

	misaligned := checkpoint
	misaligned.Sequence = 1
	if _, err := MarshalExport(records, misaligned); !errors.Is(err, ErrInvalidExport) {
		t.Fatalf("misaligned sequence error = %v", err)
	}
	misaligned = checkpoint
	misaligned.ChainHeadHash[0]++
	if _, err := MarshalExport(records, misaligned); !errors.Is(err, ErrInvalidExport) {
		t.Fatalf("misaligned head error = %v", err)
	}
	invalidSignature := checkpoint
	invalidSignature.Signature = invalidSignature.Signature[:ed25519.SignatureSize-1]
	if _, err := MarshalExport(records, invalidSignature); !errors.Is(err, ErrInvalidExport) {
		t.Fatalf("short signature error = %v", err)
	}

	encoded, err := MarshalExport(records, checkpoint)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	otherPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	otherKey, err := NewCheckpointVerificationKey("checkpoint-key-v1", otherPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("new other verification key: %v", err)
	}
	if err := VerifyExport(encoded, otherKey); !errors.Is(err, ErrCheckpointVerification) {
		t.Fatalf("untrusted checkpoint error = %v", err)
	}
	if err := VerifyExport(append(encoded, []byte(`{"extra":true}`)...), verificationKey); !errors.Is(err, ErrInvalidExport) {
		t.Fatalf("trailing document error = %v", err)
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	object["content"] = json.RawMessage(`"PRIVATE-CONTENT-CANARY"`)
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("marshal unknown-field export: %v", err)
	}
	if err := VerifyExport(unknown, verificationKey); !errors.Is(err, ErrInvalidExport) {
		t.Fatalf("unknown field error = %v", err)
	}
	if strings.Contains(ErrInvalidExport.Error(), "PRIVATE-CONTENT-CANARY") {
		t.Fatal("invalid export error contains rejected content")
	}
}

func TestCheckpointExportRejectsNoncanonicalEnvelopeJSON(t *testing.T) {
	records := chainRecords(t, 1)
	signer, verificationKey := checkpointTestKeys(t)
	checkpoint, err := CreateCheckpoint(
		context.Background(),
		1,
		records[0].EventHash,
		time.Date(2026, time.July, 24, 15, 0, 0, 0, time.UTC),
		&signer,
	)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	exported, err := MarshalExport(records, checkpoint)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}

	decoded := decodeExportTestEnvelope(t, exported)
	reorderedRecords, err := json.Marshal(decoded.Records)
	if err != nil {
		t.Fatalf("marshal reordered records: %v", err)
	}
	reordered := append([]byte(`{"records":`), reorderedRecords...)
	reordered = append(reordered, []byte(`,"checkpoint":`)...)
	reordered = append(reordered, decoded.Checkpoint...)
	reordered = append(reordered, []byte(`,"schema_version":1}`)...)

	canonicalSignature := base64.StdEncoding.EncodeToString(checkpoint.Signature)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lastDataIndex := len(canonicalSignature) - 3
	replacementIndex := strings.IndexByte(alphabet, canonicalSignature[lastDataIndex]) | 1
	noncanonicalSignature := canonicalSignature[:lastDataIndex] + string(alphabet[replacementIndex]) + canonicalSignature[lastDataIndex+1:]

	for name, noncanonical := range map[string][]byte{
		"leading whitespace":  []byte(" " + string(exported)),
		"duplicate field":     bytes.Replace(exported, []byte(`{"schema_version":1,`), []byte(`{"schema_version":1,"schema_version":1,`), 1),
		"field order":         reordered,
		"base64 padding bits": bytes.Replace(exported, []byte(canonicalSignature), []byte(noncanonicalSignature), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyExport(noncanonical, verificationKey); !errors.Is(err, ErrInvalidExport) {
				t.Fatalf("VerifyExport() error = %v", err)
			}
		})
	}
}

type exportTestEnvelope struct {
	SchemaVersion int               `json:"schema_version"`
	Records       []json.RawMessage `json:"records"`
	Checkpoint    json.RawMessage   `json:"checkpoint"`
}

func decodeExportTestEnvelope(t *testing.T, encoded []byte) exportTestEnvelope {
	t.Helper()
	var value exportTestEnvelope
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatalf("decode export envelope: %v", err)
	}
	return value
}

func assertNoForbiddenExportKeys(t *testing.T, encoded []byte) {
	t.Helper()
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatalf("decode export keys: %v", err)
	}
	forbidden := map[string]struct{}{
		"prompt": {}, "content": {}, "message": {}, "request_body": {}, "response_body": {}, "details": {}, "metadata": {},
	}
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, blocked := forbidden[key]; blocked {
					t.Fatalf("export contains forbidden key %q", key)
				}
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
}

package audit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

var ErrInvalidExport = errors.New("invalid audit export")

// MarshalExport returns deterministic V1 JSON containing a complete chain through one checkpoint.
func MarshalExport(records []Record, checkpoint Checkpoint) ([]byte, error) {
	if len(records) == 0 || VerifyChain(records) != nil {
		return nil, ErrInvalidExport
	}
	last := records[len(records)-1]
	if checkpoint.Sequence != last.Sequence || checkpoint.ChainHeadHash != last.EventHash || len(checkpoint.Signature) != ed25519.SignatureSize {
		return nil, ErrInvalidExport
	}
	if _, err := canonicalCheckpointPayload(checkpoint); err != nil {
		return nil, ErrInvalidExport
	}

	wire := exportEnvelope{
		SchemaVersion: 1,
		Records:       make([]exportRecord, 0, len(records)),
		Checkpoint:    checkpointToWire(checkpoint),
	}
	for _, record := range records {
		canonicalEvent, err := Canonical(record.Event)
		if err != nil {
			return nil, ErrInvalidExport
		}
		wire.Records = append(wire.Records, exportRecord{
			Sequence:  record.Sequence,
			Event:     json.RawMessage(canonicalEvent),
			EventHash: record.EventHash.String(),
		})
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, ErrInvalidExport
	}
	return encoded, nil
}

// VerifyExport verifies strict V1 JSON, the complete event chain, checkpoint alignment, and signature.
func VerifyExport(encoded []byte, verificationKey CheckpointVerificationKey) error {
	var wire exportEnvelope
	if err := decodeStrictJSON(encoded, &wire); err != nil || wire.SchemaVersion != 1 || len(wire.Records) == 0 {
		return ErrInvalidExport
	}
	canonicalEnvelope, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonicalEnvelope, encoded) {
		return ErrInvalidExport
	}
	checkpoint, err := checkpointFromWire(wire.Checkpoint)
	if err != nil {
		return ErrInvalidExport
	}
	if err := VerifyCheckpoint(checkpoint, verificationKey); err != nil {
		return ErrCheckpointVerification
	}

	records := make([]Record, 0, len(wire.Records))
	for index, wireRecord := range wire.Records {
		expectedSequence := int64(index + 1)
		if wireRecord.Sequence != expectedSequence {
			affected := expectedSequence
			if wireRecord.Sequence > 0 && wireRecord.Sequence < affected {
				affected = wireRecord.Sequence
			}
			return &VerificationError{Sequence: affected}
		}
		event, decodeErr := eventFromCanonicalJSON(wireRecord.Event)
		if decodeErr != nil {
			return &VerificationError{Sequence: wireRecord.Sequence}
		}
		eventHash, ok := digestFromHex(wireRecord.EventHash)
		if !ok {
			return &VerificationError{Sequence: wireRecord.Sequence}
		}
		records = append(records, Record{Sequence: wireRecord.Sequence, Event: event, EventHash: eventHash})
	}
	if err := VerifyChain(records); err != nil {
		return err
	}
	last := records[len(records)-1]
	if checkpoint.Sequence != last.Sequence {
		affected := checkpoint.Sequence
		if last.Sequence > checkpoint.Sequence {
			affected = checkpoint.Sequence + 1
		}
		return &VerificationError{Sequence: affected}
	}
	if checkpoint.ChainHeadHash != last.EventHash {
		return &VerificationError{Sequence: checkpoint.Sequence}
	}
	return nil
}

type exportEnvelope struct {
	SchemaVersion int              `json:"schema_version"`
	Records       []exportRecord   `json:"records"`
	Checkpoint    checkpointRecord `json:"checkpoint"`
}

type exportRecord struct {
	Sequence  int64           `json:"sequence"`
	Event     json.RawMessage `json:"event"`
	EventHash string          `json:"event_hash"`
}

type checkpointRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Sequence      int64  `json:"sequence"`
	ChainHeadHash string `json:"chain_head_hash"`
	SigningKeyID  string `json:"signing_key_id"`
	CreatedAt     string `json:"created_at"`
	Signature     []byte `json:"signature"`
}

func checkpointToWire(checkpoint Checkpoint) checkpointRecord {
	return checkpointRecord{
		SchemaVersion: checkpoint.SchemaVersion,
		Sequence:      checkpoint.Sequence,
		ChainHeadHash: checkpoint.ChainHeadHash.String(),
		SigningKeyID:  checkpoint.SigningKeyID,
		CreatedAt:     checkpoint.CreatedAt.Format(time.RFC3339Nano),
		Signature:     append([]byte(nil), checkpoint.Signature...),
	}
}

func checkpointFromWire(wire checkpointRecord) (Checkpoint, error) {
	head, ok := digestFromHex(wire.ChainHeadHash)
	if !ok {
		return Checkpoint{}, ErrInvalidExport
	}
	createdAt, err := time.Parse(time.RFC3339Nano, wire.CreatedAt)
	if err != nil || createdAt.Location() != time.UTC || createdAt.Format(time.RFC3339Nano) != wire.CreatedAt {
		return Checkpoint{}, ErrInvalidExport
	}
	checkpoint := Checkpoint{
		SchemaVersion: wire.SchemaVersion,
		Sequence:      wire.Sequence,
		ChainHeadHash: head,
		SigningKeyID:  wire.SigningKeyID,
		CreatedAt:     createdAt,
		Signature:     append([]byte(nil), wire.Signature...),
	}
	if _, err := canonicalCheckpointPayload(checkpoint); err != nil {
		return Checkpoint{}, ErrInvalidExport
	}
	return checkpoint, nil
}

func eventFromCanonicalJSON(encoded []byte) (Event, error) {
	var wire canonicalEvent
	if err := decodeStrictJSON(encoded, &wire); err != nil {
		return Event{}, ErrInvalidExport
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, wire.OccurredAt)
	if err != nil || occurredAt.Location() != time.UTC || occurredAt.Format(time.RFC3339Nano) != wire.OccurredAt {
		return Event{}, ErrInvalidExport
	}
	event := Event{
		SchemaVersion:             wire.SchemaVersion,
		EventID:                   wire.EventID,
		RunID:                     wire.RunID,
		EventType:                 wire.EventType,
		OccurredAt:                occurredAt,
		PrincipalID:               wire.PrincipalID,
		AuthMethod:                wire.AuthMethod,
		Decision:                  wire.Decision,
		DecisionReasonCodes:       append([]string{}, wire.DecisionReasonCodes...),
		RequestedModel:            wire.RequestedModel,
		ResolvedBackend:           wire.ResolvedBackend,
		ContentHMACKeyID:          wire.ContentHMACKeyID,
		RequestBytes:              wire.RequestBytes,
		ResponseBytes:             copyInt64Pointer(wire.ResponseBytes),
		PIICategories:             append([]string{}, wire.PIICategories...),
		PIIMatchCounts:            mapCopy(wire.PIIMatchCounts),
		HealthIndicatorCategories: append([]string{}, wire.HealthIndicatorCategories...),
		SecretCategories:          append([]string{}, wire.SecretCategories...),
		InputTokens:               copyInt64Pointer(wire.InputTokens),
		OutputTokens:              copyInt64Pointer(wire.OutputTokens),
		ReservedCostMicros:        copyInt64Pointer(wire.ReservedCostMicros),
		ActualCostMicros:          copyInt64Pointer(wire.ActualCostMicros),
		Status:                    wire.Status,
		ErrorCode:                 copyStringPointer(wire.ErrorCode),
		SoftwareVersion:           wire.SoftwareVersion,
	}
	if !decodeRequiredDigest(&event.PolicyVersionHash, wire.PolicyVersionHash) ||
		!decodeRequiredDigest(&event.RequestHMAC, wire.RequestHMAC) ||
		!decodeRequiredDigest(&event.DetectorBundleHash, wire.DetectorBundleHash) ||
		!decodeRequiredDigest(&event.PreviousEventHash, wire.PreviousEventHash) ||
		!decodeRequiredDigest(&event.ConfigHash, wire.ConfigHash) {
		return Event{}, ErrInvalidExport
	}
	if wire.OIDCIssuerHash != nil {
		digest, ok := digestFromHex(*wire.OIDCIssuerHash)
		if !ok {
			return Event{}, ErrInvalidExport
		}
		event.OIDCIssuerHash = &digest
	}
	if wire.ResponseHMAC != nil {
		digest, ok := digestFromHex(*wire.ResponseHMAC)
		if !ok {
			return Event{}, ErrInvalidExport
		}
		event.ResponseHMAC = &digest
	}
	if err := event.Validate(); err != nil {
		return Event{}, ErrInvalidExport
	}
	canonical, err := Canonical(event)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Event{}, ErrInvalidExport
	}
	return event, nil
}

func decodeStrictJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidExport
	}
	return nil
}

func digestFromHex(encoded string) (Digest, bool) {
	if len(encoded) != hex.EncodedLen(len(Digest{})) {
		return Digest{}, false
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || hex.EncodeToString(raw) != encoded {
		return Digest{}, false
	}
	var digest Digest
	copy(digest[:], raw)
	return digest, true
}

func decodeRequiredDigest(destination *Digest, encoded string) bool {
	digest, ok := digestFromHex(encoded)
	if ok {
		*destination = digest
	}
	return ok
}

func copyInt64Pointer(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func copyStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

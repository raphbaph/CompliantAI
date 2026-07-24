package audit

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrRepositoryUnavailable reports an unusable audit repository.
	ErrRepositoryUnavailable = errors.New("audit repository unavailable")
	// ErrAppend reports a failed transactional audit append without database details.
	ErrAppend = errors.New("audit append failed")
	// ErrRead reports a failed audit read without database details.
	ErrRead = errors.New("audit read failed")
	// ErrCheckpointStore reports a failed checkpoint write without database details.
	ErrCheckpointStore = errors.New("audit checkpoint store failed")
	// ErrCheckpointRead reports a failed checkpoint or chain-head read without database details.
	ErrCheckpointRead = errors.New("audit checkpoint read failed")
)

const (
	lockAuditChainHeadSQL = `SELECT sequence, event_hash FROM lock_audit_chain_head()`
	appendAuditEventSQL   = `SELECT append_audit_event(
		$1::smallint, $2::uuid, $3::uuid, $4::text, $5::timestamptz, $6::uuid, $7::text,
		$8::bytea, $9::bytea, $10::text, $11::text[], $12::text, $13::text, $14::text,
		$15::bytea, $16::bytea, $17::bigint, $18::bigint, $19::text[], $20::jsonb,
		$21::text[], $22::text[], $23::bytea, $24::bigint, $25::bigint, $26::bigint,
		$27::bigint, $28::text, $29::text, $30::bytea, $31::bytea, $32::text, $33::bytea
	)`
	selectAuditRecordColumnsSQL = `SELECT
		sequence, schema_version, event_id::text, run_id::text, event_type, occurred_at,
		principal_id::text, auth_method, oidc_issuer_hash, policy_version_hash, decision,
		decision_reason_codes, requested_model, resolved_backend, content_hmac_key_id,
		request_hmac, response_hmac, request_bytes, response_bytes, pii_categories,
		pii_match_counts, health_indicator_categories, secret_categories, detector_bundle_hash,
		input_tokens, output_tokens, reserved_cost_micros, actual_cost_micros, status,
		error_code, previous_event_hash, event_hash, software_version, config_hash
	FROM audit_events`
	selectAuditRecordsSQL        = selectAuditRecordColumnsSQL + ` ORDER BY sequence`
	selectAuditRecordsThroughSQL = selectAuditRecordColumnsSQL + ` WHERE sequence <= $1 ORDER BY sequence`
	readCheckpointHeadSQL        = `SELECT sequence, event_hash FROM get_audit_chain_head()`
	storeCheckpointSQL           = `SELECT store_audit_checkpoint($1::bigint, $2::bytea, $3::text, $4::bytea, $5::timestamptz)`
	loadCheckpointSQL            = `SELECT sequence, chain_head_hash, signing_key_id, signature, created_at
		FROM audit_checkpoints WHERE sequence = $1`
)

// Repository persists and verifies content-free audit events.
type Repository struct {
	pool *pgxpool.Pool
}

// ChainHead is the minimal content-free state required to create a checkpoint.
type ChainHead struct {
	Sequence  int64
	EventHash Digest
}

// AppendReceipt proves that an audit append committed successfully.
type AppendReceipt struct {
	sequence          int64
	eventHash         Digest
	backendAuthorized bool
}

// Sequence returns the committed audit sequence, or zero for an invalid receipt.
func (receipt AppendReceipt) Sequence() int64 {
	return receipt.sequence
}

// EventHash returns the committed chain head hash.
func (receipt AppendReceipt) EventHash() Digest {
	return receipt.eventHash
}

// AuthorizesBackendCall reports whether a committed run_started event permits backend invocation.
func (receipt AppendReceipt) AuthorizesBackendCall() bool {
	return receipt.backendAuthorized
}

// NewRepository binds audit persistence to an existing PostgreSQL pool.
func NewRepository(pool *pgxpool.Pool) (*Repository, error) {
	if pool == nil {
		return nil, ErrRepositoryUnavailable
	}
	return &Repository{pool: pool}, nil
}

// Append serializes the chain head, persists one event, and commits before returning a receipt.
func (repository *Repository) Append(ctx context.Context, event Event) (AppendReceipt, error) {
	if repository == nil || repository.pool == nil || event.PreviousEventHash != (Digest{}) {
		return AppendReceipt{}, ErrAppend
	}
	if err := event.Validate(); err != nil {
		return AppendReceipt{}, ErrAppend
	}

	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return AppendReceipt{}, ErrAppend
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	var headSequence int64
	var rawHeadHash []byte
	if err := tx.QueryRow(ctx, lockAuditChainHeadSQL).Scan(&headSequence, &rawHeadHash); err != nil {
		return AppendReceipt{}, ErrAppend
	}
	headHash, ok := digestFromBytes(rawHeadHash)
	if !ok {
		return AppendReceipt{}, ErrAppend
	}
	event.PreviousEventHash = headHash
	eventHash, err := EventHash(event)
	if err != nil {
		return AppendReceipt{}, ErrAppend
	}

	var sequence int64
	if err := tx.QueryRow(ctx, appendAuditEventSQL, appendArguments(event, eventHash)...).Scan(&sequence); err != nil {
		return AppendReceipt{}, ErrAppend
	}
	if sequence != headSequence+1 {
		return AppendReceipt{}, ErrAppend
	}
	if err := tx.Commit(ctx); err != nil {
		return AppendReceipt{}, ErrAppend
	}
	return AppendReceipt{
		sequence:          sequence,
		eventHash:         eventHash,
		backendAuthorized: event.EventType == EventRunStarted,
	}, nil
}

// ChainHead reads the current chain head through the approved checkpoint administration API.
func (repository *Repository) ChainHead(ctx context.Context) (ChainHead, error) {
	if repository == nil || repository.pool == nil {
		return ChainHead{}, ErrCheckpointRead
	}
	var head ChainHead
	var rawHash []byte
	if err := repository.pool.QueryRow(ctx, readCheckpointHeadSQL).Scan(&head.Sequence, &rawHash); err != nil {
		return ChainHead{}, ErrCheckpointRead
	}
	digest, ok := digestFromBytes(rawHash)
	if !ok || head.Sequence <= 0 || digest == (Digest{}) {
		return ChainHead{}, ErrCheckpointRead
	}
	head.EventHash = digest
	return head, nil
}

// StoreCheckpoint persists one signed checkpoint through the approved administration API.
func (repository *Repository) StoreCheckpoint(ctx context.Context, checkpoint Checkpoint) error {
	if repository == nil || repository.pool == nil || len(checkpoint.Signature) != 64 {
		return ErrCheckpointStore
	}
	if _, err := canonicalCheckpointPayload(checkpoint); err != nil || checkpoint.ChainHeadHash == (Digest{}) {
		return ErrCheckpointStore
	}
	if _, err := repository.pool.Exec(
		ctx,
		storeCheckpointSQL,
		checkpoint.Sequence,
		checkpoint.ChainHeadHash[:],
		checkpoint.SigningKeyID,
		checkpoint.Signature,
		checkpoint.CreatedAt,
	); err != nil {
		return ErrCheckpointStore
	}
	return nil
}

// LoadCheckpoint reads one persisted checkpoint without requiring database write access.
func (repository *Repository) LoadCheckpoint(ctx context.Context, sequence int64) (Checkpoint, error) {
	if repository == nil || repository.pool == nil || sequence <= 0 {
		return Checkpoint{}, ErrCheckpointRead
	}
	checkpoint := Checkpoint{SchemaVersion: 1}
	var rawHash []byte
	if err := repository.pool.QueryRow(ctx, loadCheckpointSQL, sequence).Scan(
		&checkpoint.Sequence,
		&rawHash,
		&checkpoint.SigningKeyID,
		&checkpoint.Signature,
		&checkpoint.CreatedAt,
	); err != nil {
		return Checkpoint{}, ErrCheckpointRead
	}
	digest, ok := digestFromBytes(rawHash)
	if !ok || digest == (Digest{}) || len(checkpoint.Signature) != 64 {
		return Checkpoint{}, ErrCheckpointRead
	}
	checkpoint.ChainHeadHash = digest
	checkpoint.CreatedAt = checkpoint.CreatedAt.UTC()
	if _, err := canonicalCheckpointPayload(checkpoint); err != nil {
		return Checkpoint{}, ErrCheckpointRead
	}
	checkpoint.Signature = append([]byte(nil), checkpoint.Signature...)
	return checkpoint, nil
}

// RecordsThrough reads and verifies a complete chain ending at the requested checkpoint sequence.
func (repository *Repository) RecordsThrough(ctx context.Context, sequence int64) ([]Record, error) {
	if repository == nil || repository.pool == nil || sequence <= 0 {
		return nil, ErrRead
	}
	records, err := repository.readRecords(ctx, selectAuditRecordsThroughSQL, sequence)
	if err != nil {
		return nil, err
	}
	if err := VerifyChain(records); err != nil {
		return nil, err
	}
	if len(records) == 0 || records[len(records)-1].Sequence != sequence {
		return nil, &VerificationError{Sequence: int64(len(records) + 1)}
	}
	return records, nil
}

// Verify reads the ordered audit history and verifies sequence and hash-chain integrity.
func (repository *Repository) Verify(ctx context.Context) error {
	if repository == nil || repository.pool == nil {
		return ErrRead
	}
	records, err := repository.readRecords(ctx, selectAuditRecordsSQL)
	if err != nil {
		return err
	}
	return VerifyChain(records)
}

func (repository *Repository) readRecords(ctx context.Context, query string, arguments ...any) ([]Record, error) {
	rows, err := repository.pool.Query(ctx, query, arguments...)
	if err != nil {
		return nil, ErrRead
	}
	defer rows.Close()

	records := make([]Record, 0)
	for rows.Next() {
		record, scanErr := scanRecord(rows)
		if scanErr != nil {
			if record.Sequence > 0 {
				return nil, &VerificationError{Sequence: record.Sequence}
			}
			return nil, ErrRead
		}
		records = append(records, record)
	}
	if rows.Err() != nil {
		return nil, ErrRead
	}
	return records, nil
}

func appendArguments(event Event, eventHash Digest) []any {
	return []any{
		event.SchemaVersion,
		event.EventID,
		event.RunID,
		string(event.EventType),
		event.OccurredAt,
		event.PrincipalID,
		string(event.AuthMethod),
		optionalDigestBytes(event.OIDCIssuerHash),
		event.PolicyVersionHash[:],
		string(event.Decision),
		event.DecisionReasonCodes,
		event.RequestedModel,
		event.ResolvedBackend,
		event.ContentHMACKeyID,
		event.RequestHMAC[:],
		optionalDigestBytes(event.ResponseHMAC),
		event.RequestBytes,
		event.ResponseBytes,
		event.PIICategories,
		event.PIIMatchCounts,
		event.HealthIndicatorCategories,
		event.SecretCategories,
		event.DetectorBundleHash[:],
		event.InputTokens,
		event.OutputTokens,
		event.ReservedCostMicros,
		event.ActualCostMicros,
		string(event.Status),
		event.ErrorCode,
		event.PreviousEventHash[:],
		eventHash[:],
		event.SoftwareVersion,
		event.ConfigHash[:],
	}
}

func scanRecord(rows pgx.Rows) (Record, error) {
	var record Record
	var eventType, authMethod, decision, status string
	var oidcIssuerHash, policyVersionHash, requestHMAC, responseHMAC []byte
	var detectorBundleHash, previousEventHash, eventHash, configHash []byte
	if err := rows.Scan(
		&record.Sequence,
		&record.Event.SchemaVersion,
		&record.Event.EventID,
		&record.Event.RunID,
		&eventType,
		&record.Event.OccurredAt,
		&record.Event.PrincipalID,
		&authMethod,
		&oidcIssuerHash,
		&policyVersionHash,
		&decision,
		&record.Event.DecisionReasonCodes,
		&record.Event.RequestedModel,
		&record.Event.ResolvedBackend,
		&record.Event.ContentHMACKeyID,
		&requestHMAC,
		&responseHMAC,
		&record.Event.RequestBytes,
		&record.Event.ResponseBytes,
		&record.Event.PIICategories,
		&record.Event.PIIMatchCounts,
		&record.Event.HealthIndicatorCategories,
		&record.Event.SecretCategories,
		&detectorBundleHash,
		&record.Event.InputTokens,
		&record.Event.OutputTokens,
		&record.Event.ReservedCostMicros,
		&record.Event.ActualCostMicros,
		&status,
		&record.Event.ErrorCode,
		&previousEventHash,
		&eventHash,
		&record.Event.SoftwareVersion,
		&configHash,
	); err != nil {
		return record, err
	}

	record.Event.EventType = EventType(eventType)
	record.Event.AuthMethod = AuthMethod(authMethod)
	record.Event.Decision = Decision(decision)
	record.Event.Status = Status(status)
	if !assignRequiredDigest(&record.Event.PolicyVersionHash, policyVersionHash) ||
		!assignRequiredDigest(&record.Event.RequestHMAC, requestHMAC) ||
		!assignRequiredDigest(&record.Event.DetectorBundleHash, detectorBundleHash) ||
		!assignRequiredDigest(&record.Event.PreviousEventHash, previousEventHash) ||
		!assignRequiredDigest(&record.Event.ConfigHash, configHash) ||
		!assignRequiredDigest(&record.EventHash, eventHash) {
		return record, ErrRead
	}
	if oidcIssuerHash != nil {
		digest, ok := digestFromBytes(oidcIssuerHash)
		if !ok {
			return record, ErrRead
		}
		record.Event.OIDCIssuerHash = &digest
	}
	if responseHMAC != nil {
		digest, ok := digestFromBytes(responseHMAC)
		if !ok {
			return record, ErrRead
		}
		record.Event.ResponseHMAC = &digest
	}
	return record, nil
}

func optionalDigestBytes(digest *Digest) []byte {
	if digest == nil {
		return nil
	}
	return digest[:]
}

func assignRequiredDigest(destination *Digest, raw []byte) bool {
	digest, ok := digestFromBytes(raw)
	if !ok {
		return false
	}
	*destination = digest
	return true
}

func digestFromBytes(raw []byte) (Digest, bool) {
	if len(raw) != len(Digest{}) {
		return Digest{}, false
	}
	var digest Digest
	copy(digest[:], raw)
	return digest, true
}

# Signed audit checkpoints and offline verification

## Purpose and assurance boundary

The gateway produces content-free, tamper-evident audit records. A signed checkpoint binds an Ed25519 key to one exact sequence and chain-head hash. An export packages the complete record chain from sequence 1 through that checkpoint so it can be verified without database access.

This mechanism supports customer audit-integrity controls and evidence. It does not make a host immutable and does not by itself establish regulatory compliance. A database superuser or host administrator who cannot use the signing key cannot silently rewrite a previously exported, independently verified chain. In demo mode, however, the signing key is a root-readable file on the same host. A host administrator can copy or use that key and can therefore forge later checkpoints.

Stronger resistance to host-administrator compromise requires both:

1. a non-exportable TPM/HSM-backed checkpoint key with an approved signing policy; and
2. prompt publication of checkpoints to an independent immutable witness or WORM destination.

The local PostgreSQL records and local checkpoint table remain **tamper-evident**, not absolutely immutable.

## Export V1 envelope

`schemas/audit-export-v1.schema.json` is the normative structural schema. The top-level object has this fixed field order when emitted by `agentboxctl`:

1. `schema_version` — integer `1`;
2. `records` — the complete ordered record list;
3. `checkpoint` — the signed chain-head statement.

Each record contains only:

- `sequence` — contiguous integer starting at 1;
- `event` — a canonical event conforming to `schemas/audit-event-v1.schema.json`;
- `event_hash` — lowercase hexadecimal SHA-256 digest.

The checkpoint contains only:

- `schema_version` — integer `1`;
- `sequence` — the last exported record sequence;
- `chain_head_hash` — lowercase hexadecimal hash of that record;
- `signing_key_id` — strict non-secret key identity;
- `created_at` — UTC RFC 3339 timestamp with at most microsecond precision;
- `signature` — standard padded base64 encoding of the 64-byte Ed25519 signature.

The export contains pseudonymous identifiers, detector categories/counts, usage, cost, and content HMAC evidence. It contains no plaintext prompts, responses, detector matches, snippets, offsets, credentials, or signing private key. The permitted metadata can still be sensitive and must be transferred and retained under customer-approved audit access controls.

## Exact cryptographic inputs

### Event chain

For each event:

```text
event_hash = SHA-256(
    UTF8("compliantai:audit-chain:v1\x00") || canonical_event_json
)
```

`canonical_event_json` includes `previous_event_hash`. Sequence 1 must use the all-zero predecessor. Each later event must contain the preceding record's exact event hash.

### Checkpoint signature

The unsigned canonical checkpoint JSON has these fields in this exact order and no whitespace:

```json
{"schema_version":1,"sequence":42,"chain_head_hash":"<64 lowercase hex characters>","signing_key_id":"checkpoint-key-v1","created_at":"2026-07-24T16:00:00.123456Z"}
```

The Ed25519 message is:

```text
UTF8("compliantai:audit-checkpoint:v1\x00") || unsigned_canonical_checkpoint_json
```

No additional pre-hash is applied by the application. The signature must verify against the independently trusted public key whose configured key ID exactly equals `signing_key_id`.

## Demo key preparation

Generate an Ed25519 PKCS#8 private key and the corresponding PKIX public key on the customer-controlled host:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out /secure/checkpoint-private.pem
chmod 0600 /secure/checkpoint-private.pem
openssl pkey \
  -in /secure/checkpoint-private.pem \
  -pubout \
  -out /secure/checkpoint-public.pem
```

The private-key loader atomically rejects symlinks, non-regular files, leading/multiple/trailing PEM content, non-Ed25519 keys, files larger than 16 KiB, and group/other permission bits. The public key is not secret and should be distributed over a separately authenticated channel. Record its approved key ID and fingerprint in the customer's evidence register.

The demo command always prints this warning:

```text
WARNING: file-based checkpoint signing does not protect against host administrators
```

Do not suppress or reinterpret the warning as a production security claim.

## Database role separation

Use separate, root-readable, one-line DSN files with mode `0600`:

- checkpoint creation: `security_admin` DSN;
- export: `audit_reader` DSN.

`security_admin` can read only the minimal current chain head and persist a checkpoint through approved `SECURITY DEFINER` functions. It cannot insert directly into checkpoint or event tables. `audit_reader` can read audit evidence but cannot create checkpoints. `gateway_runtime` has neither checkpoint-administration capability.

## Create a checkpoint

```sh
agentboxctl checkpoint \
  --dsn-file /secure/security-admin.dsn \
  --private-key-file /secure/checkpoint-private.pem \
  --key-id checkpoint-key-v1
```

The command reads the latest committed chain head, signs it in memory, persists the signature through the approved function, clears its in-process signer copy, and emits a content-free JSON summary. It fails closed if the head cannot be read, signing fails, the database write fails, or the sequence/hash no longer satisfies the database contract.

## Export through a checkpoint

```sh
agentboxctl export \
  --dsn-file /secure/audit-reader.dsn \
  --sequence 42 \
  --output /secure-transfer/audit-export-42.json
```

The output path must not already exist. The command creates it with mode `0600`. Export succeeds only if records 1 through the checkpoint sequence form a complete valid chain and the persisted checkpoint matches the last record. Transfer the export and trusted public key using customer-approved secure channels; preferably transfer or authenticate the public-key fingerprint separately from the export.

## Verify without database access

Copy only `agentboxctl`, the export, and the trusted public key to an isolated verification system. No PostgreSQL DSN is required.

```sh
agentboxctl verify \
  --input audit-export-42.json \
  --public-key-file checkpoint-public.pem \
  --key-id checkpoint-key-v1
```

Successful output:

```json
{"valid":true}
```

For a chain edit, deletion, insertion, reordering, malformed canonical event, or record-hash mismatch where the affected record is identifiable, the command exits nonzero and reports only the content-free first affected sequence, for example:

```json
{"valid":false,"first_affected_sequence":17}
```

Malformed envelopes, untrusted keys, checkpoint-signature failures, unreadable files, and other failures return a fixed content-free error. Verification stops at the first affected sequence. It requires the exact deterministic envelope bytes—including field order, whitespace, and canonical padded base64—then checks canonical event bytes, contiguous sequence, genesis linkage, predecessor linkage, every event hash, checkpoint-to-last-record alignment, key identity, and the Ed25519 signature.

## Operational evidence procedure

For each checkpoint retained as customer evidence:

1. record the approved signing key ID and independently authenticated public-key fingerprint;
2. create the checkpoint with the `security_admin` role;
3. export through that exact checkpoint with the `audit_reader` role;
4. copy the export to the approved independent destination;
5. run offline verification from that destination;
6. retain the verification result, checkpoint sequence/hash, transfer time, operator identity, and destination reference under the customer's evidence policy;
7. investigate any nonzero verifier exit before relying on later records.

Key rotation uses a new strict key ID and separately distributed trusted public key. Existing exports remain verifiable with the historical public key. Never reuse a key ID for different public key material.

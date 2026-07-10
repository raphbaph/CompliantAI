# V1 Data Inventory and Zero-Retention Contract

## 1. Purpose

This document is the normative inventory of data touched by the V1 gateway. It defines what counts as content, what may persist, where data flows, and which fields are prohibited.

The zero-retention commitment applies to the gateway deployment. It does not automatically govern the caller, customer identity provider, existing inference server, customer network appliances, or customer SIEM; those are separate customer-controlled systems that must be assessed and configured consistently.

## 2. Data classes

### C0 — Request/response content: never persist

C0 includes:

- system, user, assistant, and future tool messages;
- exact HTTP request and response bodies;
- uploaded, embedded, or unknown client-provided string values;
- model outputs and finish-reason details that could contain generated text;
- backend error bodies, validation excerpts, and stack-local content values;
- detector matches, regular-expression capture groups, snippets, offsets, and context;
- authorization bearer JWTs and complete API-key values;
- arbitrary client headers, query strings, and caller-provided request IDs;
- token IDs, embeddings, hidden states, and other content-derived representations if later supported.

C0 may exist only in bounded volatile process memory for the duration needed to handle a synchronous request. It is forbidden in PostgreSQL, files, container logs, metrics, traces, core dumps, swap, exports, diagnostics, checkpoints, and backups.

### C1 — Content-derived classifications: permitted with restrictions

C1 includes category-only facts produced by a versioned detector, for example:

- `pii.email: 1`;
- `pii.iban: 1`;
- `health_data_indicator.icd_code: true`;
- `secret.jwt_shape: 1`.

C1 must never contain the match, snippet, offset, free-form explanation, or captured context. C1 can itself reveal sensitive information when associated with a principal and therefore receives the same audit access controls and retention review as other personal metadata.

### C2 — Pseudonymous content evidence: permitted with restrictions

C2 includes:

- HMAC-SHA-256 of exact request bytes;
- HMAC-SHA-256 of exact returned response bytes;
- request/response byte counts.

The HMAC uses a per-deployment secret distinct from the audit-checkpoint signing key. C2 is evidence for equality verification, not anonymization. A holder of the HMAC key can test candidate values.

### C3 — Identity and authorization metadata: permitted

C3 includes:

- internal principal UUID;
- OIDC issuer/audience identifiers or approved digests;
- OIDC subject needed for identity mapping;
- effective group/role identifiers used by policy;
- authentication method and API-key public ID;
- endpoint, requested model, policy version digest, decision, and fixed reason codes.

Avoid display names, email addresses, and full token claims unless a customer-approved audit use requires them. Never persist the raw JWT.

### C4 — Usage and budget metadata: permitted

C4 includes:

- backend/model identifier;
- input/output token counts returned by the backend;
- reservation and settled amount in integer micro-euros or integer cost units;
- daily/monthly budget window and outcome;
- duration, status, and fixed error code.

### C5 — Integrity and software metadata: permitted

C5 includes:

- event ID, run ID, sequence, timestamp;
- previous event hash and event hash;
- signed checkpoint, public signing-key ID, and witness reference;
- detector-bundle, configuration, policy, and software-version digests;
- database administrative actor/role, action class, object identifier, and outcome where content-free.

### C6 — Secrets and key material: never log; persist only in protected secret stores

C6 includes:

- content-HMAC key;
- checkpoint-signing private key;
- TLS private key;
- backend credential;
- API-key verifier pepper if used;
- PostgreSQL credentials.

C6 may be stored only in root-readable mounted files or an approved production TPM/HSM/secret store. It is never stored in audit events, configuration committed to source control, diagnostics, or logs.

## 3. Data-flow inventory

| Stage | Inputs visible | Output | Durable write permitted? |
|---|---|---|---|
| Client connection | TLS metadata, auth header, bounded body | Authenticated request or fixed denial | C3/C5 denial metadata only; never auth token/body |
| Authentication | JWT/API key, IdP/JWKS data | Principal and effective claims | C3 mapping and fixed outcome; never raw credential |
| Parsing | Exact request bytes | Strict supported request object | HMAC/byte length only |
| Classification | Content-bearing strings | Category/count findings | C1 only |
| Authorization | Principal, groups, endpoint, model, policy | Allow/deny + fixed reason codes | C3/C5 decision context |
| Budget reservation | Principal, model, conservative maximum | Reservation or denial | C4/C5 |
| Backend invocation | Reconstructed plaintext request, server credential | Plaintext response + usage | No content; C4/C5 status only |
| Completion | Exact returned response bytes, usage | Response HMAC and settlement | C1–C5 only |
| Operational logging | Typed content-free event arguments | JSON operational event | Explicit schema only |
| Audit export | Stored C1–C5 evidence | Canonical JSON/JSONL + checkpoint | C1–C5 only |
| Verification | Export and public key | Pass/fail + first bad sequence | No C0/C6 |

## 4. Persistent stores

### PostgreSQL application tables

Permitted:

- principals and identity mappings;
- API-key public IDs and one-way verifiers;
- budget accounts and reservations;
- canonical content-free audit events;
- chain hashes and signed checkpoints.

Prohibited:

- request/response bodies;
- arbitrary JSON metadata;
- free-form error/detail/message fields;
- detector matches or snippets;
- raw credentials;
- raw client or backend headers.

### PostgreSQL logs and `pgaudit`

Permitted:

- connection and disconnection;
- authenticated database role;
- role changes;
- DDL class and object names;
- privileged write class and outcome;
- fixed statement/procedure identifiers where configured safely.

Prohibited:

- bind parameters;
- request/response content;
- full API keys, JWTs, or secret files;
- dynamically generated SQL containing user content.

The gateway must never place C0 in SQL, which is the primary protection against database statement and WAL leakage.

### Gateway/container logs

Only typed operational events with an explicit field set may be emitted. There is no generic message, arbitrary map, printf-style content argument, request dump, response dump, header dump, or stack-variable capture.

### Metrics and traces

V1 should avoid distributed tracing. Metrics may contain fixed component, route-template, method, status class, model ID, and fixed error-code labels. Principal, request ID, detector finding, JWT claim, and arbitrary caller values are forbidden as metric labels.

### Files, temporary paths, and core/swap

- Gateway root filesystem is read-only.
- Explicit temporary paths are tmpfs.
- Swap and process/core dumps are disabled by deployment preflight.
- No request-body buffering proxy is part of V1.
- Export files contain only C1–C5 and are created only by an explicit administrator action.

### Backups

Backups may contain persisted C1–C6 database state but must never contain C0. Backups inherit the sensitivity and retention of audit and identity metadata. Production backup/restore and key-recovery procedures are a post-demo gate.

## 5. Required audit event fields

The precise schema will be versioned under `schemas/audit-event-v1.schema.json`. It may include only the following field families:

- schema/event/run identifiers and timestamp;
- principal UUID and authentication method;
- policy/configuration/software/detector digests;
- endpoint, requested model, resolved backend identifier;
- allow/deny decision and fixed reason codes;
- request/response HMAC and byte counts;
- category/count detector findings;
- token counts, reservation, settled cost, duration, status, and fixed error code;
- previous hash, event hash, checkpoint/signature references.

The schema must set `additionalProperties: false`.

## 6. Prohibited field patterns

Do not introduce fields named or serving the purpose of:

- `prompt`, `messages`, `content`, `completion`, `response_text`, `request_body`, `response_body`;
- `matched_text`, `snippet`, `context`, `raw`, `payload`, `body`, `headers`;
- `error_message`, `stack_variables`, `debug`, `notes`, `description`;
- arbitrary `metadata`, `labels`, `tags`, or untyped JSON extensions.

A fixed enum such as `error_code = backend_timeout` is permitted. A free-form backend error is not.

## 7. Detector finding schema

Each finding is reduced before persistence to:

```json
{
  "category": "pii.iban",
  "count": 1,
  "rule_id": "iban-checksum-v1"
}
```

Rules:

- `category` and `rule_id` are server-defined enums.
- `count` is a non-negative bounded integer.
- Findings are aggregated by category/rule.
- No matched value, hash of an individual match, location, offset, or context is retained.
- “Health data” detections are labelled indicators, not legal conclusions.

## 8. Content digests and canonical evidence

- Compute request HMAC over the exact accepted HTTP body bytes before reconstruction.
- Compute response HMAC over the exact bytes returned to the caller.
- Use a per-deployment HMAC key and a versioned domain separator.
- Keep old key IDs and protected keys as required to verify retained records after rotation.
- Never expose a content-HMAC oracle to ordinary callers.
- Do not use raw SHA-256 as content evidence.

Audit event hashes are unkeyed chain-integrity hashes over canonical content-free events. They serve a different purpose from request/response HMACs.

## 9. Retention and deletion

V1 does not implement automated audit deletion. The technical demo must not be marketed as having a complete production retention lifecycle.

Before a pilot, the customer must approve:

- audit, identity, API-key, budget, database-log, backup, checkpoint, and key-retention periods;
- lawful deletion and legal-hold behavior;
- whether EU AI Act Article 26(6)’s at-least-six-month log period applies to the use case;
- GDPR storage-limitation requirements; and
- whether C1–C3 constitute personal or special-category metadata in context.

Authorized expiration must itself create verifiable evidence and must not be implemented as an undocumented administrator delete.

## 10. Access matrix

| Data class | Runtime | Security admin | Audit reader | DB migration owner | Ordinary app user |
|---|---|---|---|---|---|
| C0 in-memory content | During own request processing | No | No | No | Sends/receives own request |
| C1 classifications | Insert via event path | Read only if approved | Read | Schema only | No |
| C2 HMAC evidence | Insert via event path | Read only if approved | Read | Schema only | No default access |
| C3 identity/policy metadata | Required read/insert | Controlled management | Approved read | Schema only | No |
| C4 budget/usage | Reserve/settle | Controlled management | Approved read | Schema only | Own status only if later exposed |
| C5 integrity metadata | Insert/checkpoint request | Read | Read/verify | Schema only | No |
| C6 secrets | Specific mounted secret only | Key-management procedure only | Public verification key only | No runtime secret | API key shown once at creation |

No application, security-admin, or audit-reader role may update/delete canonical audit events.

## 11. Canary verification

The persistence test generates distinct high-entropy canaries for:

- prompt;
- backend response;
- API key;
- JWT claim;
- malformed request;
- backend error.

It exercises allowed, denied, oversized, malformed, backend-failure, and disconnect paths, then searches each enumerated destination and encoding. The valid report wording is:

> No tested canary was detected in the enumerated persistence locations.

The test does not prove absence from unenumerated systems or all possible encodings.

## 12. Change control

Any new endpoint, content type, detector, log field, trace, metric label, database column, export field, or integration must update this inventory before implementation. A schema or code-review approval must explicitly classify the new data as C0–C6 and add a canary or acceptance test where applicable.

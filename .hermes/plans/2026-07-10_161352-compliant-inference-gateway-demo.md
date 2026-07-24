# Compliant Inference Gateway Technical Demo Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** By 28 August 2026, deliver a demonstrable, single-tenant, on-premises Go gateway that sits in front of an existing OpenAI-compatible inference server, authenticates callers, enforces access and per-user spend limits, detects configured PII/health-data indicators and secrets in memory, retains no plaintext request or response content, and emits tamper-evident audit evidence.

**Architecture:** Build a small modular monolith rather than a platform. A Go service terminates the client API connection, validates OIDC JWTs or API keys, parses a bounded non-streaming request in memory, computes keyed request/response digests, classifies content without retaining matches, authorizes the request, reserves budget atomically in PostgreSQL, calls one configured OpenAI-compatible backend, commits a content-free audit record, and only then returns the buffered response. PostgreSQL is local and append-only for audit events; a hash chain and signed checkpoints make unauthorized alteration detectable. Deployment uses Docker Compose on one customer-controlled Linux server; there is no Kubernetes, vendor control plane, web UI, fleet manager, or retained-content mode.

**Tech Stack:** Go 1.24 or the current supported Go release selected at implementation start; PostgreSQL 17 with `pgaudit`; Docker Engine with Compose v2; standard `net/http`; `golang-jwt/jwt/v5`; an OIDC/JWKS validation library selected and pinned during implementation; `golang.org/x/crypto`; YAML configuration; JSON Schema for published audit events; Go unit, integration, fuzz, and race tests.

---

## 1. Product boundary and terminology

### Product statement

Use this claim:

> The gateway enforces customer-approved inference access and handling policies and produces verifiable evidence of how requests were authorized, classified, budgeted, routed, and handled.

Do **not** claim that the gateway decides whether an arbitrary request or customer is “EU AI Act compliant.” AI Act applicability and risk classification depend on the customer’s use case. The gateway provides technical controls and evidence that can support a customer’s compliance program.

### Initial customer profile

- Small German and Austrian legal or medical enterprise, approximately 8–50 staff.
- Customer already operates an OpenAI-compatible inference server on premises.
- Customer does not operate Kubernetes.
- Buyers are legal decision-makers or CEOs rather than a dedicated platform team.
- The first deliverable is a technical demo, not a certified production appliance.

### V1 in scope

- `POST /v1/chat/completions`, non-streaming only.
- `GET /v1/models`, filtered to models permitted for the caller.
- OIDC bearer JWT validation against the customer IdP.
- Transitional API keys tied to principals and stored only as one-way verifiers.
- Typed local YAML policy, not OPA or Cedar.
- Allow/deny authorization based on principal, group, service, endpoint, and model.
- Per-user daily and monthly spend limits with atomic reservation and settlement.
- In-memory PII, health-data-indicator, and secret classification.
- Content-free audit events with request and response HMACs.
- Append-only audit records, hash chaining, checkpoint signing, verification, and export.
- Database administrative action logging.
- Docker Compose packaging and a ZRM preflight check.
- CLI for API-key lifecycle, audit export, audit verification, and checkpoint generation.

### Explicitly out of scope for the August demo

- Streaming.
- Tool/function calling and `/v1/responses`.
- Embeddings, images, documents, audio, and batch inference.
- Content retention of any kind, including a debug exception.
- Human “flag for review” workflow.
- Semantic DLP using a model or external service.
- A guarantee that every natural-language reference to health or personal data is detected.
- SAML, SCIM, OAuth token exchange, and delegated agent authority.
- Web administration UI.
- Shared vendor control plane, billing service, fleet management, or remote operator access.
- Kubernetes, GPU rental, managed model serving, and air-gap bundle delivery.
- Dynamic cost/latency routing.
- Confidential-computing or GPU-memory attestation.
- A universal legal-compliance certification.

### Future compatibility constraint

The internal request representation must preserve the distinction between ordinary message text and tool-call data so tool calling can be added later without redesigning audit, classification, policy, or hashing. Do not expose tool calling in V1.

---

## 2. Compliance interpretation and legal review boundary

The implementation should map evidence to relevant duties without asserting that every customer use is a high-risk AI system.

- The EU AI Act uses a risk-based classification. A legal practice’s ordinary private use is not automatically the Annex III “administration of justice” use case, which is framed around use by or on behalf of judicial authorities and similar alternative-dispute-resolution uses.
- Medical use is not automatically high risk merely because the user is a medical practice; classification can depend on whether the AI is itself a regulated product or safety component and on its intended purpose.
- For high-risk systems, Article 12 addresses automatic recording of events, and Article 26(6) requires deployers to retain logs under their control for an appropriate period of at least six months unless other Union or national law provides otherwise.
- Health data is a special category of personal data under GDPR Article 9. Even a content-free event saying that a named employee submitted a health-data-bearing request may itself be personal or sensitive metadata.
- HMACs of request and response bodies are pseudonymous evidence, not automatically anonymous data.

Authoritative starting references:

- EU AI Act official text: <https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng>
- European Commission AI Act overview: <https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai>
- European Commission AI Act Q&A: <https://digital-strategy.ec.europa.eu/en/faqs/navigating-ai-act>
- German BfDI information on health data and GDPR: <https://www.bfdi.bund.de/DE/Buerger/Inhalte/GesundheitSoziales/Allgemein/Heil-_und_Hilfsmittel.html>
- German BfDI information on data-protection impact assessments: <https://www.bfdi.bund.de/DE/Fachthemen/Inhalte/Technik/Datenschutz-Folgenabschaetzungen.html>

Before a production claim or pilot contract, obtain German/Austrian counsel review of:

1. The customer’s role and AI Act risk classification.
2. Controller/processor roles under GDPR.
3. The lawful basis for processing and classifying prompt content.
4. Audit-event retention and deletion periods.
5. Whether PII/health classifications associated with user identity are special-category data.
6. DPA, TOMs, DPIA/DSFA support, incident handling, and employee/works-council implications.

---

## 3. Security properties and honest limitations

### Required properties

1. Plaintext prompt and response content never enters PostgreSQL, filesystem files, metrics, traces, or application logs.
2. Request and response content exists only in bounded process memory while the synchronous request is handled.
3. Every authenticated request that reaches policy evaluation produces a content-free audit event, including denied requests.
4. No backend invocation occurs unless an initial audit event and budget reservation have committed.
5. No successful response is returned unless completion, usage, classifications, hashes, and budget settlement have committed.
6. Audit application roles cannot update or delete audit events.
7. Unauthorized audit alteration is detectable by chain verification and checkpoint verification.
8. Database login, role, DDL, and privileged activity is recorded without SQL bind parameters or request content.
9. A customer can export and independently verify audit evidence.
10. If audit storage or budget enforcement is unavailable, inference fails closed.

### Honest limitation: immutable versus tamper-evident

A PostgreSQL superuser or host root user can ultimately alter a local database and local log files. PostgreSQL permissions alone cannot make records physically immutable from such an actor.

Therefore the August demo must demonstrate:

- Append-only permissions for ordinary application and administration roles.
- A per-deployment hash chain.
- Signed checkpoints whose signing key is not available to the database role.
- Detection of row modification, deletion, insertion, and reordering after a checkpoint.

A production claim that database administrators and operators cannot silently rewrite history requires an independent trust domain, such as:

- TPM/HSM-backed checkpoint signing, plus
- Checkpoint copies sent to customer-controlled WORM storage, a SIEM with immutable retention, or another independent witness.

File-based signing keys are acceptable only for the technical demo and must be visibly labelled non-production.

### Zero-retention definition for V1

“Content” includes all user and model-provided natural language, uploaded or embedded values, system messages, assistant messages, client metadata strings not on an explicit allowlist, and backend error fragments. V1 persists only:

- HMAC digests of exact request and response bytes.
- Content byte lengths.
- Token counts returned by the backend.
- Boolean/category/count classification results.
- Identity, authorization, model, budget, timing, and outcome metadata.
- Policy, detector, configuration, and software version digests.

The following are prohibited:

- Matched snippets.
- Captured regular-expression groups.
- Prompt offsets or surrounding context.
- Raw backend errors.
- Arbitrary client headers or query strings.
- Plain SHA-256 of low-entropy content.
- Per-request retention overrides.

---

## 4. Request lifecycle

Process each request in this exact order:

1. Generate an internal request ID. Never trust a caller-provided value as the audit identifier.
2. Authenticate before reading more than the configured bounded request body.
3. Read at most `max_request_bytes` into memory; reject larger bodies with a content-free `413`.
4. Strictly parse the supported V1 JSON shape. Reject `stream: true`, tool fields, unsupported modalities, query parameters, and malformed values without echoing content.
5. Compute `request_hmac = HMAC-SHA-256(deployment_content_key, exact_request_bytes)`.
6. Run all enabled in-memory detectors over content-bearing string values.
7. Resolve the principal, effective groups, requested model, and applicable policy.
8. Evaluate allow/deny authorization.
9. If denied, append a final denied audit event and return a content-free `403`; do not contact the backend.
10. Conservatively calculate the maximum reservable request cost and atomically reserve it against the principal’s daily and monthly budgets.
11. Commit a `run_started` audit event and reservation before backend invocation.
12. Send a reconstructed, supported-field-only request to the configured backend. Do not forward arbitrary unknown fields or client headers.
13. Buffer the bounded backend response in memory. Reject or fail safely if it exceeds `max_response_bytes`.
14. Validate the backend response and required `usage` fields.
15. Compute `response_hmac` over the exact bytes that will be returned.
16. Atomically settle the reservation to actual usage and append `run_completed` or `run_failed`.
17. Return the buffered response only after the audit/budget transaction commits.
18. Release all references to request/response buffers. Document that Go garbage collection does not promise immediate memory zeroing; the V1 guarantee is zero durable retention, not perfect RAM erasure.

On client disconnect after backend invocation, settlement and completion audit must still execute using a bounded internal context rather than being cancelled with the client request.

---

## 5. Proposed repository layout

```text
.
├── cmd/
│   ├── gateway/main.go
│   └── agentboxctl/main.go
├── internal/
│   ├── api/
│   │   ├── server.go
│   │   ├── chat.go
│   │   ├── models.go
│   │   ├── errors.go
│   │   └── limits.go
│   ├── audit/
│   │   ├── event.go
│   │   ├── canonical.go
│   │   ├── chain.go
│   │   ├── repository.go
│   │   ├── signer.go
│   │   ├── verify.go
│   │   └── export.go
│   ├── auth/
│   │   ├── authenticator.go
│   │   ├── oidc.go
│   │   ├── jwks.go
│   │   ├── apikey.go
│   │   └── principal.go
│   ├── backend/
│   │   ├── client.go
│   │   ├── openai.go
│   │   └── errors.go
│   ├── budget/
│   │   ├── service.go
│   │   ├── reservation.go
│   │   └── price.go
│   ├── config/
│   │   ├── config.go
│   │   ├── load.go
│   │   └── validate.go
│   ├── detect/
│   │   ├── detector.go
│   │   ├── engine.go
│   │   ├── pii.go
│   │   ├── health.go
│   │   ├── secrets.go
│   │   └── normalize.go
│   ├── policy/
│   │   ├── types.go
│   │   ├── engine.go
│   │   └── decision.go
│   ├── safelog/logger.go
│   ├── store/postgres.go
│   └── version/version.go
├── migrations/
│   ├── 000001_roles_and_extensions.up.sql
│   ├── 000002_principals_and_keys.up.sql
│   ├── 000003_budgets.up.sql
│   ├── 000004_audit_events.up.sql
│   ├── 000005_audit_permissions.up.sql
│   └── 000006_db_admin_audit.up.sql
├── schemas/
│   ├── audit-event-v1.schema.json
│   └── config-v1.schema.json
├── deploy/
│   ├── compose.yaml
│   ├── gateway.Dockerfile
│   ├── postgres.Dockerfile
│   ├── postgres/
│   │   ├── postgresql.conf
│   │   └── pg_hba.conf
│   └── scripts/zrm-preflight.sh
├── configs/example.yaml
├── tests/
│   ├── integration/
│   ├── e2e/
│   ├── fixtures/
│   └── canary/
├── docs/
│   ├── threat-model.md
│   ├── data-inventory.md
│   ├── audit-schema.md
│   ├── policy-reference.md
│   ├── deployment.md
│   ├── evidence-pack.md
│   ├── compliance-control-map.md
│   └── demo-runbook.md
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

Use a temporary Go module path agreed at implementation start; do not couple package names to the final product brand.

---

## 6. Core data model

### `principals`

- `id UUID PRIMARY KEY`
- `external_subject TEXT NULL`
- `issuer TEXT NULL`
- `display_label TEXT NULL` — avoid personal names unless the customer requires them
- `status TEXT`
- `created_at TIMESTAMPTZ`
- `disabled_at TIMESTAMPTZ NULL`

Unique identity key: `(issuer, external_subject)`.

### `api_keys`

- Public random key ID used for lookup.
- Argon2id verifier for the secret portion.
- Principal ID, creation time, expiry, last-used time, and disabled time.
- Never store or log the complete key.
- CLI prints the secret once.

### `budget_accounts`

- Principal ID.
- Daily limit and monthly limit in integer micro-euros or customer-defined integer cost units.
- Current period boundaries.
- Committed amount.
- Reserved amount.
- Updated in a row-locked transaction.

Never use floating-point arithmetic for money.

### `spend_reservations`

- Reservation ID and run ID.
- Principal and model.
- Reserved maximum amount.
- Settled actual amount.
- State: `reserved`, `settled`, `released`, or `expired`.
- Expiration permits recovery after process crashes.

### `audit_events`

Required fields:

- `sequence BIGINT`
- `event_id UUID`
- `run_id UUID`
- `event_type`
- `occurred_at`
- `principal_id`
- `auth_method`
- `oidc_issuer_hash` where appropriate
- `policy_version_hash`
- `decision`
- `decision_reason_codes[]`
- `requested_model`
- `resolved_backend`
- `request_hmac`
- `response_hmac NULL`
- `request_bytes`
- `response_bytes NULL`
- `pii_categories[]`
- `pii_match_counts JSONB` with category/count only
- `health_indicator_categories[]`
- `secret_categories[]`
- `detector_bundle_hash`
- `input_tokens NULL`
- `output_tokens NULL`
- `reserved_cost_micros NULL`
- `actual_cost_micros NULL`
- `status`
- `error_code NULL`
- `previous_event_hash`
- `event_hash`
- `software_version`
- `config_hash`

Prohibit free-form message, details, metadata, tags, or arbitrary JSON fields.

### `audit_checkpoints`

- Sequence and chain head hash.
- Signing-key ID.
- Signature.
- Creation timestamp.
- Export status or witness reference.

### Chain construction

Use canonical JSON or another documented canonical binary encoding. Compute:

```text
event_hash = SHA-256(domain_separator || previous_event_hash || canonical_event_without_hashes)
```

The HMAC content key and audit-checkpoint signing key must be different keys with separate lifecycle documentation.

---

## 7. Detector scope

### V1 structured PII detectors

Implement deterministic, locally executed detectors with test fixtures for:

- Email addresses.
- Telephone numbers with German and Austrian examples.
- IBAN with checksum validation.
- IPv4/IPv6 addresses when configured as personal identifiers.
- German and Austrian tax/social identifiers only where a reliable documented checksum or format exists.
- Configurable customer identifiers using anchored patterns.

Avoid a generic “number looks like ID” rule that creates unusable false positives.

### V1 secret detectors

- PEM private-key headers.
- Common cloud access-key formats.
- JWT-shaped bearer tokens.
- GitHub/GitLab-style access-token formats that can be tested without storing values.
- Database URLs containing credentials.
- High-entropy candidate strings only when paired with a key-like assignment context.

### V1 health-data indicators

A pure Go deterministic classifier cannot reliably determine all medical meaning. V1 may identify explicit, configurable indicators such as:

- ICD-style codes.
- Customer-provided medication or diagnosis terms.
- Explicit field labels such as `diagnosis`, `patient`, `medication`, and German equivalents.

Name these events `health_data_indicator`, not “confirmed medical data.” Document false-positive and false-negative limitations in the demo.

### Detector output

Each detector returns only:

```go
type Finding struct {
    Category string
    Count    int
    RuleID   string
}
```

It must not return matched text, byte slices into the input, or loggable error strings containing content. Aggregate findings before persistence.

---

## 8. Budget enforcement design

A hard spending limit requires reservation before inference because actual output usage is known only afterward.

For each model configure:

- Input cost per token or unit.
- Output cost per token or unit.
- Maximum request bytes.
- Maximum output tokens.
- Conservative input-token estimator.
- Whether backend `usage` is mandatory.

Algorithm:

1. Conservatively estimate maximum input tokens.
2. Add the configured/requested maximum output-token cost.
3. Lock the principal’s budget row.
4. Reject if `committed + reserved + requested_reservation > limit` for either window.
5. Add the reservation and commit before backend invocation.
6. Settle to actual backend usage after a successful response.
7. Release on a pre-generation backend failure.
8. If reliable usage is absent, settle to the reserved maximum rather than undercharging.
9. Recover stale reservations after a configured timeout with an auditable recovery event.

This guarantees that concurrent requests cannot collectively exceed the configured limit, at the cost of conservative rejection near the limit.

---

## 9. Implementation tasks

Every production-code task follows RED → verify RED → GREEN → verify GREEN → refactor. Run the race detector for concurrency-sensitive code. Commit after each task.

### Task 1: Record the accepted V1 contract

**Files:**
- Create `README.md`
- Create `docs/threat-model.md`
- Create `docs/data-inventory.md`
- Create `docs/compliance-control-map.md`

**Steps:**
1. Record scope, non-goals, actors, trust boundaries, and the immutable-versus-tamper-evident limitation.
2. Define content and permitted metadata.
3. Map each user requirement to one acceptance test.
4. Mark legal classification and counsel review as customer obligations.
5. Review the documents for forbidden product claims.
6. Commit: `docs: define gateway v1 security and compliance boundary`.

**Verification:** A reviewer can answer what persists, who can alter it, what is detected, and what is explicitly not guaranteed without reading source code.

### Task 2: Scaffold the Go service and quality gates

**Files:**
- Create `go.mod`, `cmd/gateway/main.go`, `cmd/agentboxctl/main.go`
- Create `internal/version/version.go`
- Create `Makefile`
- Create CI workflow under `.github/workflows/ci.yml` if this repository will use GitHub

**TDD cycle:**
1. Write a test asserting version/build metadata has stable JSON fields.
2. Run `go test ./internal/version -v`; expect failure because implementation is absent.
3. Implement the minimum version package.
4. Run the test; expect pass.
5. Add `make test`, `make test-race`, `make vet`, and `make build`.
6. Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and `go build ./cmd/...`; expect success.
7. Commit: `build: scaffold gateway and quality gates`.

### Task 3: Implement strict configuration loading

**Files:**
- Create `internal/config/config.go`, `load.go`, `validate.go`
- Create `internal/config/config_test.go`
- Create `configs/example.yaml`
- Create `schemas/config-v1.schema.json`

**Test cases:**
- Valid minimal config loads.
- Unknown YAML fields fail.
- Missing issuer, audience, backend, TLS, key references, limits, or model price fails.
- Insecure backend URL fails unless loopback or explicitly enabled.
- Duplicate model names and invalid money values fail.
- Secret values are represented as file paths/environment references and never rendered by `String` or errors.

**Commands:**
- RED/GREEN: `go test ./internal/config -run TestLoad -v`
- Full: `go test ./...`

**Commit:** `feat: add strict versioned gateway configuration`.

### Task 4: Add schema-bound safe logging

**Files:**
- Create `internal/safelog/logger.go`
- Create `internal/safelog/logger_test.go`

**Design:** Export typed methods/events only. Do not expose a generic `map[string]any`, printf-style method, or arbitrary message field.

**Test cases:**
- Events contain only approved fields.
- Authorization and backend errors map to fixed codes.
- Canary prompt, response, API key, JWT, and backend error strings never appear in captured logs.
- New unknown event fields require a compile-time code change rather than runtime attachment.

**Commands:** `go test ./internal/safelog -v` and `go test ./...`.

**Commit:** `feat: add content-free typed operational logging`.

### Task 5: Create PostgreSQL image, migrations, and least-privilege roles

**Files:**
- Create `deploy/postgres.Dockerfile`
- Create `deploy/postgres/postgresql.conf`, `pg_hba.conf`
- Create migrations `000001` through `000006`
- Create `internal/store/postgres.go`
- Create `tests/integration/postgres_roles_test.go`

**Roles:**
- `gateway_runtime`: authenticate, execute approved insert/reservation procedures, read required config rows.
- `audit_reader`: select audit data only.
- `security_admin`: manage principals/API keys/budgets through controlled procedures; no audit update/delete.
- `migration_owner`: offline schema migration only; not used by the running gateway.
- No shared human superuser for normal operations.

**PostgreSQL logging:**
- Install and configure `pgaudit`.
- Log connection, role, DDL, and write-class administrative activity.
- Do not log bind parameters or full request statements.
- Ensure audit tables have no update/delete grants and protective triggers fail closed.

**Test cases:**
- Runtime role can insert only through approved path.
- Runtime, reader, and security-admin roles cannot update/delete audit rows.
- Security admin cannot disable protective triggers.
- DDL and failed privileged attempts appear in database audit logs.
- Canary content is absent from database logs.

**Commands:**
- `docker compose -f deploy/compose.yaml up -d postgres`
- `go test ./tests/integration -run TestPostgresRoles -v`

**Commit:** `feat: add append-only postgres schema and database auditing`.

### Task 6: Implement canonical audit events and HMAC content digests

**Files:**
- Create `internal/audit/event.go`, `canonical.go`, `chain.go`
- Create corresponding `_test.go` files
- Create `schemas/audit-event-v1.schema.json`

**Test cases:**
- Same exact bytes and key produce the same HMAC.
- Different deployment keys produce different HMACs.
- Low-entropy input cannot be verified without the key.
- Canonical events are byte-stable across map/order variations.
- Free-form content fields do not exist in the event type or JSON schema.
- Golden vectors are stored without real personal data.

**Commands:** `go test ./internal/audit -run 'Test(HMAC|Canonical|Schema)' -v`.

**Commit:** `feat: define content-free canonical audit events`.

### Task 7: Implement append-only chain persistence and verification

**Files:**
- Create `internal/audit/repository.go`, `verify.go`
- Create unit and PostgreSQL integration tests

**Design:** Serialize chain-head updates in a transaction. At target pilot scale, correctness is more important than maximum event throughput.

**Test cases:**
- Concurrent inserts produce one contiguous sequence and valid chain.
- Editing, deleting, inserting, or reordering a row makes verification fail at the first affected sequence.
- Transaction rollback does not advance the chain.
- A failed database write produces no backend-call authorization token.

**Commands:**
- `go test -race ./internal/audit -v`
- `go test ./tests/integration -run TestAuditChain -v`

**Commit:** `feat: add transactional tamper-evident audit chain`.

### Task 8: Add signed checkpoints and independent verification CLI

**Files:**
- Create `internal/audit/signer.go`, `export.go`
- Add `checkpoint`, `export`, and `verify` commands to `cmd/agentboxctl`
- Create `docs/audit-schema.md`

**Test cases:**
- Valid checkpoint verifies against the public key.
- Changed sequence or chain head invalidates signature.
- Export contains no content and validates against JSON Schema.
- Verification works without database write access.
- Private-key material never appears in output or logs.

**Demo mode:** Ed25519 key loaded from a root-readable file. Print a startup warning that this is not sufficient against host administrators.

**Production interface:** Keep signer behind an interface that can later use TPM/HSM/KMS without changing event schemas.

**Commands:** `go test ./internal/audit -run TestCheckpoint -v`; then run CLI verification against integration fixtures.

**Commit:** `feat: add signed audit checkpoints and verifier`.

### Task 9: Implement principal and API-key authentication

**Files:**
- Create `internal/auth/authenticator.go`, `apikey.go`, `principal.go`
- Add API-key management commands to `agentboxctl`

**Test cases:**
- Valid key authenticates the correct principal.
- Full secret is shown only once at creation.
- Stored row cannot be used directly as a bearer key.
- Expired, disabled, malformed, and unknown keys fail identically.
- Authentication logs only key ID prefix and principal ID, never the secret.
- Constant-time verifier behavior is used where applicable.

**Commands:** `go test ./internal/auth -run TestAPIKey -v`.

**Commit:** `feat: add revocable principal-bound API keys`.

### Task 10: Implement OIDC JWT validation

**Files:**
- Create `internal/auth/oidc.go`, `jwks.go`
- Create OIDC unit and integration fixtures with generated test keys

**Test cases:**
- Valid issuer, audience, signature, expiry, and subject pass.
- Wrong issuer/audience, expired token, `none` algorithm, unknown `kid`, and invalid signature fail.
- Group claims map according to config.
- JWKS cache respects configured freshness.
- Unknown signing key fails closed when the IdP is unavailable.
- Raw JWT and claim values outside the allowlist never enter logs/audit.

**Commands:** `go test ./internal/auth -run 'TestOIDC|TestJWKS' -v`.

**Commit:** `feat: validate customer oidc identities locally`.

### Task 11: Implement the typed policy engine

**Files:**
- Create `internal/policy/types.go`, `engine.go`, `decision.go`
- Create `internal/policy/engine_test.go`
- Create `docs/policy-reference.md`

**V1 rules:**
- Default deny.
- Match principal IDs and/or OIDC groups.
- Permit specific endpoint/service and model combinations.
- Policy has a content digest and explicit version.
- Denials return stable reason codes only.

**Test cases:**
- Unknown principal, group, endpoint, or model denies.
- Explicit grants allow only their exact scope.
- Conflicting rules resolve deterministically with deny precedence.
- Decision context records all non-content inputs needed to reproduce the decision.
- Policy reload requires restart in V1; no unsafe hot reload.

**Commands:** `go test ./internal/policy -v`.

**Commit:** `feat: add default-deny typed inference policy`.

### Task 12: Build the classification engine

**Files:**
- Create all files under `internal/detect/`
- Create synthetic German and Austrian fixtures under `tests/fixtures/`
- Create `docs/data-inventory.md` detector section

**Test cases:**
- Each supported PII, secret, and health indicator is detected in English and relevant German examples.
- IBAN validation rejects invalid checksums.
- Findings contain category/count/rule ID only.
- No matched value survives after aggregation.
- Invalid UTF-8 and large inputs fail safely.
- False-positive regression cases are represented.
- Fuzz tests never panic and never include input in errors.

**Commands:**
- `go test ./internal/detect -v`
- `go test ./internal/detect -fuzz=FuzzDetect -fuzztime=30s`

**Commit:** `feat: classify pii health indicators and secrets in memory`.

### Task 13: Implement atomic budget reservation and settlement

**Files:**
- Create `internal/budget/service.go`, `reservation.go`, `price.go`
- Add migration and integration tests if schema adjustment is required

**Test cases:**
- Daily and monthly limits are enforced.
- Integer arithmetic has no rounding overflow.
- Concurrent reservations cannot exceed the limit.
- Settlement reduces reserved and increases committed amounts atomically.
- Missing usage settles conservatively.
- Expired reservation recovery is audited.
- Disabled principal cannot reserve.

**Commands:**
- `go test -race ./internal/budget -v`
- `go test ./tests/integration -run TestConcurrentBudget -v`

**Commit:** `feat: enforce atomic per-user spend limits`.

### Task 14: Implement the bounded OpenAI backend client

**Files:**
- Create `internal/backend/client.go`, `openai.go`, `errors.go`
- Create a local fake OpenAI server in tests

**Test cases:**
- Supported request fields are reconstructed and forwarded.
- Unknown fields, tools, modalities, and streaming are rejected.
- Client authorization header is never forwarded.
- Backend credentials are injected from server configuration.
- Backend timeout, malformed JSON, oversized response, and content-bearing errors map to fixed safe codes.
- Backend `usage` is validated.
- Client disconnect does not cancel final audit settlement after invocation.

**Commands:** `go test ./internal/backend -v`.

**Commit:** `feat: add bounded non-streaming openai backend client`.

### Task 15: Build the HTTP API vertical slice

**Files:**
- Create files under `internal/api/`
- Wire dependencies in `cmd/gateway/main.go`
- Add API integration tests

**Initial vertical test:**

1. Start fake IdP/JWKS, PostgreSQL, fake backend, and gateway.
2. Submit one valid non-streaming chat request.
3. Assert backend received it.
4. Assert response is returned.
5. Assert audit records contain expected hashes/classification/decision/usage but not plaintext canaries.
6. Assert budget settled.

Then add tests for:

- Missing/invalid auth.
- Policy denial.
- Budget denial.
- PII/health/secret labels.
- Database unavailable before invocation: backend not called.
- Completion audit failure: response not returned.
- Oversized body.
- Query parameters rejected.
- `stream: true` rejected.
- `/v1/models` returns only permitted models.
- TLS configuration and security headers.

**Commands:**
- `go test ./internal/api -v`
- `go test ./tests/integration -run TestGatewayRequestLifecycle -v`

**Commit:** `feat: deliver audited policy-enforced chat completions`.

### Task 16: Add zero-retention canary tests

**Files:**
- Create `tests/canary/zero_retention_test.go`
- Create `tests/canary/sweep.go`
- Create `docs/evidence-pack.md`

**Test procedure:**

1. Generate unique high-entropy canaries for prompt, backend response, API key, JWT claim, and backend error.
2. Exercise allowed, denied, malformed, oversized, failed-backend, and client-disconnect paths.
3. Search enumerated persistence destinations: PostgreSQL logical tables, database logs, gateway/container logs, mounted volumes, configured temporary directory, exported evidence, and checkpoint output.
4. Confirm only expected HMACs and category/count metadata remain.
5. Record exactly which locations and encodings were tested.

Do not call this proof of universal absence. Report: “No tested canary was detected in the enumerated persistence locations.”

**Commands:** `go test ./tests/canary -v`.

**Commit:** `test: add zero-retention persistence canary sweep`.

### Task 17: Harden the container and host preflight

**Files:**
- Create `deploy/gateway.Dockerfile`, `deploy/compose.yaml`
- Create `deploy/scripts/zrm-preflight.sh`
- Create `docs/deployment.md`

**Container controls:**
- Non-root gateway user.
- Read-only root filesystem.
- Explicit tmpfs for unavoidable temporary paths.
- Dropped Linux capabilities.
- `no-new-privileges`.
- Core dumps disabled.
- No Docker logging configuration capable of receiving content because logs are typed metadata only.
- Secrets mounted from root-readable files rather than embedded in images or Compose YAML.
- Health checks that expose no configuration or content.

**Host preflight checks:**
- Swap disabled.
- Core-dump posture.
- Writable/mounted paths enumerated.
- TLS and content-HMAC key file permissions.
- Database is not externally exposed by default.
- Backend reachability and security mode.
- System clock sanity.

For the demo, preflight fails closed on mandatory ZRM controls; provide no “ignore all” flag.

**Verification:** Run Compose, inspect effective container security settings, and execute the full integration/canary suite.

**Commit:** `build: package hardened single-host deployment`.

### Task 18: Produce the technical demo and evidence pack

**Files:**
- Create `docs/demo-runbook.md`
- Complete `docs/evidence-pack.md`
- Update `README.md`

**Demo sequence:**

1. Show an unauthorized user being denied.
2. Show an authorized user successfully invoking an existing backend.
3. Submit synthetic email, IBAN, health indicator, and fake secret values.
4. Show category/count events with no matched text.
5. Show a per-user budget denial and a concurrent-limit test.
6. Export audit records and verify the hash chain and signed checkpoint offline.
7. Modify a copied audit row and show verification failure.
8. Demonstrate that runtime/admin database roles cannot update/delete audit rows.
9. Show a database administrative event in the DB audit log.
10. Run the canary sweep and present its signed report.
11. Disconnect the network path to the vendor—nothing changes because no vendor control plane exists.
12. State detector and local-root limitations explicitly.

**Release verification commands:**

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...
docker compose -f deploy/compose.yaml build
docker compose -f deploy/compose.yaml up -d
go test ./tests/integration ./tests/e2e ./tests/canary -v
```

Expected: all commands exit successfully; no canary plaintext appears in enumerated persistent stores.

**Commit:** `docs: add reproducible compliance gateway demo and evidence pack`.

---

## 10. Delivery schedule

### Week 1 — 13–17 July

- Tasks 1–4.
- Freeze V1 API, content taxonomy, threat model, and configuration.
- Establish CI and safe logging before content handling exists.

**Exit criterion:** The build is reproducible; product claims and prohibited persisted fields are documented and schema-testable.

### Week 2 — 20–24 July

- Tasks 5–8.
- PostgreSQL roles, append-only audit chain, export, and checkpoint verification.

**Exit criterion:** Synthetic events can be inserted, exported, independently verified, and tampering is detected.

### Week 3 — 27–31 July

- Tasks 9–11.
- API keys, OIDC, and typed default-deny policy.

**Exit criterion:** Authorized and unauthorized principals receive deterministic decisions with no backend involved.

### Week 4 — 3–7 August

- Task 12 and detector documentation.

**Exit criterion:** Synthetic German/Austrian PII, selected health indicators, and secrets produce category/count findings without retaining matches.

### Week 5 — 10–14 August

- Tasks 13–15.
- Atomic budgets, backend client, and first end-to-end completion.

**Exit criterion:** One complete request can be authenticated, classified, authorized, reserved, inferred, settled, audited, and returned.

### Week 6 — 17–21 August

- Tasks 16–17.
- Canary test and hardened Compose deployment.

**Exit criterion:** The gateway passes the enumerated persistence sweep on a clean Linux host matching the target deployment.

### Week 7 — 24–28 August

- Task 18.
- Demo rehearsal, performance checks, evidence-pack review, and pilot installation rehearsal.

**Exit criterion:** A third party can follow the runbook from a clean host and reproduce the complete demo.

### Buffer — 31 August

- Only critical fixes, documentation correction, and packaging. No new features.

---

## 11. Demo acceptance criteria

The demo is complete only when all are true:

- [ ] A valid OIDC token can call an explicitly permitted model.
- [ ] A valid API key can call only the principal’s permitted models.
- [ ] Missing, expired, disabled, or unauthorized credentials fail closed.
- [ ] `/v1/models` is filtered by caller policy.
- [ ] Streaming, tools, unsupported modalities, query parameters, and oversized bodies are rejected safely.
- [ ] PII, health indicators, and secrets generate category/count events without snippets.
- [ ] Request and response plaintext canaries are absent from all enumerated persistent stores.
- [ ] Exact request and response bytes can later be matched by a party holding the HMAC key.
- [ ] Concurrent requests cannot exceed a user’s daily or monthly spending limit.
- [ ] The backend is not called if authentication, authorization, reservation, or initial auditing fails.
- [ ] A successful response is not returned until final audit and budget settlement commit.
- [ ] Audit events cannot be updated or deleted by runtime, reader, or security-admin roles.
- [ ] Copied-data tampering is detected by chain and checkpoint verification.
- [ ] Database administrative activity appears in the configured DB audit output.
- [ ] The full service runs through Docker Compose without Kubernetes.
- [ ] The evidence pack states, rather than hides, the root/superuser and detector limitations.

---

## 12. Performance and operational targets

These are demo targets, not contractual SLAs:

- Gateway overhead excluding inference: p95 below 50 ms on the target host for a 100 KiB request.
- At least 20 concurrent non-streaming requests without budget overspend or audit-chain corruption.
- Maximum request and response sizes are configurable and bounded.
- Graceful shutdown stops accepting requests, completes bounded in-flight settlement, and then exits.
- Database outage produces a fixed `503` and zero new backend invocations.
- Backend timeout is configurable and produces a content-free failure record.

Benchmark with synthetic content only.

---

## 13. Risks and mitigations

### PII/medical detection accuracy

**Risk:** Deterministic detectors miss contextual personal or medical data and can also over-classify.

**Mitigation:** Call outputs indicators, publish supported detector classes and test corpus, allow customer-defined patterns, version detector bundles, and avoid “complete DLP” claims. Evaluate a local semantic detector only after the demo and only if pilot requirements demand it.

### Local administrator strength

**Risk:** A host root or PostgreSQL superuser can rewrite local state and potentially steal file-based signing keys.

**Mitigation:** Demonstrate tamper evidence and least privilege now. Require TPM/HSM signing and an independent WORM witness before claiming resistance to privileged administrators in production.

### Budget accuracy

**Risk:** Existing inference backend may omit or misreport usage; exact tokenizer integration may be model-specific.

**Mitigation:** Reserve conservatively and settle to the maximum when reliable usage is unavailable. Do not claim exact billing until the backend’s usage semantics are validated.

### Metadata sensitivity

**Risk:** Principal plus health/PII indicator metadata can itself reveal sensitive facts.

**Mitigation:** Restrict audit readers, minimize identity fields, encrypt storage, use explicit retention policy, and include event metadata in GDPR/DPIA analysis.

### Availability versus audit guarantees

**Risk:** Fail-closed auditing makes PostgreSQL availability part of inference availability.

**Mitigation:** Accept this for the first compliance-focused single-host product. Do not add an unaudited fallback. Production HA can use local PostgreSQL replication after a customer requires it.

### Schedule pressure

**Risk:** OIDC, DLP, tamper evidence, and hard budget enforcement are each non-trivial.

**Mitigation:** No UI, streaming, tools, control plane, Kubernetes, OPA, SCIM, or managed inference. If schedule slips, reduce detector breadth—not audit integrity, authorization, budget atomicity, or zero-retention tests.

---

## 14. Production gates after the demo

Do not call the August artifact production-ready until these are resolved:

1. Pilot-specific legal classification and DPIA/DSFA support.
2. External penetration test and source review.
3. TPM/HSM-backed checkpoint signing.
4. Independent immutable checkpoint/log witness.
5. Formal audit retention and authorized expiry workflow, including at-least-six-month handling where Article 26(6) applies and shorter/longer periods where other law requires.
6. Backup/restore design and proof that backups contain metadata only.
7. Key generation, rotation, recovery, and destruction procedures.
8. Signed release artifacts, SBOM, vulnerability scanning, and update procedure.
9. Host OS hardening profile and supported Linux distribution.
10. High availability and disaster recovery if required by the pilot SLA.
11. Customer-facing security incident and breach-notification process.
12. Detector validation against customer-approved synthetic or de-identified examples.
13. Performance validation against the customer’s actual inference server.

---

## 15. Triggered post-V1 roadmap

### Tool calling

Trigger: pilot needs agents rather than chat-only applications.

Add tool calls by classifying and hashing tool names, arguments, and tool results as content; introduce policy over allowed tools; ensure every tool boundary is audited. Prefer `/v1/responses` compatibility rather than extending only legacy chat completions.

### Semantic health/PII classification

Trigger: deterministic detector coverage is insufficient in pilot evaluation.

Evaluate a fully local classifier with a documented model digest, no network access, deterministic configuration, and category-only outputs. Treat its model and rules as versioned policy evidence.

### Delegated agent identity

Trigger: an agent acts on behalf of a human and both identities must appear in the audit trail.

Add OAuth 2.0 Token Exchange semantics and strict scope/budget narrowing only after ordinary workload identity is stable.

### Local administration UI

Trigger: non-technical customer administrators cannot operate the CLI during the pilot.

Build a thin local UI over the same typed administrative service; do not create separate policy or audit logic.

### Vendor control plane

Trigger: at least two deployments make update, billing, or health operations meaningfully repetitive.

Export metadata-only signed envelopes. Keep inference, identity validation, policy, budgets, and audit locally autonomous.

### Air-gap bundle

Trigger: a signed customer requires disconnected installation and update media.

Package the already-local architecture; do not build a second product or control plane unless the contract requires it.

---

## 16. Decisions fixed by this plan

- One on-premises, non-Kubernetes deployment target.
- Existing customer-operated inference server.
- Go modular monolith plus PostgreSQL.
- Docker Compose packaging.
- No shared control plane.
- OIDC and API-key authentication.
- Typed YAML policy with default deny.
- Non-streaming chat completions only.
- No plaintext retention and no debug exception.
- PII/health/secret category events without matched snippets.
- Conservative atomic budget reservations.
- Tamper-evident append-only audit with signed checkpoints.
- CLI and evidence pack instead of a web UI.
- Technical demo by 28 August 2026, with 31 August reserved for critical fixes.

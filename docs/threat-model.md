# V1 Threat Model

## 1. Purpose and status

This document defines the accepted threat model for the August 2026 technical demo. It is a security contract for implementation and testing, not a claim of certification or production readiness.

The gateway sits on a customer-controlled on-premises Linux server in front of an existing OpenAI-compatible inference server. It authenticates and authorizes callers, classifies request content in memory, enforces per-user budgets, and records content-free evidence.

## 2. Security objectives

| ID | Objective |
|---|---|
| TM-01 | Only an authenticated, enabled principal may reach authorization. |
| TM-02 | Only principals explicitly permitted for an endpoint and model may invoke it. Default is deny. |
| TM-03 | Concurrent requests must not exceed a principal’s configured daily or monthly spend limit. |
| TM-04 | Plaintext request and response content must not persist to durable storage. |
| TM-05 | PII, health-data indicators, and secrets must produce category/count evidence without retaining matched values. |
| TM-06 | Every authenticated request reaching policy evaluation must produce a content-free decision event. |
| TM-07 | The backend must not be invoked unless required initial auditing and budget reservation commit. |
| TM-08 | A successful response must not be returned unless completion auditing and budget settlement commit. |
| TM-09 | Runtime, audit-reader, and ordinary security-administration roles must not update or delete audit events. |
| TM-10 | Deletion, modification, insertion, or reordering of exported audit events after a signed checkpoint must be detectable. |
| TM-11 | Database connections, role changes, DDL, and privileged writes must be logged without request content or SQL bind values. |
| TM-12 | Errors and operational logs must use fixed schemas and codes and must never echo input or backend content. |

## 3. Assets

### Content assets

- User, system, and assistant message text.
- Exact request and response bodies.
- Unsupported or unknown client-provided string fields.
- Backend error bodies and fragments.
- API-key secrets and bearer JWTs.
- Detector matches and captured groups.

### Security and evidence assets

- Principal identity and group mapping.
- Authorization policy and policy digest.
- Daily/monthly budgets, reservations, and settlement state.
- Content HMAC key.
- Audit-checkpoint signing key.
- Audit events, chain head, and signed checkpoints.
- OIDC issuer, audience, JWKS cache, and API-key verifiers.
- Backend credentials and TLS private keys.

### Availability assets

- Gateway process.
- Local PostgreSQL.
- Customer identity provider/JWKS endpoint.
- Existing inference server.

## 4. Actors and capabilities

| Actor | Expected capability | V1 security expectation |
|---|---|---|
| Anonymous network caller | Can send arbitrary HTTP traffic to exposed gateway port. | Cannot authenticate, invoke backend, read models, or cause content to persist. |
| Authenticated application user | Has a valid OIDC token or API key and can submit arbitrary supported request content. | Can invoke only explicitly permitted models and cannot alter audit or budget state. |
| Compromised API key | Can act as its bound principal until disabled or expired. | Cannot widen scope, bypass budget, or access administration. Rotation/revocation is required mitigation. |
| Customer security administrator | Manages principals, keys, budgets, and policy through controlled interfaces. | Cannot update/delete audit rows or forge valid signed checkpoints. Administrative changes are audited. |
| Audit reader/auditor | Reads and exports content-free evidence and public verification material. | Cannot write operational, budget, identity, or audit state. |
| Gateway runtime | Reads configuration, authenticates, reserves budgets, invokes backend, and inserts approved events. | Has no general audit update/delete privilege and no database-superuser capability. |
| AgentBox operator | Installs or supports the deployment without routine content or database-superuser access. | Cannot alter audit via application/admin credentials. Host-root access is outside the V1 prevention guarantee and must be separately controlled. |
| PostgreSQL administrator/superuser | Can administer the local database. | Activity should be logged, but a superuser can ultimately bypass PostgreSQL controls. Silent history rewriting is addressed only through independently protected signed checkpoints. |
| Host root | Controls processes, files, memory, containers, and local logs. | Outside the V1 confidentiality and prevention boundary. Production mitigation requires customer access controls, TPM/HSM keys, and independent immutable evidence. |
| Infrastructure provider | May control underlying physical or virtual infrastructure. | Explicitly out of concern for the initial customer requirement; not covered by V1 claims. |
| Existing inference server | Receives authorized plaintext and returns plaintext/usage. | Trusted to perform inference and not independently persist content; its retention posture is a customer prerequisite and not enforced by the gateway. |

## 5. Trust boundaries

### TB-1: Client to gateway

- HTTPS is mandatory except isolated local test fixtures.
- Client identity comes from a validated OIDC JWT or an API key.
- Client headers, query strings, request IDs, model names, and JSON fields are untrusted.
- Authorization headers are never forwarded to the inference backend.

### TB-2: Gateway content-processing boundary

- Request/response content exists in bounded memory only.
- Request size, response size, and processing duration are bounded.
- Unsupported streaming, tools, modalities, query parameters, and fields are rejected.
- The gateway reconstructs a supported-field-only backend request; it does not proxy arbitrary JSON or headers.

### TB-3: Gateway to inference backend

- Backend address and credential are server configuration, not caller input.
- HTTPS is required for remote backends. Plain HTTP is accepted only for loopback or an explicit documented local-network exception.
- Backend errors are mapped to fixed codes and never copied into logs or audit details.
- Backend usage is validated. Missing reliable usage settles to the conservative reserved amount.

### TB-4: Gateway to PostgreSQL

- Runtime uses a least-privilege role and approved procedures.
- Prompt, output, JWT, API-key secret, detector match, and backend error values are forbidden in SQL parameters and schemas.
- Audit inserts and budget operations are transactional.
- Audit tables reject update/delete for runtime, reader, and ordinary administration roles.

### TB-5: PostgreSQL to audit verifier/witness

- Audit exports contain content-free canonical events, chain hashes, and signed checkpoints.
- Verification uses a public key and must work without database write access.
- File-based signing is demo-only. Production protection from DB/host administrators needs TPM/HSM signing and a checkpoint copy outside their alteration domain.

## 6. Request security state machine

1. Generate a server-owned request ID.
2. Authenticate caller.
3. Read a bounded body into memory.
4. Strictly parse the supported V1 shape.
5. Compute a per-deployment HMAC over exact request bytes.
6. Run in-memory detectors and aggregate category/count findings.
7. Evaluate default-deny policy using a content-free decision context.
8. On denial, commit a final decision event and return a fixed `403`; do not call backend.
9. On allowance, conservatively reserve budget and commit `run_started`.
10. Invoke the configured backend with reconstructed fields.
11. Buffer and validate a bounded response.
12. Compute response HMAC.
13. Settle budget and commit `run_completed` or `run_failed`.
14. Return a successful response only after commit.

A client disconnect after step 10 must not cancel bounded final settlement and auditing.

## 7. Threats and required mitigations

| Threat | Required V1 mitigation | Residual risk |
|---|---|---|
| Unauthenticated inference | OIDC/API-key authentication before policy and backend invocation. | Stolen valid credentials act with their principal’s scope until revocation/expiry. |
| Scope escalation | Default-deny typed policy; caller cannot choose groups, backend, or effective principal. | Incorrect customer policy can grant excessive access. |
| Budget race | Row-locked atomic reservation before inference; integer money; settlement transaction. | Conservative reservations may reject valid work near a limit. |
| Body/query leakage in access logs | Reject query parameters; typed logger; no body/header logging. | Customer-managed network devices are outside gateway control and must be assessed. |
| Validation or backend error echo | Fixed public and audit error codes; no raw error serialization. | Unexpected third-party process output is addressed by canary tests, not assumed safe. |
| Content in PostgreSQL | Content-free schemas and no content-shaped SQL parameters. | A future schema change could regress this; schema and canary tests are required. |
| Content in process/container logs | Typed log API; no generic fields/messages; inference-server logs remain a customer prerequisite. | Native/runtime output can bypass a library; persistence canaries enumerate actual destinations. |
| PII/secret match leakage | Detector returns category, count, and rule ID only. | Category metadata can itself be sensitive and requires restricted access. |
| Plain hash dictionary attack | HMAC-SHA-256 with a per-deployment secret. | A party with the HMAC key can perform equality tests and must be trusted accordingly. |
| Audit update/delete by app/admin role | Separate DB roles, revoked privileges, protective triggers, controlled procedures. | PostgreSQL superuser can bypass controls. |
| Audit rewriting by DB/host admin | Hash chain and signed checkpoints; production external witness. | Demo file key can be stolen by host root; V1 cannot prevent this. |
| Signing-key misuse | Separate content-HMAC and checkpoint-signing keys; restrictive file permissions; key IDs. | Demo lacks hardware-backed non-exportability. |
| JWKS outage/unknown key | Cache known keys within configured freshness; unknown `kid` fails closed. | Revocation latency follows token lifetime and customer IdP availability. |
| Backend response without usage | Settle to conservative maximum or fail according to model config. | Cost may be overestimated. |
| Denial of service | Size/time/concurrency limits and bounded DB/backend clients. | V1 has no external DDoS service or HA. |
| Process crash after reservation | Expiring reservations and audited recovery. | Single-host outage interrupts service. |
| Go memory remanence | Dedicated process, bounded buffers, release references, swap/core-dump preflight. | Go does not promise immediate zeroing; V1 guarantees zero durable retention, not perfect RAM erasure. |

## 8. Audit integrity: exact claim

The accepted V1 claim is:

> Ordinary application, audit-reader, and security-administration credentials cannot update or delete audit events. Events are hash-chained and periodically checkpoint-signed so alteration after a protected checkpoint is detectable.

The following claim is forbidden for the demo:

> No database administrator, system administrator, or operator can alter audit history.

That stronger claim requires a signing key and witness outside every relevant administrator’s control. Database administrative actions will be logged, but a local superuser can disable or rewrite local database logs. The evidence pack must state this limitation.

## 9. Detection boundary

V1 detects documented structured PII, configured health-data indicators, and documented secret formats. It does not establish that text legally constitutes personal data, health data, or a breach. It does not guarantee semantic completeness.

Persisted findings contain only:

- category;
- count;
- rule ID or detector-bundle digest; and
- boolean presence where count is unnecessary.

No snippets, matched strings, capture groups, byte offsets, or surrounding context are permitted.

## 10. Assumptions and customer prerequisites

- Customer has classified the intended AI use and approved the policy.
- Customer IdP issues suitable short-lived tokens and remains the identity authority.
- Existing inference server is customer-approved and configured not to persist prompts/responses.
- Customer host meets ZRM preflight: no swap, no core dumps, controlled writable paths, protected keys, and restricted DB exposure.
- Customer controls physical/host access and backup configuration.
- Customer chooses audit retention and access based on legal advice.
- Customer understands that classification metadata and HMACs may remain personal or sensitive data.

## 11. Explicit non-goals

- Protecting plaintext from the authorized inference backend.
- Protecting process memory from host root.
- Proving the infrastructure provider cannot observe data.
- Detecting every contextual PII or medical reference.
- Providing human-review workflows, output safety, or medical/legal correctness.
- Guaranteeing availability during local PostgreSQL or host failure.
- Determining legal compliance or AI Act risk category.

## 12. Verification references

Acceptance-test IDs and their requirement mapping are defined in [compliance-control-map.md](compliance-control-map.md). Persisted/prohibited fields are defined in [data-inventory.md](data-inventory.md). Any implementation behavior conflicting with those documents requires an explicit contract revision before code changes.

# V1 Compliance Control and Acceptance-Test Map

## 1. Purpose

This document maps the first-customer requirements to technical controls and executable acceptance tests. It is an engineering evidence map, not a legal opinion or certification.

The gateway can support access control, traceability, data minimization, accountability, and operational evidence. The customer remains responsible for intended-use classification, lawful basis, human and organizational controls, instructions for use, retention decisions, and regulatory submissions.

## 2. Product-claim boundary

### Permitted

> The gateway enforces customer-approved inference access and handling policies and produces verifiable evidence of how requests were authorized, classified, budgeted, routed, and handled.

> In the tested zero-retention deployment, no tested plaintext canary was detected in the enumerated persistence locations.

> Audit history is append-only for application and ordinary administration roles and tamper-evident through hash chaining and signed checkpoints.

### Prohibited

- “The gateway makes every AI request EU AI Act compliant.”
- “The gateway detects all PII or medical data.”
- “No administrator can alter audit history.”
- “HMACs or classification metadata are anonymous.”
- “A canary sweep proves that no content can ever persist.”
- “Using the gateway automatically satisfies GDPR, professional secrecy, medical-device, or sector obligations.”

## 3. Customer requirements

| ID | Requirement | Accepted V1 interpretation |
|---|---|---|
| REQ-01 | Access must be gated to permitted users. | Validate OIDC JWTs or API keys, map to enabled principals, apply default-deny endpoint/model policy. |
| REQ-02 | Who may use each service/model must be controlled. | Local typed policy grants exact principal/group, endpoint, and model combinations. |
| REQ-03 | Requests and responses need hashed traces. | Persist per-deployment HMAC-SHA-256 of exact accepted request bytes and exact returned response bytes. |
| REQ-04 | No plaintext requests may be retained. | Persist no request or response content, snippets, matches, raw credentials, or content-bearing errors. |
| REQ-05 | PII, medical data, and secrets must be detected and logged. | Run versioned in-memory detectors and persist category/count indicators only; no claim of semantic completeness or legal classification. |
| REQ-06 | Spending limits must be observed per user. | Atomically reserve a conservative maximum before inference and settle after usage; concurrent requests cannot exceed daily/monthly limits. |
| REQ-07 | Application users, customer admins, and AgentBox operators must not alter logs. | Their ordinary roles have no audit update/delete privilege; hash chain/checkpoints detect later changes. Host-root/DB-superuser prevention requires a production external trust anchor. |
| REQ-08 | Database administrator logins and actions must be logged. | `pgaudit`/PostgreSQL records connections, roles, DDL, and privileged activity without bind values. Local superuser can still tamper with local DB logs; production requires an independent witness. |
| REQ-09 | Evidence must support EU AI Act audits. | Publish versioned event schema, policy/detector/config/software digests, content HMACs, decision context, budget outcome, and independently verifiable checkpoints. Applicability remains customer/legal responsibility. |
| REQ-10 | Technical demo by end of August 2026. | Complete the documented non-streaming, single-host scope by 28 August with 31 August reserved for critical fixes. |

## 4. Acceptance tests

These IDs are stable references for implementation tests and the evidence pack.

### Authentication and authorization

| Test ID | Requirement | Setup and action | Pass condition |
|---|---|---|---|
| AC-AUTH-001 | REQ-01 | Call with a valid OIDC token having configured issuer, audience, subject, expiry, signature, and group claims. | Principal resolves and request proceeds to policy; raw JWT is absent from persistence. |
| AC-AUTH-002 | REQ-01 | Call with expired, wrong-audience, wrong-issuer, invalid-signature, unknown-`kid`, or `none`-algorithm JWT. | Fixed `401`; backend not called; no raw token/claims in logs. |
| AC-AUTH-003 | REQ-01 | Call with valid, disabled, expired, malformed, and unknown API keys. | Only valid enabled key authenticates; complete key is never stored or logged. |
| AC-AUTHZ-001 | REQ-02 | Authenticated principal requests an endpoint/model without an explicit grant. | Fixed `403`, denial audit event, backend not called. |
| AC-AUTHZ-002 | REQ-02 | Principal/group has an exact endpoint/model grant. | Request is allowed subject to budget and audit availability. |
| AC-AUTHZ-003 | REQ-02 | Conflicting allow and deny rules apply. | Deny wins deterministically and policy digest/reason code are recorded. |
| AC-MODEL-001 | REQ-02 | Two principals call `GET /v1/models` with different grants. | Each sees only explicitly permitted models. |

### Zero retention and classification

| Test ID | Requirement | Setup and action | Pass condition |
|---|---|---|---|
| AC-ZRM-001 | REQ-03, REQ-04 | Send unique prompt and response canaries through a successful call. | Correct request/response HMACs persist; plaintext canaries are absent from enumerated stores. |
| AC-ZRM-002 | REQ-04 | Exercise denied, malformed, oversized, backend-error, and client-disconnect paths with unique canaries. | No canary appears in gateway logs, DB tables/logs, volumes, temp paths, exports, or checkpoints. |
| AC-ZRM-003 | REQ-04 | Send query parameters, `stream: true`, tool fields, unsupported modalities, and unknown fields. | Request is rejected with fixed content-free error; backend not called. |
| AC-ZRM-004 | REQ-04 | Cause validation and backend errors containing unique text. | Public, operational, and audit outputs contain fixed codes only. |
| AC-DET-001 | REQ-05 | Submit synthetic German/Austrian email, phone, valid IBAN, supported identifier, health indicator, and fake secret fixtures. | Expected server-defined categories/counts and detector digest persist. |
| AC-DET-002 | REQ-05 | Inspect every finding, audit row, log, and export after detection. | No match, snippet, context, capture group, offset, or hash of an individual match persists. |
| AC-DET-003 | REQ-05 | Submit invalid checksums and documented false-positive regression fixtures. | Invalid structured values are not reported; regression behavior matches detector documentation. |
| AC-DET-004 | REQ-05 | Fuzz detector with arbitrary byte strings and invalid UTF-8. | No panic and no input value appears in error/log output. |

### Spending limits

| Test ID | Requirement | Setup and action | Pass condition |
|---|---|---|---|
| AC-BUDGET-001 | REQ-06 | Submit one request whose conservative reservation exceeds daily/monthly remaining budget. | Fixed denial; backend not called; denial/reservation outcome audited. |
| AC-BUDGET-002 | REQ-06 | Submit concurrent individually valid requests whose aggregate reservation exceeds the remaining limit. | Only reservations fitting the limit commit; total reserved+spent never exceeds limit. |
| AC-BUDGET-003 | REQ-06 | Complete a request with reliable usage. | Reservation settles atomically to integer actual cost and completion audit agrees. |
| AC-BUDGET-004 | REQ-06 | Backend omits/unreliably reports usage. | Request settles to conservative maximum or fails according to model policy; never under-reserves silently. |
| AC-BUDGET-005 | REQ-06 | Crash/expire a reservation and run recovery. | Recovery follows configured rule and creates a content-free recovery audit event. |

### Audit integrity and database activity

| Test ID | Requirement | Setup and action | Pass condition |
|---|---|---|---|
| AC-AUDIT-001 | REQ-07 | Attempt audit update/delete as gateway runtime, security admin, and audit reader. | Database denies every attempt. |
| AC-AUDIT-002 | REQ-07 | Insert concurrent valid events. | One contiguous sequence and valid hash chain results. |
| AC-AUDIT-003 | REQ-07, REQ-09 | Export evidence and verify a signed checkpoint with only the public key. | Verification succeeds without DB write access. |
| AC-AUDIT-004 | REQ-07, REQ-09 | Modify, delete, insert, or reorder an event in a copied export after checkpoint. | Verification fails at the first affected sequence/checkpoint. |
| AC-AUDIT-005 | REQ-07 | Attempt to forge checkpoint without signing key. | Signature verification fails. Demo documentation notes file-key/root limitation. |
| AC-DBA-001 | REQ-08 | Connect, change role, run DDL, and attempt prohibited write as administrative roles. | Connection/role/DDL/write class and outcome appear in DB audit output. |
| AC-DBA-002 | REQ-04, REQ-08 | Repeat DB tests while request canaries are in flight. | DB audit output contains no bind values or plaintext canaries. |

### Fail-closed lifecycle and evidence

| Test ID | Requirement | Setup and action | Pass condition |
|---|---|---|---|
| AC-FAIL-001 | REQ-04, REQ-09 | Make PostgreSQL unavailable before reservation/start audit. | Fixed `503`; backend invocation count remains unchanged. |
| AC-FAIL-002 | REQ-03, REQ-06, REQ-09 | Fail completion settlement/audit after backend response is buffered. | Successful response is not returned; start/failure state is recoverable and auditable. |
| AC-FAIL-003 | REQ-09 | Disconnect client after backend invocation. | Bounded internal completion still settles budget and writes final event. |
| AC-EVID-001 | REQ-09 | Validate every exported event against published JSON Schema. | All events validate and unknown fields are rejected. |
| AC-EVID-002 | REQ-09 | Re-evaluate a recorded decision from policy digest and content-free decision context. | Same allow/deny outcome and reason codes are obtained. |
| AC-DEMO-001 | REQ-10 | Follow demo runbook from a clean supported Linux host. | Compose stack starts and all authentication, policy, detector, budget, audit, DB-admin, and canary demonstrations reproduce. |

## 5. Controls-to-evidence matrix

| Control | Design evidence | Runtime evidence | Test evidence |
|---|---|---|---|
| Identity validation | Issuer/audience/claim mapping configuration | Auth method, principal UUID, fixed outcome | AC-AUTH-001–003 |
| Default-deny permissioning | Versioned typed policy and digest | Decision context and reason codes | AC-AUTHZ-001–003, AC-MODEL-001 |
| Zero plaintext retention | Data inventory, strict schemas, safe logging design | HMACs, byte counts, content-free events | AC-ZRM-001–004 |
| PII/health/secret indicators | Versioned detector rules and documented limits | Categories, counts, detector digest | AC-DET-001–004 |
| Per-user spending limits | Integer price model and transactional reservation | Reservation/settlement fields and denial | AC-BUDGET-001–005 |
| Append-only audit | Role/grant migrations and insert procedures | Contiguous hash-chain events | AC-AUDIT-001–002 |
| Tamper evidence | Canonical encoding and checkpoint signature design | Signed checkpoint and chain head | AC-AUDIT-003–005 |
| DB administrative accountability | PostgreSQL/`pgaudit` configuration | Connection/role/DDL/write audit output | AC-DBA-001–002 |
| Fail-closed operation | Request lifecycle state machine | Fixed failure event/status | AC-FAIL-001–003 |
| Audit usability | JSON Schema, export and verifier specifications | Versioned export/evidence pack | AC-EVID-001–002, AC-DEMO-001 |

## 6. EU AI Act and GDPR support map

This section identifies potentially relevant engineering support; applicability must be determined for the customer’s intended use.

| Regulatory topic | Gateway support | Boundary |
|---|---|---|
| Traceability/logging | Identity, model, policy, detector, decision, usage, status, hashes, chain, checkpoints. | Gateway events do not prove that every required event of a separate high-risk AI system is captured. |
| Deployer log retention | Exportable content-free logs designed for customer-controlled retention. | Customer/legal review selects period. Article 26(6)’s at-least-six-month rule applies only where its conditions apply and may be displaced by other law. |
| Access and human responsibility | Named principals/groups and default-deny model permissioning. | Human oversight process, qualifications, instructions, and monitoring remain customer responsibilities. |
| Data minimization | No plaintext retention; category/count findings; bounded schemas. | HMACs, principal association, and health indicators can still be personal/sensitive metadata. |
| Integrity/confidentiality | TLS, least-privilege roles, no content logs, hash chain and checkpoints. | Host root and DB superuser require external/hardware-backed production controls. |
| Accountability | Policy/config/software/detector versions and reproducible decision context. | Legal conclusion and documentation completeness remain customer responsibilities. |
| DPIA/DSFA support | Data inventory, flow, actors, retention questions, controls, and residual risks. | Customer/controller owns the assessment and lawful basis. |

Authoritative starting points:

- Regulation (EU) 2024/1689: <https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng>
- European Commission AI Act overview: <https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai>
- European Commission AI Act Q&A: <https://digital-strategy.ec.europa.eu/en/faqs/navigating-ai-act>
- BfDI health-data information: <https://www.bfdi.bund.de/DE/Buerger/Inhalte/GesundheitSoziales/Allgemein/Heil-_und_Hilfsmittel.html>
- BfDI DPIA/DSFA information: <https://www.bfdi.bund.de/DE/Fachthemen/Inhalte/Technik/Datenschutz-Folgenabschaetzungen.html>

## 7. Customer and counsel obligations before production

The customer, supported by qualified German/Austrian counsel, must decide and document:

1. Intended purpose and whether each AI use is prohibited, high risk, transparency-regulated, or otherwise regulated.
2. Provider/deployer, controller/processor, professional-secrecy, medical-device, and sector-specific roles.
3. Lawful basis for processing prompts and detector classifications, including health data.
4. Required human oversight, instructions, training, monitoring, and incident process.
5. Audit and database-log retention, legal holds, deletion, and subject-right procedures.
6. DPIA/DSFA need and mitigations.
7. Works-council/employee-monitoring implications of per-user identity, classification, and spend logs.
8. Existing inference server retention, security, model provenance, and output-use controls.
9. Which administrators control the host, database, checkpoint signer, and immutable witness.

## 8. Review checklist

Before accepting a change:

- [ ] Every persisted field is classified in `data-inventory.md`.
- [ ] Every new behavior has an acceptance-test ID or extends one explicitly.
- [ ] No claim implies universal legal compliance.
- [ ] No claim equates deterministic indicators with complete PII/medical detection.
- [ ] No claim says local DB/host administrators are unable to alter evidence without an external trust anchor.
- [ ] No canary result is described as proof of universal absence.
- [ ] Legal classification and retention remain explicit customer/counsel decisions.
- [ ] Content-free schemas contain no arbitrary/free-form fields.

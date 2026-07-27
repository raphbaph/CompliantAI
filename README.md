# Compliant Inference Gateway

A single-tenant, on-premises gateway for enforcing customer-approved access and handling policies in front of an existing OpenAI-compatible inference server.

> **Project status:** technical-demo implementation on branch `Development-start`. Package-level controls, hardened Compose packaging, and verification suites are in place. Full `cmd/gateway` live process bootstrap (TLS serve wiring) remains a packaging follow-up behind Compose profile `gateway`. This repository is **not** a legal-compliance certification.

## Product claim

The gateway is intended to enforce customer-approved inference access and handling policies and produce verifiable evidence of how requests were authorized, classified, budgeted, routed, and handled.

It does **not** decide whether an arbitrary request, AI system, or organization is “EU AI Act compliant.” Applicability, risk classification, lawful basis, retention, and organizational obligations depend on the customer’s intended use and require customer and legal review.

## August 2026 demo scope

The technical demo targets a small German or Austrian legal or medical enterprise that:

- operates an OpenAI-compatible inference server on premises;
- does not operate Kubernetes;
- needs identity-based access to approved models;
- needs per-user spending limits;
- needs content-free, tamper-evident audit evidence; and
- must not retain plaintext prompts or model responses.

### Included

- Go gateway deployed with Docker Compose on a customer-controlled Linux server.
- Non-streaming `POST /v1/chat/completions` vertical slice.
- Caller-filtered `GET /v1/models`.
- OIDC bearer JWTs and transitional principal-bound API keys.
- Local typed YAML allow/deny policy with default deny.
- Atomic daily and monthly per-user spend-limit enforcement.
- In-memory detection of configured PII, health-data indicators, and secrets.
- HMAC digests of exact request and response bytes.
- Content-free audit events in local PostgreSQL.
- Append-only database permissions, hash chaining, signed checkpoints, export, and independent verification.
- Database connection, role, DDL, and privileged-activity logging (pgaudit).
- Zero-retention preflight and persistence-canary testing.
- Hardened container packaging (non-root, read-only rootfs, dropped capabilities).

### Not included

- Streaming, tool/function calling, embeddings, images, audio, documents, or batch inference.
- Retained-content mode or a per-request debug exception.
- A web administration UI.
- OPA, Cedar, SAML, SCIM, or OAuth token exchange.
- A vendor-hosted control plane, fleet management, or remote operator access.
- Kubernetes, managed GPUs, model serving, or air-gap media delivery.
- Semantic DLP or a guarantee that all natural-language personal or medical information is detected.
- A universal EU AI Act or GDPR compliance determination.

## What is implemented (technical demo)

| Area | Package / asset | Status |
|---|---|---|
| Config + safe logging | `internal/config`, `internal/safelog` | Verified |
| PostgreSQL roles + migrations | `migrations/`, `deploy/postgres*` | Verified |
| Audit chain, export, checkpoints | `internal/audit`, `cmd/agentboxctl` | Verified |
| API keys + OIDC JWT | `internal/auth` | Verified |
| Default-deny policy | `internal/policy` | Verified |
| Detectors | `internal/detect` | Verified |
| Atomic budgets | `internal/budget` | Verified |
| Bounded OpenAI client | `internal/backend` | Verified |
| HTTP API vertical slice | `internal/api` | Verified (injected deps) |
| Canary ZRM suite | `tests/canary` | Verified |
| Hardened Compose + preflight | `deploy/` | Verified |
| Live gateway process bootstrap | `cmd/gateway --config` | Packaging follow-up |

## Security summary

Plaintext request and response content may exist in bounded gateway memory while a synchronous request is processed. It must not enter PostgreSQL, files, metrics, traces, application logs, database logs, exports, or checkpoints. Persisted evidence is limited to keyed content digests and explicitly allowed operational metadata.

The gateway fails closed when authentication, authorization, budget reservation, or required audit persistence is unavailable. It does not invoke the inference backend until an initial audit event and budget reservation have committed, and it does not return a successful response until completion evidence and budget settlement have committed.

Audit records are **tamper-evident**, not physically immutable against a PostgreSQL superuser or host root user. Application and ordinary administration roles cannot update or delete events. A hash chain and signed checkpoints expose later alteration. Production resistance to privileged local administrators requires checkpoint signing in a TPM/HSM and an independent immutable witness such as customer-controlled WORM storage.

## Quick start (developers)

```bash
# Unit and package tests
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...

# Zero-retention canary sweep
go test ./tests/canary -v

# Hardened images (standalone docker-compose binary on some hosts)
docker-compose -f deploy/compose.yaml build

# Host/container preflight (full ZRM host checks require Linux)
./deploy/scripts/zrm-preflight.sh
```

Live PostgreSQL integration tests require compose Postgres and role DSNs — see [docs/deployment.md](docs/deployment.md).

## Documentation

| Document | Purpose |
|---|---|
| [Demo runbook](docs/demo-runbook.md) | 12-step technical demo sequence |
| [Evidence pack](docs/evidence-pack.md) | Evidence index and interpretation |
| [Deployment](docs/deployment.md) | Single-host Compose + preflight |
| [Threat model](docs/threat-model.md) | Adversaries and residuals |
| [Data inventory / ZRM](docs/data-inventory.md) | What may persist |
| [Compliance control map](docs/compliance-control-map.md) | Requirements → acceptance tests |
| [Policy reference](docs/policy-reference.md) | Authorization policy contract |
| [Audit export verification](docs/audit-export-verification.md) | Offline verify algorithm |

## Planned deployment boundary

```text
Customer application
        |
        | HTTPS + OIDC JWT or API key
        v
+----------------------------- customer-controlled host -----------------------------+
|                                                                                     |
|  Go gateway  --->  existing OpenAI-compatible inference server                      |
|      |                                                                              |
|      +------> local PostgreSQL (identity, budgets, content-free audit metadata)       |
|                                                                                     |
+-------------------------------------------------------------------------------------+

No vendor control plane or vendor data path exists in V1.
```

## Legal and customer review

Before a production pilot, the customer and qualified German/Austrian counsel must determine the intended-use classification, controller/processor roles, lawful basis, retention period, DPIA/DSFA needs, employment/works-council implications, and any sector-specific duties. The gateway supplies technical controls and evidence; it does not replace those decisions.

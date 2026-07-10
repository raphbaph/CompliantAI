# Compliant Inference Gateway

A single-tenant, on-premises gateway for enforcing customer-approved access and handling policies in front of an existing OpenAI-compatible inference server.

> **Project status:** pre-implementation technical-demo scope. This repository does not yet contain a production-ready service or a legal-compliance certification.

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
- Non-streaming `POST /v1/chat/completions`.
- Caller-filtered `GET /v1/models`.
- OIDC bearer JWTs and transitional principal-bound API keys.
- Local typed YAML allow/deny policy with default deny.
- Atomic daily and monthly per-user spend-limit enforcement.
- In-memory detection of configured PII, health-data indicators, and secrets.
- HMAC digests of exact request and response bytes.
- Content-free audit events in local PostgreSQL.
- Append-only database permissions, hash chaining, signed checkpoints, export, and independent verification.
- Database connection, role, DDL, and privileged-activity logging.
- Zero-retention preflight and persistence-canary testing.

### Not included

- Streaming, tool/function calling, embeddings, images, audio, documents, or batch inference.
- Retained-content mode or a per-request debug exception.
- A web administration UI.
- OPA, Cedar, SAML, SCIM, or OAuth token exchange.
- A vendor-hosted control plane, fleet management, or remote operator access.
- Kubernetes, managed GPUs, model serving, or air-gap media delivery.
- Semantic DLP or a guarantee that all natural-language personal or medical information is detected.
- A universal EU AI Act or GDPR compliance determination.

## Security summary

Plaintext request and response content may exist in bounded gateway memory while a synchronous request is processed. It must not enter PostgreSQL, files, metrics, traces, application logs, database logs, exports, or checkpoints. Persisted evidence is limited to keyed content digests and explicitly allowed operational metadata.

The gateway fails closed when authentication, authorization, budget reservation, or required audit persistence is unavailable. It does not invoke the inference backend until an initial audit event and budget reservation have committed, and it does not return a successful response until completion evidence and budget settlement have committed.

Audit records are **tamper-evident**, not physically immutable against a PostgreSQL superuser or host root user. Application and ordinary administration roles cannot update or delete events. A hash chain and signed checkpoints expose later alteration. Production resistance to privileged local administrators requires checkpoint signing in a TPM/HSM and an independent immutable witness such as customer-controlled WORM storage.

## Documentation

- [Threat model](docs/threat-model.md)
- [Data inventory and zero-retention contract](docs/data-inventory.md)
- [Compliance control and acceptance-test map](docs/compliance-control-map.md)

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

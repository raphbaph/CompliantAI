# Evidence pack (V1 technical demo)

This document describes the evidence produced by the Compliant Inference Gateway technical demo and how to interpret it.

## Product claim boundary

The gateway produces **verifiable evidence of customer-configured controls** (authentication outcome, policy decision, classification categories/counts, budget reservation/settlement, content HMACs, and integrity chain).

It does **not** certify that an organization, AI system, or request is “EU AI Act compliant.” Applicability and legal conclusions require customer and counsel review.

## Evidence artifacts

| Artifact | Source | Content class |
|---|---|---|
| Audit event export (JSONL/JSON) | `agentboxctl` / audit export path | C1–C5 only |
| Hash-chain verification report | Offline verifier | C5 |
| Signed checkpoint | `audit_checkpoints` + Ed25519 signature | C5 |
| Canary sweep report | `go test ./tests/canary` | Test metadata only |
| Database administrative audit (pgaudit) | PostgreSQL logs | C5 operational |
| Policy digest / version | Policy engine | C3/C5 |
| Detector bundle digest | Detector package | C5 |

## Zero-retention canary sweep

### Procedure

1. Generate unique high-entropy canaries for prompt, backend response, API key, JWT claim, malformed input, and backend error.
2. Exercise allowed, policy-denied, malformed/stream-rejected, oversized, backend-failure, and client-disconnect paths through the HTTP API vertical slice.
3. Search enumerated persistence destinations and encodings (see test report fields `locations_searched` and `encodings_searched`).
4. Fail the test if any canary appears in those destinations.

### Approved wording on a clean run

> No tested canary was detected in the enumerated persistence locations.

### Explicit limitations

- The sweep does **not** prove universal absence of content from unenumerated systems (caller devices, IdP logs, inference-server logs, SIEM, packet captures, crash dumps outside preflight controls).
- In-memory process state during a request may hold C0 content; the commitment is about **persistence destinations enumerated by the test and deployment inventory**.
- Search encodings are exact and case-folded UTF-8 substring matches (plus optional PostgreSQL `CAST(... AS text) LIKE` when `TEST_GATEWAY_DSN` is set). Other encodings are out of scope unless added to the report.
- HMAC evidence is keyed equality evidence, not irreversible anonymization.

### How to run

```bash
go test ./tests/canary -v
# Optional live PostgreSQL scan when integration DSNs are exported:
# TEST_GATEWAY_DSN=... go test ./tests/canary -v
```

## Integrity verification (summary)

1. Export audit events in sequence order.
2. Recompute each event hash with the canonicalization rules in `docs/audit-export-verification.md`.
3. Verify the chain links via `previous_event_hash`.
4. Verify the latest signed checkpoint against the customer-held public key.
5. Tamper a copy and confirm verification fails without leaking row content in errors.

## Demo interpretation checklist

- [ ] Unauthorized caller receives fixed denial; backend not invoked.
- [ ] Authorized caller completes non-streaming chat against the local backend.
- [ ] Detector categories/counts appear without matched plaintext.
- [ ] Budget denial returns fixed code and is audited.
- [ ] Export verifies; tampered copy fails verification.
- [ ] Canary sweep prints the approved wording above.
- [ ] Detector and local-root limitations are stated verbally in the demo.

## Change control

New endpoints, log fields, columns, or exports must update `docs/data-inventory.md` and extend the canary sweep before merge.

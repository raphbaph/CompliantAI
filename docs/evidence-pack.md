# Evidence pack (V1 technical demo)

This document is the evidence index for the Compliant Inference Gateway technical demo. It describes **what evidence exists**, **how to produce it**, and **how to interpret it conservatively**.

## 1. Product claim boundary

The gateway produces **verifiable evidence of customer-configured controls**:

- authentication method and principal identifier (not raw tokens);
- policy version/digest, decision, and fixed reason codes;
- detector category/count metadata (not matched text);
- budget reservation and settlement amounts;
- keyed content HMACs and byte counts;
- append-only audit chain hashes and signed checkpoints.

It does **not** certify that an organization, AI system, or request is “EU AI Act compliant.” Applicability, risk class, lawful basis, and retention require customer and qualified counsel review.

Approved control-map phrasing for a clean canary run:

> In the tested zero-retention deployment, no tested plaintext canary was detected in the enumerated persistence locations.

## 2. Evidence artifacts

| Artifact | How to produce | Content class | Consumer |
|---|---|---|---|
| Unit/integration JUnit-free Go test output | `go test ./... -count=1` | Build evidence | Engineering |
| Race/vet/build logs | `go test -race ./... && go vet ./... && go build ./cmd/...` | Build evidence | Engineering |
| Audit event records | Live DB via gateway runtime / integration inserts | C1–C5 | Audit reader |
| Audit export (JSON/JSONL) | `agentboxctl` export path / offline tools | C1–C5 | Independent verifier |
| Hash-chain verification result | Offline verifier (`internal/audit` verify APIs) | C5 | Independent verifier |
| Signed checkpoint | `audit_checkpoints` + Ed25519 verify | C5 | Independent verifier |
| Canary sweep log | `go test ./tests/canary -v` | Test metadata | Security reviewer |
| pgaudit PostgreSQL logs | `docker logs compliantai-postgres` | C5 operational | Security admin |
| Policy digest/version | Policy engine `Version`/`Digest` | C3/C5 | Auditor |
| Detector bundle digest | `detect.BundleVersion` / result `BundleDigest` | C5 | Auditor |
| ZRM preflight report | `./deploy/scripts/zrm-preflight.sh` | Host/container posture | Operator |
| Container inspect JSON | `docker inspect` on running containers; gateway image via `build gateway` + one-shot hardened `docker run` (profile `gateway` not default) | Hardening posture | Operator |

## 3. How each demo step maps to evidence

| Demo step (see [demo-runbook.md](demo-runbook.md)) | Primary evidence |
|---|---|
| 1 Unauthorized denied | `internal/api` auth/policy tests; fixed public error codes |
| 2 Authorized backend call | `TestChatCompletionsVerticalSlice`; audit start+complete pair |
| 3 Synthetic PII/health/secret | `internal/detect` + DE/AT fixtures |
| 4 Category/count only | Audit event fields; canary absence in audit JSON |
| 5 Budget denial / concurrent | `TestConcurrentBudget` |
| 6 Export + verify chain/checkpoint | `internal/audit` verify + [audit-export-verification.md](audit-export-verification.md) |
| 7 Tamper detection | Verify tests with modified copy |
| 8 Runtime/admin roles cannot update/delete audit rows | `go test ./tests/integration -run 'TestPostgresRoles/audit writes are append only' -v` |
| 9 DB admin audit | `TestPostgresRoles/pgaudit records privileged attempts without parameters` + `TEST_POSTGRES_CONTAINER` + container logs |
| 10 Canary sweep | `tests/canary` + approved wording |
| 11 No vendor control plane | Architecture + compose inventory (no vendor endpoints) |
| 12 Limitations stated | This section + threat model residual risks |

> **Compose note:** `docker-compose -f deploy/compose.yaml up -d` starts **postgres** by default. The gateway service is behind profile `gateway` (`--profile gateway`) because full `cmd/gateway` TLS process bootstrap is still a packaging follow-up. Hardening evidence for the gateway image can still be collected with `docker-compose -f deploy/compose.yaml build gateway` and a one-shot hardened `docker run` of the built image (resolve the image name via `docker-compose -f deploy/compose.yaml config` as in [deployment.md](deployment.md)). Do not assume container name `compliantai-gateway` exists after a default `up`.

## 4. Zero-retention canary sweep

### Procedure

1. Generate unique high-entropy canaries for prompt, backend response, API key, JWT claim, malformed input, and backend error.
2. Exercise allowed, policy-denied, invalid JSON, stream-rejected, credential-auth failures, oversized, backend-failure, and client-disconnect paths.
3. Search only locations actually scanned (report field `locations_searched`).
4. Fail if any canary appears in those destinations.

### Approved wording on a clean run

> No tested canary was detected in the enumerated persistence locations.

### Explicit limitations

- Does **not** prove universal absence from unenumerated systems (caller devices, IdP logs, inference-server logs, SIEM, packet captures, crash dumps outside preflight).
- In-memory process state during a request may hold C0 content; the commitment is about **enumerated persistence destinations**.
- Search encodings: UTF-8 exact + case-folded substring; optional PostgreSQL `CAST(text/varchar/json/jsonb AS text) LIKE` when `TEST_GATEWAY_DSN` is set.
- HMAC evidence is keyed equality evidence, not irreversible anonymization.

### How to run

```bash
go test ./tests/canary -v
# Optional live PostgreSQL column scan:
# TEST_GATEWAY_DSN=... go test ./tests/canary -v
```

## 5. Integrity verification procedure

Detailed rules: [audit-export-verification.md](audit-export-verification.md).

Summary:

1. Export audit events in sequence order.
2. Recompute each event hash with canonicalization rules.
3. Verify `previous_event_hash` links.
4. Verify the latest signed checkpoint with the customer-held public key.
5. Tamper a **copy** and confirm verification fails without leaking row content in errors.

## 6. Release verification commands

Use the standalone Compose binary when the plugin is unavailable:

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...
docker-compose -f deploy/compose.yaml build
docker-compose -f deploy/compose.yaml up -d
# Postgres only by default. Gateway runtime profile (when bootstrap is ready):
# docker-compose -f deploy/compose.yaml --profile gateway up -d
# With live DSNs exported for Postgres roles/budget/audit tests:
go test ./tests/integration ./tests/canary -v
./deploy/scripts/zrm-preflight.sh
```

Expected: all applicable commands exit successfully; canary suite prints the approved wording; preflight has zero mandatory failures on a hardened Linux host.

## 7. Demo interpretation checklist

- [ ] Unauthorized caller receives fixed denial; backend not invoked.
- [ ] Authorized path completes non-streaming chat against the customer backend (or verified vertical slice).
- [ ] Detector categories/counts appear without matched plaintext.
- [ ] Budget denial and concurrent limit behavior demonstrated.
- [ ] Export verifies; tampered copy fails verification.
- [ ] Runtime roles cannot UPDATE/DELETE audit rows.
- [ ] pgaudit shows privileged activity without content parameters.
- [ ] Canary sweep prints the approved wording.
- [ ] No vendor control plane is present in the architecture.
- [ ] Detector and local-root limitations stated explicitly.

## 8. Residual risks (must remain visible)

From the threat model and deployment docs:

- Local root or PostgreSQL superuser can still compromise the host; checkpoints + independent witness are required for stronger resistance.
- Detectors are incomplete by design for open-ended natural language.
- Customer IdP, inference server, and SIEM are outside the gateway ZRM boundary.
- Full `cmd/gateway` TLS process bootstrap is the remaining packaging step after package-level vertical verification.

## 9. Change control

Any new endpoint, log field, column, export field, or integration must:

1. Update [data-inventory.md](data-inventory.md) with C0–C6 classification.
2. Extend canary coverage where content risk exists.
3. Update this evidence pack and the compliance control map acceptance tests.

## 10. Document set

| Document | Role |
|---|---|
| [demo-runbook.md](demo-runbook.md) | Live demo sequence |
| [deployment.md](deployment.md) | Single-host bring-up + preflight |
| [data-inventory.md](data-inventory.md) | What may persist |
| [threat-model.md](threat-model.md) | Adversaries and residuals |
| [compliance-control-map.md](compliance-control-map.md) | Requirements → acceptance tests |
| [policy-reference.md](policy-reference.md) | Authorization policy contract |
| [audit-export-verification.md](audit-export-verification.md) | Offline verify algorithm |

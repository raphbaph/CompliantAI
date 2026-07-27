# Technical demo runbook (V1)

This runbook is the reproducible sequence for the Compliant Inference Gateway technical demo on a **customer-controlled Linux host**.

## Before you start

### Claims you may make

- The gateway enforces **customer-configured** authentication, policy, budget, and handling controls and produces **content-free, tamper-evident** evidence of those controls.
- In the tested zero-retention deployment, **no tested plaintext canary was detected in the enumerated persistence locations.**

### Claims you must not make

- That the product makes an organization, model, or request “EU AI Act compliant.”
- That detectors find all natural-language personal or medical information.
- That canary results prove universal absence of content from unenumerated systems.
- That audit rows are physically immutable against PostgreSQL superuser or host root (they are **tamper-evident**).

### Prerequisites

1. Linux host with Docker Engine and standalone `docker-compose` (or Compose plugin).
2. Go toolchain matching `go.mod`.
3. Customer-operated OpenAI-compatible backend reachable as configured (for live inference steps).
4. Secrets and config prepared per [deployment.md](deployment.md).
5. Fail-closed preflight:

```bash
./deploy/scripts/zrm-preflight.sh
```

### Build and unit verification

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...
docker-compose -f deploy/compose.yaml build
docker-compose -f deploy/compose.yaml up -d
# Live DB integration + canary (export DSNs as in integration docs)
go test ./tests/integration ./tests/canary -v
```

> **Note:** Full `cmd/gateway` process bootstrap (live TLS listener + wired deps) is profile-gated (`--profile gateway`) and lands with final runtime wiring. Demo steps below use the **verified packages and integration suites** already in the repository. Where a step is package-level today, the runbook labels it clearly.

---

## Demo sequence

### Shared live-DB exports (steps 5–9)

Many demo steps use `tests/integration`. Export **all four** role DSNs plus the container name before those steps (passwords must match compose secrets):

```bash
export TEST_BOOTSTRAP_DSN='postgres://bootstrap_admin:PASSWORD@127.0.0.1:55432/compliantai?sslmode=disable'
export TEST_GATEWAY_DSN='postgres://gateway_runtime:PASSWORD@127.0.0.1:55432/compliantai?sslmode=disable'
export TEST_AUDIT_READER_DSN='postgres://audit_reader:PASSWORD@127.0.0.1:55432/compliantai?sslmode=disable'
export TEST_SECURITY_ADMIN_DSN='postgres://security_admin:PASSWORD@127.0.0.1:55432/compliantai?sslmode=disable'
export TEST_POSTGRES_CONTAINER=compliantai-postgres
```

Details: [deployment.md](deployment.md) § Live integration test environment.

---

### 1. Unauthorized caller denied

**Goal:** Fixed denial; backend not invoked.

**Package demonstration (always available):**

```bash
go test ./internal/api -run 'TestChatCompletionsAuthAndValidationFailures|TestChatCompletionsPolicyDenial' -v
```

**Narration:** Missing/invalid credentials return a fixed `401` / `invalid_credentials`. Policy denial returns fixed `403` / `policy_denied`. No backend call occurs on these paths.

---

### 2. Authorized caller invokes backend

**Goal:** Happy path through auth → policy → budget → audit start → backend → settle → audit complete.

```bash
go test ./internal/api -run TestChatCompletionsVerticalSlice -v
```

**Narration:** The vertical slice returns the backend response only after start audit and budget reservation succeed, and only after completion audit and settlement succeed. Audit JSON must not contain prompt/response canaries.

---

### 3. Synthetic email, IBAN, health indicator, and fake secret

**Goal:** Detectors fire on synthetic DE/AT fixtures without retaining match text.

```bash
go test ./internal/detect -run 'TestDetect' -v
# Fixture-backed sample:
cat tests/fixtures/detect/de_at_samples.txt
```

**Narration:** Findings are reduced to `category`, `count`, and `rule_id` only. Matched substrings are never part of the result object.

---

### 4. Category/count events without matched text

**Goal:** Audit/classification metadata is content-free.

```bash
go test ./internal/api -run TestChatCompletionsVerticalSlice -v
# Observe test assertion: audit marshal must not contain PROMPT/RESPONSE canaries or email plaintext.
go test ./tests/canary -run TestZeroRetentionCanarySweep -v
```

**Narration:** Point at audit event fields `pii_categories`, `pii_match_counts`, `health_indicator_categories`, `secret_categories`. No matched email/IBAN/secret string appears.

---

### 5. Per-user budget denial and concurrent limit

**Goal:** Atomic reservation cannot exceed remaining daily headroom.

```bash
# Requires shared live-DB exports (see above)
go test ./tests/integration -run TestConcurrentBudget -v
```

**Narration:** With daily limit 1000 and 20 concurrent 100-unit reservations, exactly 10 accept and 10 deny. Disabled principals cannot reserve. Direct table updates by `gateway_runtime` are rejected.

---

### 6. Export audit records and verify hash chain + signed checkpoint

**Goal:** Offline independent verification.

```bash
# Requires shared live-DB exports (see above)
go test ./internal/audit -run 'TestVerify|TestCheckpoint|TestHMAC' -v
go test ./tests/integration -run 'TestAudit|TestPostgresRoles' -v
# Operator docs:
# docs/audit-export-verification.md
```

**Narration:** Show export bytes, chain head, and signed checkpoint verification with the customer-held public key. Verification is content-free (no prompt replay).

---

### 7. Tamper a copied audit row → verification fails

**Goal:** Tamper evidence without leaking content in errors.

```bash
go test ./internal/audit -run TestVerify -v
# Specifically the tamper / canary-in-error cases in verify_test.go
```

**Narration:** After altering a copied model name or hash, verification fails with a fixed error and must not echo the canary content.

---

### 8. Runtime/admin roles cannot update/delete audit rows

**Goal:** Append-only at the SQL privilege boundary.

```bash
# Requires shared live-DB exports (see above)
go test ./tests/integration -run 'TestPostgresRoles/audit writes are append only' -v
```

**Narration:** `gateway_runtime` may insert only via `SECURITY DEFINER` append functions. `UPDATE`/`DELETE` on `audit_events` fail with insufficient privilege. Security-admin and audit-reader likewise cannot mutate canonical events.

---

### 9. Database administrative event in DB audit log

**Goal:** Privileged activity is recorded by pgaudit without SQL parameter content.

```bash
# Requires shared live-DB exports including TEST_POSTGRES_CONTAINER (see above)
go test ./tests/integration -run 'TestPostgresRoles/pgaudit records privileged attempts without parameters' -v
# Optional: docker logs compliantai-postgres 2>&1 | rg 'AUDIT:' | tail
```

**Narration:** Show AUDIT session lines for privileged attempts. Bound parameters/content canaries must not appear in logs (integration asserts this).

---

### 10. Canary sweep report

**Goal:** Present the approved zero-retention wording.

```bash
go test ./tests/canary -v
```

**Expected log line:**

> No tested canary was detected in the enumerated persistence locations.

**Narration:** Read `locations_searched` and `encodings_searched` from the test log. State limitations from [evidence-pack.md](evidence-pack.md).

---

### 11. No vendor control plane

**Goal:** Disconnecting “vendor network” changes nothing.

**Demonstration:**

1. Show architecture diagram in README: no outbound vendor SaaS path in V1.
2. Confirm Compose has no vendor endpoints; backend URL is customer-local.
3. Optional: drop external network route while stack runs — inference continues against the local backend; audit remains local PostgreSQL.

**Narration:** “There is no vendor control plane or vendor data path in V1.”

---

### 12. Explicit limitations (closing slide)

State verbally and leave on screen:

1. **Detectors** are rule/regex indicators for demo categories — not semantic DLP and not complete for all natural language.
2. **Local root / DB superuser** can still subvert the host; audit is tamper-evident via hash chain + signed checkpoints, not physically immutable.
3. **Canary sweep** covers enumerated locations/encodings only — not caller devices, IdP logs, inference-server logs, or SIEM.
4. **Legal** classification (EU AI Act applicability, GDPR roles, retention) remains a customer/counsel determination.
5. **Gateway process bootstrap** (full TLS serve wiring in `cmd/gateway`) is the remaining packaging step after package-level vertical verification.

---

## Timing guide (≈30–40 minutes)

| Block | Steps | Minutes |
|---|---|---|
| Setup & preflight | build, compose, preflight | 5 |
| Access control | 1–2 | 5 |
| Classification & ZRM | 3–4, 10 | 8 |
| Budget | 5 | 4 |
| Audit integrity | 6–9 | 10 |
| Architecture & limits | 11–12 | 5 |

---

## Failure handling during demo

| Symptom | Action |
|---|---|
| Preflight fails | Fix mandatory control; do not proceed with “ignore” |
| Integration tests skipped (no DSN) | Start compose Postgres; export DSNs; rerun |
| Canary finding | Stop demo; treat as release blocker; capture report |
| Backend down | Show fail-closed fixed error path; do not paste upstream body |

---

## Related documents

- [deployment.md](deployment.md)
- [evidence-pack.md](evidence-pack.md)
- [data-inventory.md](data-inventory.md)
- [threat-model.md](threat-model.md)
- [compliance-control-map.md](compliance-control-map.md)
- [policy-reference.md](policy-reference.md)
- [audit-export-verification.md](audit-export-verification.md)

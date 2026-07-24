# Zero-Retention Mode: Design Spec

AgentBox inference gateway, dedicated deployments. Draft for review.

---

## 1. Definition and scope

Zero-retention mode (ZRM) is a per-deployment configuration in which **prompt content, model outputs, and any intermediate representation of either never persist to durable storage**. Run records keep hashes only.

What still persists (and must, for billing and audit):

- Run records: version hash, input hash, output hash, token counts, duration, chain links, status, signature
- Metering events: model, tokens in/out, GPU seconds, request counts
- Audit events: who called what, when, outcome. No payloads.
- Ledger entries

The design principle that makes this enforceable rather than aspirational: **content-free by construction**. The run record schema physically has no field where content could go. Redaction pipelines are a smell; if you're scrubbing content out of logs, content got into logs, and you're one regex bug away from a breach. The goal is that content never enters any write path in the first place.

One consequence to state up front: in ZRM, a disputed run can't be re-examined by reading the prompt. Adjudication works from hashes, metadata, and re-execution (caller re-submits the input, we verify the input hash matches, we replay against the pinned artifact version). This is a real product tradeoff and it belongs in the contract, not in fine print.

---

## 2. The leak vector walk

Every place content touches between the TLS socket and the GPU, and how to close each. Ordered by the request's actual path through the system.

### 2.1 Edge and proxy layer

**Access logs.** Default nginx/Envoy access logs capture URLs and can capture bodies. Close: access log format pinned to a content-free schema (method, path template, status, duration, bytes). No query strings logged (prompts can hide in GET params if someone builds a lazy client). Request bodies never logged, enforced by config-as-code that's part of the signed deployment bundle.

**Request body buffering.** nginx spills large request bodies to disk (`client_body_buffer_size` exceeded writes to a temp file). Close: raise in-memory buffer above max request size, point the temp path at a RAM-backed tmpfs as a belt-and-suspenders, and verify the tmpfs isn't swap-backed (see 2.8).

**TLS termination.** Terminate once, inside the deployment boundary, at the gateway. No CDN, no external WAF, no third-party DDoS layer in front of ZRM deployments; each of those is a content-touching party outside your control. If the customer insists on their own WAF, it sits inside their network and it's their retention problem, documented in the DPA.

### 2.2 Gateway application layer

**Application logs.** The classic leak: a developer writes `log.error("failed to parse request", request)` and the whole prompt lands in the log stream. Close: the logging library used in the gateway takes structured events against a fixed schema, and the schema has no free-form payload field. Log calls that attempt to attach unknown fields fail in CI. This is enforceable at code review and by a linter, and it's the single highest-value control in the whole document.

**Error handling and echoes.** Validation errors love echoing input back ("invalid JSON at position 4021: <content>"). Close: error responses reference positions and rule IDs, never input fragments. Same rule for schema validation failures against the artifact's input schema.

**Exception reporting (Sentry and friends).** Crash reporters serialize local variables, and local variables hold the prompt. Close: no third-party crash reporting in ZRM deployments. Local exception capture with stack traces only, variable capture disabled at the SDK level, config in the signed bundle.

### 2.3 Observability

**Traces.** OpenTelemetry spans accept arbitrary attributes, and instrumented HTTP libraries happily attach request/response bodies. Close: an OTel processor at the collector that drops all attributes not on an explicit allowlist, plus SDK config that never captures bodies. The allowlist is part of the versioned telemetry schema the customer can already inspect.

**Metrics.** Prompts leak into metrics through high-cardinality labels (someone labels a counter with `user_query`). Close: metric label allowlist enforced at the collector, cardinality limits as a tripwire (a cardinality explosion is a decent smoke alarm for content-in-labels).

**stdout/stderr capture.** Container runtimes capture stdout and ship it to log drivers, journald, and `kubectl logs`. Anything printed is persisted somewhere. Close: the schema-enforced logger is the only writer to stdout; inference server verbosity pinned down (see 2.6); journald rate limits and retention configured; and the log pipeline's destination is covered by the canary sweep (section 4).

### 2.4 Queues and async paths

**Message payloads.** If invocation requests transit a queue, the queue's durability is the leak: disk-backed brokers, dead-letter queues, and retry buffers all persist payloads. Close: in ZRM, content never rides a durable queue. The queue carries a run ID and metadata; content stays in memory in the gateway process and is handed to the execution worker over a direct mTLS stream. If a run fails before dispatch, it fails; there's no dead-letter replay containing the prompt, by design.

### 2.5 Database and storage

**Run records.** Already hashes-only by schema. The hash is salted per-deployment (HMAC with a deployment key) so short or low-entropy inputs can't be recovered by dictionary attack against the hash. Worth stating because plain SHA-256 of "yes" is not privacy.

**Postgres side channels.** Slow-query logs capture bind parameters; `log_statement` can capture full statements; temp files spill sort data. Close: content never appears in a SQL statement in the first place (nothing content-shaped is ever inserted), which neutralizes all three. Verified by the canary sweep rather than by trusting the config.

**Object storage.** In normal mode, S3 holds execution logs and outputs. In ZRM, execution stdout/stderr from artifacts is the sneaky one: artifact code can print the input. Close: artifact stdout/stderr in ZRM is either discarded or passed back to the caller in the response and never written. The run record notes `logs_discarded: true`.

**Backups.** Backups faithfully preserve whatever leaked. Close: nothing above leaks, so backups hold metadata only. But treat backups as in-scope for the canary sweep, because backups are where redaction-based designs go to die.

### 2.6 Inference serving

**Request logging.** Inference servers (vLLM, SGLang, TRT-LLM) ship with request logging that includes prompts, usually on by default in debug and sometimes in info. Close: request logging disabled by flag, flags pinned in the signed bundle, and the server's log stream routed through the same schema filter. Verify against the exact server version at build time; these flags move between releases, so the build pipeline asserts the flag exists and is honored (start the server, fire a canary, grep the logs).

**Prefix and prompt caches.** vLLM-style prefix caching keeps tokenized prompt content in the KV cache to accelerate repeated prefixes. That's content, resident in GPU and sometimes CPU memory, potentially across requests from different callers. Close: in ZRM, cross-request prefix caching is disabled, or scoped per-caller and flushed at session end. This costs real throughput on repetitive workloads. It's the honest price of the mode and goes in the sales material, not under the rug.

**Response caches.** Any semantic/response cache is a content store by definition. Off in ZRM. If Redis is anywhere in the stack for other reasons, RDB snapshots and AOF persistence are disabled and the instance is memory-only.

### 2.7 GPU memory

**VRAM residence.** Prompts, KV cache, and activations live in VRAM during inference. VRAM is not zeroed on free; a subsequent process on the same GPU can read stale memory. On dedicated single-tenant deployments this is contained (there is no other tenant), but it still matters at decommissioning and for rented GPUs. Close: explicit buffer zeroing on session teardown in the inference server's allocator path where supported; on rented GPU tiers, confidential-computing mode (H100/Blackwell CC) encrypts VRAM so the host operator and successor tenants read ciphertext. On decommission, the wipe procedure includes a full-VRAM overwrite pass before the instance is released.

**CUDA core dumps.** CUDA can dump device memory on fault (`CUDA_ENABLE_COREDUMP_ON_EXCEPTION` and friends). That's a full copy of the KV cache to disk. Close: disabled by environment in the signed bundle; the env is asserted at process start and recorded in the deployment attestation.

**MIG and shared-GPU neighbors.** Not applicable on dedicated deployments (whole-GPU allocation), explicitly disallowed on rented tiers in ZRM: no fractional GPU rental, no MIG slices shared with strangers.

### 2.8 Operating system

**Core dumps.** A gateway or inference process crash dumps its heap, and the heap holds prompts. Close: core dumps disabled system-wide (ulimit 0, kernel core_pattern to /dev/null, systemd `DumpCore=no`). This is the crash-dump answer, and it's absolute in ZRM: no exceptions for debugging convenience. Debugging without dumps is the operational cost; see section 5.

**Kernel crash dumps.** kdump captures all of RAM. Close: disabled in ZRM images.

**Swap.** Anonymous memory containing prompts gets paged to disk. Close: swap disabled outright on all ZRM hosts (not "encrypted swap," just none; these are dedicated inference boxes, memory is sized for the workload). Verified: `swapon --show` empty, asserted at boot, recorded in attestation.

**Hibernation.** Suspend-to-disk writes all RAM out. Close: disabled in the image. Trivial but auditors ask.

**tmpfs.** tmpfs pages can swap; with swap disabled this closes itself, noted for completeness.

**mlock for key material and hot paths.** The gateway locks pages holding in-flight request buffers where practical. Defense in depth, not the primary control (swap-off is).

### 2.9 Humans and support tooling

**Diagnostic bundles.** "Run this script and send us the output" is how content walks out the door with the customer's help. Close: the diagnostic collector is schema-bound like the logger; it collects configs, versions, metrics, and health state, never request data. The bundle is generated locally, and the customer reviews it before anything leaves (in air-gapped tiers, nothing leaves at all).

**Operator access.** JIT, session-recorded, and in ZRM operators get no tooling that can read process memory (no unrestricted ptrace, no debugger attach without a customer-approved break-glass event that's logged and time-boxed). Separate workstream, but the ZRM contract references it.

---

## 3. The one-page control table

| # | Vector | Control | Enforcement point |
|---|--------|---------|-------------------|
| 1 | Access logs | Content-free log format | Config in signed bundle |
| 2 | Body buffering to disk | In-memory buffers, tmpfs fallback, no swap | Config + image |
| 3 | External TLS/CDN/WAF | None in front of ZRM deployments | Architecture |
| 4 | App logs | Schema-enforced logger, no payload field exists | Code + CI linter |
| 5 | Error echoes | Position/rule-ID errors, never input fragments | Code + review |
| 6 | Crash reporters | No third-party; local, variables off | SDK config in bundle |
| 7 | Trace attributes | Collector allowlist | Versioned telemetry schema |
| 8 | Metric labels | Label allowlist + cardinality tripwire | Collector config |
| 9 | Queue payloads | Content never rides durable queues | Architecture |
| 10 | Run records | Hashes only, salted (HMAC, per-deployment key) | Schema |
| 11 | Postgres side channels | No content in any SQL statement | Architecture + canary |
| 12 | Artifact stdout | Discarded or returned, never stored | Execution worker |
| 13 | Backups | Inherit clean stores; swept anyway | Canary sweep |
| 14 | Inference request logs | Disabled, asserted at build | Flag pin + boot check |
| 15 | Prefix/KV cache reuse | Off or per-caller-scoped in ZRM | Inference config |
| 16 | Response caches / Redis persistence | Off / memory-only | Config in bundle |
| 17 | VRAM residence | Zero-on-teardown; CC mode on rented GPUs; wipe on decommission | Runtime + procedure |
| 18 | CUDA core dumps | Disabled by env, asserted at start | Bundle + attestation |
| 19 | Shared GPU neighbors | Whole-GPU only in ZRM | Procurement rule |
| 20 | Process core dumps | Disabled system-wide, no exceptions | Image + attestation |
| 21 | kdump / hibernation | Disabled in image | Image |
| 22 | Swap | None, asserted at boot | Image + attestation |
| 23 | Diagnostic bundles | Schema-bound collector, customer-reviewed | Tooling + procedure |
| 24 | Operator memory access | No debugger attach without break-glass | PAM workstream |

---

## 4. Prove vs claim

The honest split. An auditor (or a hostile CISO, same energy) will sort every statement into one of three buckets.

### Provable by the customer, continuously

- **Nothing content-shaped leaves the deployment.** They own the egress firewall and can inspect every byte through their proxy. Strongest control in the whole design and it's not even ours; it's theirs.
- **The telemetry schema has no content fields.** Published, versioned, diffable. A schema change is a visible event.
- **What's running is what was audited.** Signed images, pinned digests, reproducible builds where we can get them. The customer verifies the running digest matches the published one.
- **Config posture.** Swap off, dumps off, cache flags, log formats: all in the signed bundle, all checkable on the box, all asserted at boot into a deployment attestation the customer can read.

### Provable by us, demonstrated periodically (the evidence pack)

- **Canary sweeps.** The core verification technique, and worth building well: synthetic traffic carries unique canary strings (per-store, per-week, high-entropy). A sweep job then greps *every* persistence layer for them: log stores, Postgres (including WAL segments), object storage, backups, metrics, traces, temp paths. A canary anywhere is a sev-1 and a design bug, not an ops slip. Sweep reports are timestamped, signed, and go in the audit folder. This converts "we don't log prompts" from a claim into a measured negative result, which is as close as engineering gets to proving absence.
- **Disk forensics on decommission.** Sampled volumes from retired deployments get a forensic pass for canaries and content patterns before destruction; destruction is certified.
- **Boot attestation trail.** Every deployment start emits a signed record of the ZRM-relevant config assertions (swap, dumps, cache flags, logger schema version). Auditors get the trail, not a screenshot.
- **SOC 2 control mapping.** Each row of the control table maps to a control with evidence; the canary sweep is the recurring test of the whole family.

### Claims only (and we say so out loud)

- **Runtime memory contents.** Without a TEE, "content exists only in RAM during processing and nowhere after" is an architectural argument, not a proof. Anyone with root and a debugger could read process memory during a request. The mitigations are the PAM controls and break-glass logging, and the upgrade path is confidential computing: CPU enclaves plus GPU CC mode turn this claim into a hardware-backed attestation. That's the roadmap item that moves the biggest claim into the provable column, and it's the honest answer to "what can't you prove today."
- **Rented-GPU host behavior.** On RunPod-class tiers without CC mode, the host operator's hypervisor is outside our proof boundary. We say this plainly and price the tiers accordingly; CC-mode capacity is the fix.
- **Our own staff's intent.** Process controls, JIT access, and session recording constrain and evidence behavior; they don't prove a negative about people. No vendor can, and the ones who imply otherwise are the ones to worry about.

The auditor conversation goes: here's the architecture argument (content-free by construction), here's the continuous customer-side proof (egress + schema), here's our periodic measured proof (canaries + attestations), and here's the residual trust surface with its roadmap (TEE). That structure survives hostile questioning because nothing in it overclaims.

---

## 5. Operational costs of ZRM (so nobody's surprised)

- **Support gets harder.** No dumps, no request logs, no replay from stored prompts. Debugging works from metadata, metrics, and customer-side reproduction. Offer an opt-in per-request debug flag: customer explicitly marks a request as retainable, it's flagged in the run record, retention is time-boxed (72h), and it's the only exception path that exists.
- **Throughput drops on repetitive workloads.** Killing cross-request prefix caching costs real money on prompt-heavy, template-heavy traffic. Benchmark it per customer workload and put the number in the proposal.
- **Disputes change shape.** Hash-verified re-execution replaces prompt review. Works cleanly for deterministic artifacts, gets fuzzy with sampling; pinned seeds and temperature-zero replay policies help, and the dispute SLA reflects the extra round-trip.
- **Anomaly detection loses signal.** Content-based abuse detection is off the table by definition. Detection leans on metadata patterns (rates, sizes, egress attempts, resource anomalies), which is most of it anyway.

---

## 6. Build order

1. Schema-enforced logger and the no-payload-field rule (highest value, cheapest, everything else leans on it)
2. Image hardening: swap, dumps, kdump, CUDA dumps off, boot assertions into the attestation record
3. Inference server flag pinning plus the build-time canary check
4. Collector allowlists for traces and metrics
5. Canary sweep pipeline across all stores, weekly, signed reports
6. Queue-free content path (direct gateway-to-worker streaming)
7. Salted hashing for run records
8. Debug-flag exception path with time-boxed retention
9. Decommission wipe procedure including VRAM pass
10. TEE evaluation spike (the prove-the-last-claim roadmap item)

Items 1 through 4 are days, not weeks, and they close the vectors that cause real-world breaches. The canary pipeline is the one genuinely novel build and it's also the centerpiece of the audit story, so it earns its week.

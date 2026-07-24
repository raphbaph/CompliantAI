# AgentBox Control Plane / Data Plane Architecture Design Document

## TL;DR
- **Adopt a "shared control plane, dedicated single-tenant data plane" model.** All prompt/output content, inference, execution, Postgres, and object storage stay inside the customer-side data plane; the AgentBox-operated control plane holds only cross-tenant metadata: identity/tenant registry, artifact catalog (hashes + signatures, not artifacts), billing ledger, run-record index, policy source-of-truth, model-registry pointers, fleet management, and aggregate telemetry. Loss of connectivity NEVER bricks inference.
- **Ship three connected tiers (AWS dedicated account, GPU-rental, connected on-prem) plus a fully air-gapped defense tier** where every control-plane function runs locally, billing is by annual license file with a grace period, and updates arrive on signed physical media applied by trained local operators.
- **Make the boundary verifiable, not just contractual:** customer-controlled egress allowlist, all telemetry as human-readable JSON over mTLS through a customer-inspectable proxy, a documented/versioned telemetry schema, signed fleet commands with optional customer co-approval, and an optional zero-telemetry mode.

## Key Findings

### 1. The industry has converged on "control plane in vendor, data plane in customer"
Every mature vendor studied splits along the same line: the vendor operates a multi-tenant control plane (provisioning, orchestration, metadata, billing, fleet updates) while the data — and increasingly the compute — runs in the customer's environment.
- **Databricks**: control plane (web app, job scheduling, cluster management, metadata) runs in the Databricks account; the classic compute plane runs in the customer's own AWS/Azure/GCP account. Databricks documents that "the control plane (Databricks-managed) handles orchestration and UI, but your actual data is processed and stored in YOUR cloud account. Databricks never stores your data." Secure cluster connectivity means customer VPCs have no open inbound ports — clusters dial out to the control plane over HTTPS 443 via a relay.
- **Confluent Cloud / WarpStream BYOC**: WarpStream's "zero-access" BYOC is the strongest documented boundary. Per WarpStream's security docs: "Control plane isolation. WarpStream's cloud metadata store contains only metadata (file-to-offset mappings), never payload data. Even in the event of a control plane compromise, topic contents are inaccessible to WarpStream." WarpStream documents exactly what metadata crosses (agent vCPU count and utilization, private IPs, availability zone, "a small sample of the Agent's logs" that "never contain raw data," profiling data) and provides flags to disable it (`-disableLogsCollection`, `-disableProfileForwarding`). This is the model AgentBox should emulate most closely.
- **HashiCorp Cloud Platform**: control plane = user management, product deployment, monitoring; data plane = per-org isolated VPCs. Data-plane agents (Consul/Vault/Nomad/Boundary) "connect back, and execute instructions from the control and management planes."
- **Temporal Cloud**: cell-based architecture; control plane provisions namespaces, does billing/metering, rolls out fleet updates via "deployment rings"; the data plane executes workflows. Critically, per Temporal Cloud docs: "Temporal Cloud never executes your application code. Workers run in your environment, connecting to Temporal Cloud over encrypted channels. You control access to your compute resources and secrets." Payloads can be encrypted client-side so "Temporal Cloud stores ciphertext."

The 2025-2026 best practice, articulated by Confluent's own sovereignty writing, is architectural rather than contractual: design so that the vendor "holds no identity and access management (IAM) permissions into your data plane, no network path to your storage, and no cryptographic key to your data" — such an architecture "has nothing for a legal instrument to compel."

### 2. Only metadata, hashes, usage events, health telemetry and signed attestations should cross
The requirement that prompt/output content never leaves the data plane is met by every leading BYOC vendor and is directly implementable. WarpStream and Databricks both document the boundary contents publicly; AgentBox should do the same with a versioned schema so a schema change is a visible, reviewable event.

### 3. Air-gapped delivery is a solved problem with known tooling
Replicated Embedded Cluster (based on k0s), GitLab offline installs, Chainguard/Iron Bank hardened images, and cosign signature verification form a complete pattern. Replicated ships an air-gap bundle (binary, license file, images) as a `.tgz` moved on physical media; upgrades are applied by uploading a signed release archive to a local admin console that "validates the archive against the installed license." Defense customers require Iron Bank hardened base images (DISA STIG-hardened, scanned, documented in a Container Approval Record) for IL4+ and a SIPRNet-connected enclave for IL6.

### 4. Concrete degradation and version-skew numbers exist to anchor design
Primary vendor docs give hard numbers AgentBox should mirror:
- **Temporal Server**: "We offer maintenance support of the last three minor versions after a release… We offer maintenance support of major versions for at least 12 months after a GA release," and upgrades must be sequential — "Temporal Server should be upgraded sequentially, one minor version at a time," because skipping "might cause older formats to become unrecognizable."
- **Kubernetes Version Skew Policy**: "kubelet may be up to three minor versions older than kube-apiserver," and kubelet must never be newer than the API server.
- **HashiCorp Vault** uses a grace period between license expiration and termination: "the time between license expiration and license termination, is one day for evaluation licenses (as of 1.8), and ten years for non-evaluation licenses… When license terminates (upon grace period expiry), Vault will seal itself." Existing unsealed nodes keep running until they restart.
- **Confluent Cloud JWKS caching**: "Default: 86400 (24 hours), used when max-age is not specified… a value above the maximum is capped at 604800," and "If the JWKS URI is temporarily unavailable, the system continues using the cached keys until the next successful refresh."

## Details

### Component placement table

| Component | Where it lives | Why |
|---|---|---|
| LLM inference gateway (auth, metering, routing, policy enforcement) | **Data plane** | Sees prompt/output content; must keep serving during control-plane outage |
| Sandboxed execution workers | **Data plane** | Executes customer artifacts on customer data; never in vendor env (cf. Temporal "never executes your application code") |
| LLM inference serving (self-hosted Qwen on GPUs) | **Data plane** | Processes prompt content; GPU-resident weights + activations stay local |
| Postgres (runs, artifacts, audit) | **Data plane** | Holds content-bearing records |
| Object storage (artifacts, outputs) | **Data plane** | Holds content |
| Identity/tenant registry (who the customer is, entitlements) | **Control plane**, cached in data plane | Cross-tenant; cached locally for offline auth |
| Auth policy definitions (source of truth) | **Control plane authored, data plane enforced** | Authored centrally, pushed down, enforced locally against cached copy |
| Artifact registry — **catalog** (name, version, hash, signature) | **Control plane** | Metadata only; enables fleet-wide version tracking |
| Artifact registry — **binaries** | **Data plane** | The artifacts themselves are content |
| Billing ledger (aggregated, invoiced) | **Control plane** | Cross-tenant financial record |
| Usage metering events (raw) | **Data plane buffer → control plane** | Generated locally, queued durably, reconciled |
| Run records (full, with content refs) | **Data plane** | Content-bearing |
| Run-record **index/attestation** (hash + signature, no content) | **Data plane signs → control plane stores index** | Tamper-evident proof without content |
| Model registry — **pointers/versions** | **Control plane** | Which model versions a deployment should run |
| Model registry — **weights** | **Data plane** (or air-gap media) | Large; content-adjacent; often export-controlled |
| Fleet management (config, deployments, canary orchestration) | **Control plane → signed commands to data plane** | Central operability across single-tenant fleet |
| Telemetry (health, heartbeat, aggregate usage) | **Data plane emits → control plane aggregates** | Operability; must be inspectable and minimizable |
| Operator access (JIT, session recording) | **Control plane brokered, data plane enforced** | Separate workstream; least-privilege, time-boxed |

**Recommendation on shared vs dedicated control plane:** For a 1-3 person company serving EU enterprise + defense, run **one shared multi-tenant control plane for all connected customers** (you cannot hand-operate dozens of dedicated control planes) but keep it **regionally EU-hosted** for data residency, and ship a **fully local control plane** only for the air-gapped tier. This mirrors Temporal/Confluent economics: dedicated control planes per customer do not scale for a tiny team, while a single hardened, EU-resident control plane plus per-customer dedicated data planes gives enterprises the isolation they want at a cost you can bear.

### Boundary-crossing data inventory

| Message type | Direction | Contents (schema fields) | Frequency | Customer-verifiable? |
|---|---|---|---|---|
| **Usage metering event** | DP → CP | CloudEvents envelope: `id`, `source` (deployment ID), `subject` (tenant/project), `type=inference.usage`, `time`; `data`: `model`, `tokens_in`, `tokens_out`, `request_count`, `gpu_seconds`, `artifact_hash`, `policy_id` — **no prompt/output text** | Batched ~1-5 min; queued in WAL | Yes — JSON via inspectable proxy; schema versioned |
| **Health/heartbeat** | DP → CP | `deployment_id`, `version`, `component_status[]`, `gpu_util`, `queue_depth`, `cert_expiry`, `license_expiry`, `last_policy_version`, `uptime` | ~30-60 s | Yes |
| **Audit event summary** | DP → CP | `event_id`, `event_type`, `actor_hash`, `resource_type`, `timestamp`, `outcome`, `run_id_hash` — **counts/summaries, no content** | Batched | Yes |
| **Run-record attestation** | DP → CP | `run_id`, `artifact_hash`, `model_version`, `input_hash`, `output_hash`, `policy_version`, `signature` (signed in DP) | Per run or batched | Yes — signature chain |
| **Fleet command** | CP → DP | `command_id`, `type` (config_update / deploy_artifact / model_pin / rollback), `target_version`, `maintenance_window`, `signature`, optional `requires_customer_coapproval` | On demand | Yes — signature verifiable by customer |
| **Policy/entitlement update** | CP → DP | `policy_bundle`, `version`, `signature`, `not_before`/`not_after` | On change | Yes |
| **JWKS / auth keys** | CP → DP | Public signing keys (JWKS), `kid`, cache TTL | On rotation; cached | Yes — public keys only |
| **Model registry pointer** | CP → DP | `model_id`, `version`, `digest`, `source_ref` | On change | Yes |

All DP→CP traffic is one-way outbound (like Databricks secure cluster connectivity and WarpStream); CP→DP happens over the same customer-initiated tunnel or via pull (GitOps), so the customer never opens inbound ports.

### What the customer can verify (written for a CISO)

You do not have to trust AgentBox's word about what leaves your environment — you can enforce and inspect it:

1. **You own the egress firewall.** The AgentBox data plane is deployed with a **default-deny egress policy**. The only permitted outbound destination is the single AgentBox control-plane FQDN/IP, enforced by *your* firewall (AWS Network Firewall with SNI inspection, or your on-prem NGFW). If AgentBox tried to send data anywhere else, your firewall would block and log it — the same SNI-allowlist pattern AWS documents for controlling AI-agent egress.
2. **All telemetry is human-readable JSON over TLS through a proxy you control.** Point the AgentBox agent at your own forward proxy; you can log, inspect, and diff every byte that crosses. Content is never in these messages — you can prove it by reading them.
3. **The telemetry schema is documented and versioned.** Every field that can ever cross the boundary is in a published, semver'd schema. WarpStream and Databricks both publish their boundary contents; AgentBox commits to the same.
4. **Fleet commands are signed and optionally require your co-approval.** Every command AgentBox sends your deployment is cryptographically signed; you can verify it came from AgentBox and was not tampered with (cosign-style verification). For sensitive operations (artifact deploy, model change) you can require a second signature from your own key.
5. **mTLS with customer-verifiable certificates** secures both planes; you can pin AgentBox's CA and rotate your side independently (as Temporal issues per-namespace mTLS certs).
6. **Run records are signed in your data plane.** The signing key lives in your environment; the attestation chain proves records are authentic and unaltered without any content leaving.
7. **Optional zero-telemetry mode.** For your most sensitive deployments, disable all outbound telemetry (like WarpStream's `-disableLogsCollection`/`-disableProfileForwarding` flags). You lose remote monitoring; you gain a fully closed boundary. Billing then falls back to license-based.
8. **Third-party attestation.** SOC 2 Type II covers the control plane; optionally, GPU confidential-computing attestation (NVIDIA H100 CC mode, which supports local verification for air-gapped situations) proves inference ran on genuine, unmodified hardware in a TEE.

### Per-environment specifics

| Dimension | AWS dedicated account | GPU-rental (RunPod/Lambda/Baseten) | Connected on-prem | Air-gapped on-prem |
|---|---|---|---|---|
| Data plane location | Customer-dedicated AWS account | Rented GPU host | Customer DC | Customer DC / SCIF |
| Control plane | Shared, EU-hosted | Shared, EU-hosted | Shared, EU-hosted | **Local** (bundled) |
| Connectivity | Outbound 443 to CP | Outbound 443 to CP | Outbound 443 to CP | **None** |
| Egress control | AWS Network Firewall, customer allowlist | Provider firewall + agent proxy | Customer NGFW | N/A (no egress) |
| Billing | Usage metering events | Usage metering events | Usage metering events | **Annual license file** |
| Updates | OTA (GitOps canary) | OTA (GitOps canary) | OTA (GitOps canary) | **Signed media, local operator** |
| Auth | Cached JWKS + policy | Cached JWKS + policy | Cached JWKS + policy | **Local IdP + local policy** |
| Key management | Customer KMS (BYOK) | Provider/customer KMS | Customer HSM/KMS | Local HSM |
| Model weights | Object storage pull | Object storage pull | Object storage pull | Media delivery |
| Trust anchor | mTLS + SOC 2 | mTLS + SOC 2 + optional CC attestation | mTLS + SOC 2 | Local attestation, Iron Bank images |
| Special notes | Cleanest isolation | Least physical control — verify provider; prefer CC-mode GPUs | Customer owns network | IL4/IL5/IL6; cleared local staff |

For **GPU-rental**, the physical host is least under anyone's control, so this tier benefits most from confidential-computing GPUs (encrypted VRAM + remote attestation) to prove a rogue host admin cannot read model weights or inference inputs from VRAM.

### The degradation ladder (connected deployments)

The founder's rule — connectivity loss must never brick inference, and billing is eventual-consistency — drives a staged ladder with explicit thresholds:

**Tier 0 — Fully connected (normal):** everything works; metering events flow; policy/model/artifact updates apply; fleet commands accepted.

**Tier 1 — Control plane unreachable, 0 to ~24h (transient):**
- **Works normally:** inference, sandboxed execution, local auth against cached policy + cached JWKS, local metering. This mirrors Confluent's JWKS behavior ("continues using the cached keys until the next successful refresh") and the edge-auth pattern of verifying JWTs offline against cached keys — never fail-open on authorization.
- **Degrades:** no new artifact deployments, no policy updates, no model-registry changes (stale but functional), no new fleet commands.
- **Queues:** usage metering events accumulate in a durable local write-ahead log; audit summaries and attestations buffer locally.

**Tier 2 — Extended outage, ~24h to 7 days:**
- Inference/execution still fully operational.
- **JWKS cache**: recommend a **7-day maximum cached-key validity** (matching Confluent's 604800 s ceiling and typical OIDC signing-key rotation of ~7 days). New logins requiring an unknown `kid` fail; existing sessions and cached-key validation continue.
- **Cached credential/entitlement expiry**: recommend a **72-hour** cached tenant-entitlement TTL, after which the deployment enters read-through-degraded (existing entitlements honored, no upgrades).
- WAL continues buffering; alert at ~70% of allocated durable buffer.

**Tier 3 — Prolonged outage, 7 to 30 days:**
- Inference/execution continue — **this is the non-negotiable line; do not gate inference on license/connectivity within the contracted term.**
- **License grace period**: adopt the HashiCorp model — a grace period between license *expiration* and *termination*. Recommend a **30-day grace period** for connected deployments (a duration widely used by peers such as NetScaler and Red Hat), during which everything runs and only a warning is surfaced.
- If the local metering buffer approaches capacity, roll over to compacted aggregate counters (preserve billable totals even if per-event detail is trimmed) rather than dropping billing or blocking inference.

**Tier 4 — Reconnection:**
- Buffered metering events replay to the control plane; the billing ledger reconciles using idempotent event IDs (CloudEvents `id` + `source` dedup, per OpenMeter best practice) so replays never double-bill.
- Pending fleet commands are re-offered; cert/license renewals apply; policy/model registry re-sync.

**Certificate expiry during outage:** issue data-plane certs with lifetimes ≥ the license grace period and auto-renew well ahead; if mTLS certs would expire mid-outage, fall back to a longer-lived bootstrap cert so the tunnel can re-establish on reconnection rather than hard-failing.

### Update delivery

**Path A — OTA for connected deployments (GitOps fleet model):**
- Model on Chick-fil-A's edge fleet and Rancher Fleet / ArgoCD ApplicationSets. Per Chick-fil-A's engineering team, "Chick-fil-A runs a fleet of Edge Kubernetes clusters in each of our ~2,800 restaurants to enable highly available, business critical workloads to run without internet dependency" — each store runs K3s, with one Git repo per restaurant and an in-cluster agent ("Vessel") that reconciles signed manifests. Their "golden image" convergence model applies directly: "not all clusters will be the same at any given time, but will all end up the same eventually (over days, weeks, or possibly months)."
- **Canary across the fleet:** roll a new version to a small ring first (internal/test tenants), watch health telemetry and error rates, then progressively expand — Temporal's "deployment rings." Use Argo Rollouts/Flagger-style automated analysis with automatic rollback on metric regression.
- **Maintenance windows per contract:** each deployment carries a `maintenance_window`; the control plane only applies non-emergency updates within it.
- **Customer approval gates:** updates can require explicit customer approval (manual sync) before applying, satisfying change-control requirements. Offline resilience is inherent — if a deployment loses connectivity mid-window, its local reconciler keeps the current version healthy (Flux/Fleet behavior).

**Path B — Offline updates for air-gapped:**
- Signed update **bundle** (application images + k0s/infra + license, à la Replicated Embedded Cluster air-gap `.tgz`) delivered on physical media with malware scanning at the boundary.
- Local trained operator uploads the bundle to the local admin console, which **validates the archive signature against the installed license** before applying, or runs a headless `upgrade` command.
- **Signature verification** with cosign against a pinned public key (no transparency-log/network dependency — set `IgnoreTlog` for offline) before anything is applied.
- **Rollback**: keep the prior version's images/manifests on the appliance; rollback = re-apply previous signed bundle. Maintain local snapshots (Velero-style) before upgrade.
- **Version skew across the fleet**: adopt an explicit supported-skew window. Recommend the control plane supports **the last 3 data-plane minor versions simultaneously** (matching Temporal's "last three minor versions" and Kubernetes' 3-minor kubelet skew), and require **sequential minor upgrades with no skipping** (Temporal's rule), because skipping risks unrecognizable data formats. Air-gapped sites may lag by months, so the CP must remain backward-compatible across that whole window.

### Security and trust specifics
- **mTLS between planes** with per-deployment certificates the customer can verify and pin; customer rotates its side independently (Temporal per-namespace mTLS model).
- **Signed fleet commands**: every CP→DP command is signed; the data plane verifies the AgentBox signature before executing, and sensitive command types can require **customer co-approval** (second signature). This is the key differentiator: the customer can cryptographically prove no command ran that AgentBox didn't sign, and can gate the dangerous ones.
- **Per-customer encryption keys / BYOK**: customer-managed keys in the customer KMS/HSM; AgentBox holds no key to customer data (Confluent sovereignty model), giving the customer a revocation switch no contract clause can match.
- **Run-record signing / attestation chain in the data plane**: the signing key is generated and held in the data plane (ideally in an HSM or the confidential-computing TEE). Each run record is hashed and signed locally; only the signed hash + metadata index crosses to the control plane. The chain: run → `input_hash`/`output_hash` + `artifact_hash` + `policy_version` → signed by DP key → index stored in CP. Anyone can later verify a run's integrity against the CP index without any content ever having left the data plane.
- **Operator access (brief — separate workstream):** JIT, time-boxed, least-privilege access brokered through the control plane with session recording; for air-gapped/IL6, all operator access is local and staffed by cleared personnel.

### Air-gapped tier: what the customer must staff locally
Because no AgentBox operator can reach the environment, the customer must staff and train local operators to: apply signed update bundles from media and verify signatures; manage the local admin console; install/rotate the local license file (with expiry) and per-customer keys; operate the local model registry and load new weights from media; run local backup/restore; monitor via the local dashboard; and hold appropriate clearances (US citizens with SECRET clearance for IL6 on a SIPRNet enclave — IL6 requires "a dedicated cloud enclave connected to the Secret Internet Protocol Router Network (SIPRNet)"). Billing is a flat annual license rather than usage metering, since no usage events can leave.

## Recommendations

**Stage 1 — Build the connected core first (weeks 1-8):**
1. Implement the DP/CP split with WarpStream-grade metadata-only boundary. Publish v1 of the versioned telemetry schema.
2. Ship the AWS dedicated-account tier first (cleanest isolation, largest EU-enterprise market). Enforce default-deny egress with a documented single-FQDN allowlist.
3. Build the durable WAL metering buffer + idempotent reconciliation before you need it.

**Stage 2 — Make the boundary verifiable (weeks 6-12):**
4. Ship the customer-inspectable proxy path, signed fleet commands, and mTLS with pinnable certs.
5. Get SOC 2 Type II scoped to the control plane — table-stakes for EU enterprise.
6. Implement the degradation ladder with the specific thresholds above; test with chaos (kill CP connectivity for 7+ days in staging).

**Stage 3 — Fleet operability (weeks 10-16):**
7. Adopt GitOps fleet management (Rancher Fleet or ArgoCD ApplicationSets) with ring-based canary, per-contract maintenance windows, and customer approval gates.
8. Add the GPU-rental tier; prefer confidential-computing GPUs and expose attestation to customers.

**Stage 4 — Defense/air-gapped (weeks 16-28):**
9. Build the air-gapped tier on Replicated Embedded Cluster with Iron Bank hardened base images and cosign offline verification.
10. Implement local control-plane functions, offline license with 30-day grace + termination, and signed-media update procedures with rollback.
11. Pursue an IL4 → IL5 → IL6 pathway as customer demand justifies; each step adds cleared-personnel and facility requirements.

**Benchmarks that would change these recommendations:**
- If you win a defense customer before EU enterprise, invert Stages 1 and 4.
- If any single customer demands a dedicated control plane, price it as a premium tier — do not make it the default (it breaks the 1-3 person operating model).
- If telemetry volume or cardinality threatens control-plane cost (Chick-fil-A's cardinality warning), tighten aggregation granularity before adding infrastructure.
- If confidential-computing GPU availability at RunPod/Lambda is insufficient, treat the GPU-rental tier as lower-assurance and document that explicitly to customers.

## Caveats
- **Vendor-documented boundaries are self-reported.** WarpStream's and Databricks' "only metadata crosses" claims are backed by docs and SOC 2, not independent line-by-line audit; AgentBox's verifiability features (customer egress control, inspectable proxy) are what convert this from trust to verification — prioritize them.
- **Version-skew and grace-period numbers are recommendations anchored to peer vendors, not laws.** The 3-minor-version window, 30-day grace, 7-day JWKS ceiling, and 72-hour entitlement TTL are defensible defaults drawn from Temporal, Kubernetes, HashiCorp, Confluent, NetScaler and Red Hat, but should be tuned to your SLA and contract terms.
- **Confidential computing adds overhead and hardware constraints.** H100 CC mode encrypts CPU↔GPU traffic, which adds latency, and CC-capable GPUs are not universally available at rental providers; treat it as a premium/defense feature, not a default.
- **IL5/IL6 are heavy.** They require US-citizen cleared staff, dedicated facilities, and SIPRNet connectivity — a major organizational commitment for a 1-3 person company; partner (e.g., a Platform One / Game Warden-style ATO accelerator) rather than building this alone.
- **Air-gapped billing loses usage fidelity.** Annual licensing means you cannot true-up on actual consumption; price the license conservatively.
- **Secondary vs primary sources:** several cited comparison articles (2026-dated blogs on ArgoCD vs Flux, GitOps patterns) are secondary commentary; the primary vendor docs (Replicated, Temporal, Databricks, WarpStream, Kubernetes, HashiCorp, NVIDIA, Confluent, and the DISA Cloud Computing SRG) are the authoritative basis for this design.
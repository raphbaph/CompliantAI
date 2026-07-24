# AgentBox Gateway — Project Plan (v4)

Compliant inference infrastructure for enterprises. Draft for review, July 2026.

---

## What this project is now

A policy-enforcing LLM inference gateway, delivered as a dedicated single-tenant deployment that AgentBox operates on the customer's preferred infrastructure: a dedicated AWS account, rented GPU capacity, connected on-prem, or fully air-gapped on-prem.

The product does one job: **ensure compliant use of inference endpoints.** Every request to a model passes through the gateway, which answers four questions before any tokens are generated:

1. Who is calling, and on whose authority?
2. Is this request permitted for this caller, this data, this model, right now?
3. Which allowed model should serve it?
4. What must be recorded to prove all of the above later?

Requests that fail policy get blocked or flagged for review, with a signed record of the decision. Requests that pass get routed, metered, and attested. That's the whole surface. Minimal frontend: an admin console for policy and audit, and an OpenAI-compatible API for everything else.

## What got removed, and why

The previous scope (PRD v1.0) described a two-sided marketplace: creators publishing artifacts, callers invoking them, reputation scores, disputes, per-invocation creator pricing, a 10% platform fee. All of that is out.

Removed entirely:

- Creator and artifact reputation (success rates, invocation counts as trust signals)
- The artifact registry, publish pipeline, and certification flow
- Marketplace search and discovery
- Sandboxed execution of third-party artifacts
- Marketplace-style disputes and payout holds
- Creator payouts, Stripe Connect, the per-hop platform fee

The reasoning: the buyer with money and urgency is a CISO or platform lead at one company who needs their teams to use LLMs without violating GDPR, the EU AI Act, sector rules, or internal data policy. That buyer doesn't need a marketplace. They need a control point. The marketplace depended on two-sided liquidity that doesn't exist yet; the gateway depends on one signed contract.

What survives from the original design, because it was never really about the marketplace:

- **Delegated authority with scope narrowing.** The capability chain concept, repurposed. When an agent calls inference on behalf of a user, the request carries who authorized it, what was delegated, and a budget. Scopes narrow through delegation, never widen. Budget is a permission. Every request traces to a human or org originator; orphaned requests are rejected.
- **Signed run records.** Hashes, metadata, policy version, model version, decision outcome. The audit backbone.
- **Append-only ledger** for metering.
- **Content-addressed configuration.** Policies, model configs, and routing rules are versioned by hash. You can always prove which policy version decided a given request.

## Core capabilities

### 1. Identity and access

- SSO via SAML/OIDC against the customer's IdP (Okta, Entra, Ping). SCIM for provisioning and, more importantly, deprovisioning: when the IdP disables a user, gateway access dies within minutes.
- Workload identity for agents and services (SPIFFE-style, or cloud-native federation for AWS-hosted callers). No long-lived API keys in environment variables as the blessed path.
- Delegation tokens for agent-on-behalf-of-user calls, built on OAuth 2.0 Token Exchange (RFC 8693) semantics rather than a proprietary format. Scope narrowing and budget caps enforced at the gateway.

### 2. Policy engine

- Customer-authored policies in a standard language (Cedar or OPA/Rego; decide in week 2 after a spike). The customer's security team writes and owns the rules; we enforce them.
- Policy dimensions: caller identity and group, data classification of the request, target model, destination region, time window, spend budget, request rate.
- Data classification drives routing: "restricted never leaves on-prem," "PII only to EU-pinned models," "legal department only to the zero-retention deployment." Classification comes from caller-declared labels in v1; content inspection (DLP) is deferred and listed as such.
- Decisions: allow, block, or flag. Flagged requests execute or hold per policy, and always generate a review event for the customer's queue.

### 3. Model routing

- Allowlist-first: only platform-deployed, hash-pinned model versions are routable. Model weights are content-addressed; the run record proves which exact weights served the request.
- Within the allowed set, routing picks by policy then preference: region pinning as a hard constraint, then cost/latency/capability ranking.
- Model config changes produce a new pinned version. Nothing changes silently.

### 4. Metering and billing

- Every request emits a metering event: model, tokens in/out, GPU seconds, caller, policy version. No content.
- Events queue in a durable local write-ahead log and reconcile to the control plane with idempotent IDs. Eventual consistency by design: connectivity loss never bricks inference.
- Internal chargeback is a first-class feature: per-team, per-project, per-agent cost allocation, exportable to the customer's finance tooling.

### 5. Audit and attestation

- Signed run records per request: input hash, output hash, caller, originator, policy version, decision, model version, timestamps. Salted hashes (per-deployment HMAC) so low-entropy inputs can't be dictionary-recovered.
- Structured audit export to the customer's SIEM (Splunk, Sentinel, Datadog) in a documented, versioned schema.
- Policy decisions are replayable: given the run record and the pinned policy version, an auditor can re-derive why a request was allowed or blocked.

### 6. Zero-retention mode

- Per-deployment mode: prompt and output content never persist. The full design exists as a separate spec (24 leak vectors, controls, canary sweep verification, prove-vs-claim split). Headline commitments: content-free-by-construction logging schema, swap and core dumps disabled and attested at boot, no cross-request prefix caching, weekly canary sweeps with signed reports.
- Sold as the default for legal, defense, and health verticals.

### 7. Deployment tiers and the plane split

- Shared EU-hosted control plane, dedicated per-customer data planes. Only metadata crosses the boundary: metering events, health telemetry, audit summaries, signed attestation indexes. Prompt and output content never leaves the data plane, and the customer can verify this because they own the egress firewall and can inspect all telemetry through their own proxy against a published, versioned schema.
- Four tiers: dedicated AWS account, GPU rental (confidential-computing GPUs preferred), connected on-prem, air-gapped on-prem. Air-gapped runs a fully local control plane, annual license file with a 30-day grace period, updates via signed bundles on physical media applied by trained local operators.
- Degradation ladder for connected tiers: inference and policy enforcement continue on cached state through any outage. Cached entitlements: 72h TTL. Cached JWKS: 7-day ceiling. License grace: 30 days. Metering WAL buffers throughout and replays on reconnect. The non-negotiable line: no connectivity state ever stops inference within the contracted term.

### 8. Fleet and updates

- OTA for connected tiers: GitOps-style, ring-based canary rollout, per-contract maintenance windows, optional customer approval gates. All fleet commands signed; sensitive commands can require customer co-approval.
- Air-gapped: signed update bundles, cosign verification against a pinned key (offline mode), local operator procedures, one-version rollback retained on the appliance.
- Control plane supports the last 3 data-plane minor versions; upgrades are sequential, no skipping.

## Architecture

Six components per deployment, one shared service:

| Component | Where | Notes |
|---|---|---|
| Inference gateway | Data plane | Auth, policy, routing, metering, flagging. The product. |
| Inference serving | Data plane | Self-hosted open-weight models, hash-pinned, GPU-resident |
| Policy engine | Data plane | Evaluates customer-authored policies locally, offline-capable |
| Postgres | Data plane | Run records, policy versions, local config. Daily backups. |
| Object storage | Data plane | Model weights, audit archives. Versioning on. |
| Local admin console | Data plane | Policy management, audit review, flag queue. Minimal UI. |
| Control plane | AgentBox, EU-hosted | Tenant registry, billing ledger, fleet management, telemetry aggregation. Fully local in air-gapped tier. |

## Data model

Seven entities:

| Entity | Stores |
|---|---|
| Principal | User or workload identity, IdP linkage, group membership |
| DelegationToken | Originator, delegate, scopes, budget, TTL, chain reference |
| PolicyVersion | Content-hashed policy bundle, author, effective window |
| ModelVersion | Weights digest, config, region availability, status |
| Run | Signed record: hashes, caller, originator, policy version, model version, decision, tokens, duration |
| MeterEvent | Append-only usage: model, tokens, GPU seconds, cost allocation tags |
| FlagEvent | Flagged request reference, policy rule hit, review status, reviewer, outcome |

## API surface

| Endpoint | Purpose |
|---|---|
| POST /v1/chat/completions | OpenAI-compatible inference. Also /v1/embeddings. Existing SDKs work unchanged. |
| GET /v1/models | Models this caller may use under current policy |
| POST /v1/policies | Upload a policy bundle (admin, versioned by hash) |
| GET /v1/runs/:id | Signed run record |
| GET /v1/flags | Review queue for flagged requests (admin) |
| GET /v1/usage | Metering export, cost allocation |

OpenAI compatibility is deliberate: adoption cost inside the customer is one base-URL change.

## Compliance posture

- GDPR: AgentBox is a processor for connected tiers. DPA with subprocessor list (AWS, GPU providers), region pinning as a contractual commitment, zero-retention mode as the technical answer to data minimization.
- EU AI Act: the gateway's run records and policy replay directly serve logging and transparency duties for deployers. Positioned as a compliance asset, not overhead.
- Sector: DORA incident-reporting support for financial customers (run records plus IR runbook), professional secrecy posture for legal via zero-retention.
- Certifications: SOC 2 Type II evidence collection starts at project start, scoped to the control plane. The canary sweep reports and boot attestations feed the evidence pack.

## Business model

Per-deployment pricing, no usage-based marketplace mechanics:

- Setup: one-time deployment fee (anchor: €35k, tiered by environment; air-gapped higher)
- Platform: monthly subscription per deployment (anchor: €9k MRR) covering operations, updates, support SLA
- Usage: metered inference passthrough with margin on connected tiers; folded into the annual license for air-gapped
- Air-gapped: annual license file, priced to include the usage we can't meter

One buyer, one contract, revenue from day one of each deployment. No liquidity problem.

## Build sequence

**Weeks 1-2: Decisions and skeleton.** Cedar vs OPA spike. OpenAI-compatible gateway skeleton with auth passthrough. Telemetry schema v1 published.

**Weeks 3-8: Connected core.** Policy engine integration, model routing with hash pinning, metering WAL with idempotent reconciliation, signed run records, SSO/OIDC, the AWS dedicated tier end to end. Default-deny egress with documented allowlist.

**Weeks 9-12: Verifiable boundary.** Customer-inspectable proxy path, signed fleet commands, mTLS with pinnable certs, degradation ladder implemented and chaos-tested (7-day CP blackout in staging). SIEM export. First customer deployment targets the end of this phase.

**Weeks 13-16: Zero-retention mode.** Schema-enforced logger, image hardening with boot attestation, inference flag pinning, canary sweep pipeline. ZRM ships as a certified mode.

**Weeks 17-28: Fleet and air-gap.** GitOps fleet management with rings and approval gates. GPU-rental tier with CC-mode preference. Air-gapped tier: local control plane, license files, signed-media updates, operator runbooks and training material.

## Deferred

| Feature | Trigger |
|---|---|
| Marketplace and artifact execution (the original AgentBox) | Two customers independently ask to share capabilities across org boundaries |
| Content-inspection DLP for classification | Customer can't or won't label at the caller |
| Confidential computing attestation surfaced to customers | First defense or legal customer asks to close the runtime-memory trust gap |
| Guardrail models (output filtering) | Customer policy requires content-level controls beyond routing |
| Dedicated per-customer control plane | A customer pays for it as a premium tier |
| IL5/IL6 pathway | Signed defense customer; pursue via a Platform One-style partner |

## Risks

| Severity | Risk | Mitigation |
|---|---|---|
| High | Crowded gateway field (LiteLLM, Portkey, Kong, Cloudflare) | Wedge: compliance depth, customer-verifiable boundary, air-gap tier. None of the incumbents lead there. |
| High | Ops load of single-tenant fleet at 1-3 people | GitOps from day one; kill metric stays at 20 engineer-days per deployment |
| Medium | Caller-declared classification is gamed or lazy | Audit sampling per contract; DLP on the deferred list with a named trigger |
| Medium | SOC 2 timeline gates enterprise deals | Start evidence collection at week 1, not at first request |
| Low | Model licensing/provenance challenge | Hash-pinned weights, license review per model, AI-BOM per deployment |

## Success metrics

- 2 paid deployments live by week 16, 4 by week 28
- One air-gapped or ZRM deployment signed by week 28 (validates the differentiator)
- Zero inference downtime attributable to control-plane connectivity, ever
- Canary sweep: zero content hits across all stores, every week, from ZRM launch onward
- Deployment cost: under 20 engineer-days each, trending down

## Assumptions

- The buyer is a CISO or platform engineering lead; the users are their internal agent and application teams.
- Open-weight models served in-deployment are acceptable to the target verticals; frontier-API routing is out of scope (it breaks the sovereignty story).
- The team is 1-3 people; every architecture choice bends toward operability at that size.
- The marketplace idea is parked, not dead. The gateway builds the trust primitives (identity, delegation, attestation, policy) that a marketplace would need anyway. If A2A commerce matures, the gateway fleet is the distribution.

## Open items for review

1. Cedar vs OPA: spike scheduled, but if you have a prior, say so now.
2. Naming: "AgentBox" implied an execution sandbox. The product is now a gateway. Rename before the first customer conversation or live with it forever.
3. The €35k / €9k anchors: confirm against what din.org conversations will actually bear.
4. Frontier-API routing (Claude, GPT via the gateway with policy): excluded above to protect the sovereignty story, but it's the most-requested gateway feature in the broader market. Deliberate exclusion or v2?

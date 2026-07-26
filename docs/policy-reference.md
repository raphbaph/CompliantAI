# Policy Reference (V1)

This document describes the typed, local, default-deny inference authorization policy used by the gateway.

## Product claim boundary

The policy engine enforces **customer-authored allow/deny rules** for authenticated principals, groups, endpoints, and models. It does **not** decide whether a customer use is lawful or “EU AI Act compliant.” Compliance applicability remains the customer’s responsibility; the gateway supplies technical controls and reproducible decision evidence.

## Evaluation model

1. Authentication has already succeeded and produced a principal ID and effective groups.
2. The gateway builds a content-free `Request` with principal ID, groups, endpoint identifier, and requested model.
3. The policy engine evaluates an immutable in-memory document loaded at process start.
4. **Default deny.**
5. Every matching rule is collected.
6. If any matching rule has effect `deny`, the decision is **deny** (`explicit_deny`).
7. Else if any matching rule has effect `allow`, the decision is **allow** (`policy_allowed`).
8. Else the decision is **deny** (`no_matching_allow`).

There is **no hot reload** in V1. Changing policy requires restarting the gateway process with a new document.

## Document shape

```yaml
version: "2026-07-26.1"
rules:
  - id: allow-legal-chat
    effect: allow
    principals:
      - "00000000-0000-4000-8000-000000000001"
    groups:
      - legal-reviewers
    endpoints:
      - chat.completions
    models:
      - local-legal
  - id: deny-blocked-model
    effect: deny
    groups:
      - contractors
    endpoints:
      - chat.completions
    models:
      - local-legal
```

### Fields

| Field | Required | Notes |
| --- | --- | --- |
| `version` | yes | Explicit customer/policy version string (bounded identifier). |
| `rules[].id` | yes | Unique rule identifier; used in decision context only. |
| `rules[].effect` | yes | `allow` or `deny`. |
| `rules[].principals` | one of principals/groups | Lowercase UUID strings. |
| `rules[].groups` | one of principals/groups | OIDC group identifiers already validated at auth time. |
| `rules[].endpoints` | yes | Exact endpoint identifiers (see below). |
| `rules[].models` | yes | Exact public model names. |

A rule matches only when:

- endpoint is listed, and
- model is listed, and
- identity matches:
  - principal-only rule: principal ID is listed
  - group-only rule: at least one request group intersects
  - principal+group rule: **both** principal and group conditions match

Selectors are exact string matches. Wildcards are intentionally unsupported in V1.

## Endpoint identifiers

V1 uses stable service identifiers rather than raw HTTP paths:

| Identifier | API |
| --- | --- |
| `chat.completions` | `POST /v1/chat/completions` |
| `models.list` | `GET /v1/models` |

## Decision output

Each evaluation returns:

- `effect`: `allow` or `deny`
- `reason_codes`: one stable code from the closed set below
- `policy_version`: document version string
- `policy_digest`: SHA-256 hex digest of the canonical normalized document
- `context`: principal ID, groups, endpoint, model, and matched rule IDs

### Caller request contract

`Evaluate` accepts only content-free, already-normalized identity inputs:

- `principal_id`: lowercase UUID
- `groups`: **non-nil** slice, duplicate-free, **strictly ascending** sorted (empty is allowed)
- `endpoint` / `model`: exact identifiers matching the bounded patterns above

Invalid request shape fails closed as deny (`no_matching_allow`) without echoing rejected values. Authentication is responsible for presenting groups in this canonical form.

### Reason codes

| Code | Meaning |
| --- | --- |
| `policy_allowed` | At least one allow matched and no deny matched. |
| `no_matching_allow` | No allow matched (default deny), including unknown endpoint/model/identity combinations. |
| `explicit_deny` | At least one deny rule matched (deny precedence). |

Reason codes are intentionally coarse and content-free. They never include request bodies, claim values, or free-form explanations.

## Policy digest

On engine construction the document is normalized:

- reject invalid identifiers and duplicate selectors/rule IDs
- sort selectors and rules canonically
- freeze the result in memory

The digest is `SHA-256` over the canonical JSON encoding of that normalized document. Audit events store this digest as `policy_version_hash` evidence.

## Operational constraints

- Load policy at startup only.
- Do not accept caller-supplied policy fragments.
- Do not log request content while evaluating policy.
- Prefer explicit deny rules for sensitive model/endpoint combinations rather than relying solely on omission.
- Keep rule IDs stable so matched-rule evidence remains comparable across deploys.

## Testing expectations

- Unknown principal/group/endpoint/model denies.
- Explicit grants allow only their exact scope.
- Conflicting allow+deny resolves to deny.
- Decision context is sufficient to reproduce the decision without content.
- Engine construction fails closed on invalid documents.

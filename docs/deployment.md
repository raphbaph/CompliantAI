# Deployment guide (V1 single-host)

This document describes the single-tenant Docker Compose deployment for the Compliant Inference Gateway demo on a customer-controlled Linux host.

## Scope and claims

- The gateway runs on customer infrastructure with **no vendor control plane**.
- Zero-retention applies to the **gateway deployment** (see `docs/data-inventory.md`). Caller devices, IdP logs, and the inference server remain customer-controlled systems.
- Preflight is **fail-closed** on mandatory ZRM controls. There is no “ignore all” flag.

## Architecture (single host)

| Component | Image / binary | Network exposure |
|---|---|---|
| PostgreSQL 17 + pgaudit | `deploy/postgres.Dockerfile` | `127.0.0.1:55432` only |
| Gateway | `deploy/gateway.Dockerfile` (distroless non-root) | `127.0.0.1:8443` only |
| Inference backend | Customer-operated OpenAI-compatible server | Typically loopback or private LAN |

## Container security controls

Gateway container:

- Non-root user `65532` (distroless `nonroot`)
- Read-only root filesystem
- `tmpfs` on `/tmp` (bounded)
- `cap_drop: [ALL]`
- `no-new-privileges:true`
- `ulimits.core: 0`
- Secrets from Docker secrets / bind mounts (never baked into the image)
- Health check uses `/gateway --version` (build metadata only)
- JSON-file logs size-bounded; log content must remain typed metadata only

PostgreSQL container:

- Loopback port publish only
- `no-new-privileges`
- Dropped high-risk capabilities
- `ulimits.core: 0`
- Bounded JSON-file logging

## Secrets and files

Set these environment variables to **file paths** (mode `400` or `600`, not symlinks):

| Variable | Purpose |
|---|---|
| `POSTGRES_BOOTSTRAP_PASSWORD_FILE` | Bootstrap DB password |
| `GATEWAY_RUNTIME_PASSWORD_FILE` | `gateway_runtime` role password |
| `AUDIT_READER_PASSWORD_FILE` | `audit_reader` role password |
| `SECURITY_ADMIN_PASSWORD_FILE` | `security_admin` role password |
| `COMPLIANTAI_TLS_KEY_FILE` | TLS private key |
| `COMPLIANTAI_TLS_CERT_FILE` | TLS certificate |
| `COMPLIANTAI_CONTENT_HMAC_KEY_FILE` | 32-byte content HMAC key |
| `COMPLIANTAI_CHECKPOINT_SIGNING_KEY_FILE` | Ed25519 checkpoint signing key |
| `COMPLIANTAI_CONFIG_FILE` | Gateway YAML config |

Generate example keys (demo only):

```bash
mkdir -p .hermes/docker-secrets && chmod 700 .hermes/docker-secrets
openssl rand -base64 24 > .hermes/docker-secrets/postgres_bootstrap_password
openssl rand -base64 24 > .hermes/docker-secrets/gateway_runtime_password
openssl rand -base64 24 > .hermes/docker-secrets/audit_reader_password
openssl rand -base64 24 > .hermes/docker-secrets/security_admin_password
openssl rand 32 > .hermes/docker-secrets/content-hmac-key
openssl genpkey -algorithm Ed25519 -out .hermes/docker-secrets/checkpoint-signing-key
openssl req -x509 -newkey rsa:2048 -nodes -keyout .hermes/docker-secrets/tls-key.pem \
  -out .hermes/docker-secrets/tls-cert.pem -days 30 -subj "/CN=localhost"
chmod 600 .hermes/docker-secrets/*
```

## Bring-up (Linux host)

```bash
export POSTGRES_BOOTSTRAP_PASSWORD_FILE=$PWD/.hermes/docker-secrets/postgres_bootstrap_password
export GATEWAY_RUNTIME_PASSWORD_FILE=$PWD/.hermes/docker-secrets/gateway_runtime_password
export AUDIT_READER_PASSWORD_FILE=$PWD/.hermes/docker-secrets/audit_reader_password
export SECURITY_ADMIN_PASSWORD_FILE=$PWD/.hermes/docker-secrets/security_admin_password
export COMPLIANTAI_TLS_KEY_FILE=$PWD/.hermes/docker-secrets/tls-key.pem
export COMPLIANTAI_TLS_CERT_FILE=$PWD/.hermes/docker-secrets/tls-cert.pem
export COMPLIANTAI_CONTENT_HMAC_KEY_FILE=$PWD/.hermes/docker-secrets/content-hmac-key
export COMPLIANTAI_CHECKPOINT_SIGNING_KEY_FILE=$PWD/.hermes/docker-secrets/checkpoint-signing-key
export COMPLIANTAI_CONFIG_FILE=$PWD/configs/example.yaml

# Fail-closed host/file checks (Linux required for full ZRM host controls)
./deploy/scripts/zrm-preflight.sh

# This host uses the standalone docker-compose binary when the plugin is unavailable.
docker-compose -f deploy/compose.yaml build
docker-compose -f deploy/compose.yaml up -d

# Gateway is behind Compose profile "gateway" until full process bootstrap is wired.
# Build/inspect the hardened image any time:
docker-compose -f deploy/compose.yaml build gateway
docker run --rm --read-only --cap-drop=ALL --security-opt no-new-privileges:true \
  --user 65532:65532 "$(docker-compose -f deploy/compose.yaml config | awk '/image:.*gateway/{print $2; exit}')" --version

# When runtime bootstrap is ready:
# docker-compose -f deploy/compose.yaml --profile gateway up -d

# Re-run preflight to inspect running container security options
./deploy/scripts/zrm-preflight.sh
```

## Preflight checks

`deploy/scripts/zrm-preflight.sh` verifies:

1. Every Compose port publish is `127.0.0.1:` (rejects `0.0.0.0` and bare binds)
2. `read_only`, `cap_drop: ALL`, `no-new-privileges`
3. Secret/config/TLS file presence and modes (`400`/`600`); config DSN not external
4. System clock sanity
5. Optional backend reachability when `COMPLIANTAI_BACKEND_BASE_URL` is set
6. On Linux: swap disabled, core_pattern discards dumps (`|/bin/false`), swap mounts absent, temp mounts enumerated
7. When containers are running: read-only root (gateway), non-root user, CapDrop ALL, no-new-privileges, core ulimit

Any mandatory failure exits non-zero. There is no ignore-all flag.

## Verification commands

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...
docker-compose -f deploy/compose.yaml build
docker inspect compliantai-gateway --format '{{.HostConfig.ReadonlyRootfs}} {{.Config.User}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}}'
go test ./tests/integration ./tests/canary -v
```

## Operational notes

- Gateway process bootstrap (live TLS serve + DB/OIDC wiring in `cmd/gateway`) continues to land with demo packaging; the **image and Compose security posture** are enforced now.
- Do not publish PostgreSQL or the gateway on `0.0.0.0`.
- Inference-server logs and crash dumps on the host remain customer controls outside the gateway container.

## Related documents

- [Data inventory / ZRM](data-inventory.md)
- [Evidence pack](evidence-pack.md)
- [Threat model](threat-model.md)
- [Policy reference](policy-reference.md)

#!/usr/bin/env bash
# zrm-preflight.sh — fail-closed host and container preflight for V1 single-host deploy.
# No "ignore all" flag. Skips are only for inapplicable probes and are labeled SKIP.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-${ROOT_DIR}/deploy/compose.yaml}"
FAILED=0
WARNED=0

log() { printf '%s\n' "$*"; }
pass() { log "PASS  $*"; }
fail() { log "FAIL  $*"; FAILED=$((FAILED + 1)); }
warn() { log "WARN  $*"; WARNED=$((WARNED + 1)); }
skip() { log "SKIP  $*"; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required command not found: $1"
    return 1
  fi
  return 0
}

check_linux_host() {
  local os
  os="$(uname -s)"
  if [[ "${os}" != "Linux" ]]; then
    fail "host OS is ${os}; ZRM host controls require Linux for the production demo target"
    return 1
  fi
  pass "host OS is Linux"
  return 0
}

check_swap_disabled() {
  if [[ ! -r /proc/swaps ]]; then
    fail "cannot read /proc/swaps"
    return
  fi
  local lines
  lines="$(wc -l < /proc/swaps | tr -d ' ')"
  if [[ "${lines}" -gt 1 ]]; then
    fail "swap appears enabled (/proc/swaps has ${lines} lines including header)"
    return
  fi
  pass "swap disabled"
}

check_core_dump_posture() {
  if [[ ! -r /proc/sys/kernel/core_pattern ]]; then
    fail "cannot read /proc/sys/kernel/core_pattern"
    return
  fi
  local pattern
  pattern="$(tr -d '\n' < /proc/sys/kernel/core_pattern)"
  # Fail closed unless dumps are explicitly discarded.
  case "${pattern}" in
    "|/bin/false"|"|/bin/true"|"")
      pass "core_pattern discards dumps: ${pattern:-<empty>}"
      ;;
    *)
      fail "core_pattern does not discard dumps (got '${pattern}'); set to |/bin/false for ZRM"
      ;;
  esac
}

check_secret_file() {
  local label="$1"
  local path="$2"
  if [[ -z "${path}" ]]; then
    fail "${label} path is empty"
    return
  fi
  if [[ ! -f "${path}" ]]; then
    fail "${label} missing: ${path}"
    return
  fi
  if [[ -L "${path}" ]]; then
    fail "${label} must not be a symlink: ${path}"
    return
  fi
  local mode
  if stat --version >/dev/null 2>&1; then
    mode="$(stat -c '%a' "${path}" 2>/dev/null || true)"
  else
    mode="$(stat -f '%OLp' "${path}" 2>/dev/null || true)"
  fi
  mode="$(printf '%s' "${mode}" | sed 's/^0*//')"
  if [[ -z "${mode}" ]]; then
    fail "${label} cannot stat mode: ${path}"
    return
  fi
  if [[ "${mode}" != "400" && "${mode}" != "600" ]]; then
    fail "${label} mode is ${mode}, want 400 or 600: ${path}"
    return
  fi
  pass "${label} permissions ok (${mode})"
}

check_secret_env_files() {
  local vars=(
    POSTGRES_BOOTSTRAP_PASSWORD_FILE
    GATEWAY_RUNTIME_PASSWORD_FILE
    AUDIT_READER_PASSWORD_FILE
    SECURITY_ADMIN_PASSWORD_FILE
    COMPLIANTAI_TLS_KEY_FILE
    COMPLIANTAI_CONTENT_HMAC_KEY_FILE
    COMPLIANTAI_CHECKPOINT_SIGNING_KEY_FILE
  )
  for v in "${vars[@]}"; do
    if [[ -z "${!v:-}" ]]; then
      fail "environment ${v} is not set"
    else
      check_secret_file "${v}" "${!v}"
    fi
  done
  if [[ -n "${COMPLIANTAI_TLS_CERT_FILE:-}" ]]; then
    if [[ ! -f "${COMPLIANTAI_TLS_CERT_FILE}" ]]; then
      fail "COMPLIANTAI_TLS_CERT_FILE missing"
    else
      pass "TLS certificate file present"
    fi
  else
    fail "COMPLIANTAI_TLS_CERT_FILE is not set"
  fi
  if [[ -n "${COMPLIANTAI_CONFIG_FILE:-}" ]]; then
    if [[ ! -f "${COMPLIANTAI_CONFIG_FILE}" ]]; then
      fail "COMPLIANTAI_CONFIG_FILE missing"
    else
      pass "config file present"
      check_config_uses_local_db "${COMPLIANTAI_CONFIG_FILE}"
    fi
  else
    fail "COMPLIANTAI_CONFIG_FILE is not set"
  fi
}

check_config_uses_local_db() {
  local cfg="$1"
  # Fail closed if config embeds a remote host DSN literal.
  if grep -Eiq 'postgres(ql)?://[^[:space:]"]+@([^/[:space:]"]+)' "${cfg}"; then
    local host
    host="$(grep -Eio 'postgres(ql)?://[^[:space:]"]+@([^/[:space:]":]+)' "${cfg}" | head -1 | sed -E 's/.*@//')"
    case "${host}" in
      localhost|127.0.0.1|::1|postgres)
        pass "config DSN host is local/compose (${host})"
        ;;
      "")
        pass "config DSN host not inline (likely env/file ref)"
        ;;
      *)
        fail "config appears to point at external DB host '${host}'"
        ;;
    esac
  else
    # Prefer env/file secret refs without inline hosts.
    if grep -Eq 'dsn:|COMPLIANTAI_DATABASE' "${cfg}"; then
      pass "database DSN referenced without inline remote host"
    else
      fail "config missing database DSN reference"
    fi
  fi
}

check_writable_mounts_linux() {
  if [[ ! -r /proc/mounts ]]; then
    fail "cannot read /proc/mounts"
    return
  fi
  local line mnt opts fstype
  local found_tmp=0
  while read -r _ mnt fstype opts _; do
    case "${mnt}" in
      /tmp|/var/tmp|/dev/shm)
        found_tmp=1
        if [[ "${opts}" != *rw* ]]; then
          fail "expected temp mount ${mnt} is not rw (${opts})"
        else
          pass "temp mount enumerated: ${mnt} (${fstype},${opts})"
        fi
        ;;
    esac
    # Fail closed on swap mounts anywhere.
    if [[ "${fstype}" == "swap" ]]; then
      fail "swap filesystem mounted at ${mnt}"
    fi
  done < /proc/mounts
  if [[ "${found_tmp}" -eq 0 ]]; then
    warn "no /tmp|/var/tmp|/dev/shm mounts enumerated from /proc/mounts"
  fi
}

check_clock_sanity() {
  local now year
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  year="$(date -u +%Y)"
  if [[ "${year}" -lt 2024 || "${year}" -gt 2100 ]]; then
    fail "system clock year out of range: ${now}"
    return
  fi
  pass "system clock sanity (${now})"
}

check_compose_file() {
  if [[ ! -f "${COMPOSE_FILE}" ]]; then
    fail "compose file missing: ${COMPOSE_FILE}"
    return
  fi

  # Every published host binding must be loopback. Accept Compose interpolation
  # such as 127.0.0.1:${PORT:-55432}:5432 while rejecting 0.0.0.0 and bare ports.
  local ports_block
  ports_block="$(awk '
    $1=="ports:" {inports=1; next}
    inports && /^[[:space:]]*-/ {print; next}
    inports && NF && $1 !~ /^-/ && $1 !~ /^#/ {inports=0}
  ' "${COMPOSE_FILE}")"
  if [[ -z "${ports_block}" ]]; then
    fail "compose has no port publish entries to validate"
  else
    local line bad=0
    while IFS= read -r line; do
      [[ -z "${line}" ]] && continue
      # Strip YAML list marker and quotes for matching.
      local cleaned
      cleaned="$(sed -E 's/^[[:space:]]*-[[:space:]]*//; s/[\"'\'']//g' <<<"${line}")"
      if grep -Eq '0\.0\.0\.0:' <<<"${cleaned}"; then
        fail "compose publishes on 0.0.0.0: ${line}"
        bad=1
        continue
      fi
      if ! grep -Eq '^127\.0\.0\.1:(\$\{[A-Za-z_][A-Za-z0-9_]*(:-[0-9]+)?\}|[0-9]+):[0-9]+$' <<<"${cleaned}"; then
        fail "non-loopback or malformed port publish: ${line}"
        bad=1
      fi
    done <<<"${ports_block}"
    if [[ "${bad}" -eq 0 ]]; then
      pass "all compose port publishes are loopback-bound"
    fi
  fi

  if ! grep -q 'no-new-privileges' "${COMPOSE_FILE}"; then
    fail "compose missing no-new-privileges"
  else
    pass "compose enables no-new-privileges"
  fi
  if ! grep -q 'read_only: true' "${COMPOSE_FILE}"; then
    fail "compose gateway not marked read_only"
  else
    pass "compose gateway read_only"
  fi
  if grep -n 'cap_drop:' "${COMPOSE_FILE}" | grep -q .; then
    if awk '
      $1=="cap_drop:" {indrop=1; next}
      indrop && /^[[:space:]]*-[[:space:]]*ALL[[:space:]]*$/ {found=1}
      indrop && /^[^[:space:]#]/ && $1 !~ /^-/ {indrop=0}
      END {exit found?0:1}
    ' "${COMPOSE_FILE}"; then
      pass "compose includes cap_drop ALL"
    else
      fail "compose does not drop ALL capabilities on hardened services"
    fi
  else
    fail "compose missing cap_drop"
  fi
}

check_backend_reachability() {
  local url="${COMPLIANTAI_BACKEND_BASE_URL:-}"
  if [[ -z "${url}" ]]; then
    skip "COMPLIANTAI_BACKEND_BASE_URL unset; backend reachability not probed"
    return
  fi
  if ! command -v curl >/dev/null 2>&1; then
    fail "curl required to probe backend URL"
    return
  fi
  if curl -fsS --max-time 5 "${url}" >/dev/null 2>&1 || curl -fsS --max-time 5 "${url}/v1/models" >/dev/null 2>&1; then
    pass "backend reachable at configured base URL"
  else
    fail "backend not reachable at ${url}"
  fi
}

check_docker_container_security() {
  if ! command -v docker >/dev/null 2>&1; then
    skip "docker not available; container security inspect skipped"
    return
  fi
  local name
  for name in compliantai-gateway compliantai-postgres; do
    if ! docker inspect "${name}" >/dev/null 2>&1; then
      skip "container ${name} not running; inspect skipped"
      continue
    fi
    local readonly nnp caps user core_json
    readonly="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "${name}" 2>/dev/null || echo false)"
    user="$(docker inspect -f '{{.Config.User}}' "${name}" 2>/dev/null || true)"
    caps="$(docker inspect -f '{{json .HostConfig.CapDrop}}' "${name}" 2>/dev/null || echo '[]')"
    nnp="$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "${name}" 2>/dev/null || echo '[]')"
    core_json="$(docker inspect -f '{{json .HostConfig.Ulimits}}' "${name}" 2>/dev/null || echo 'null')"

    if [[ "${name}" == "compliantai-gateway" ]]; then
      if [[ "${readonly}" != "true" ]]; then
        fail "${name} ReadonlyRootfs=${readonly}, want true"
      else
        pass "${name} read-only root filesystem"
      fi
      if [[ "${user}" != "65532:65532" && "${user}" != "65532" && "${user}" != "nonroot" ]]; then
        fail "${name} user=${user}, want 65532/nonroot"
      else
        pass "${name} non-root user (${user})"
      fi
    fi

    if [[ "${caps}" != *ALL* ]]; then
      fail "${name} CapDrop does not include ALL: ${caps}"
    else
      pass "${name} capabilities dropped (ALL)"
    fi

    if grep -q 'no-new-privileges' <<<"${nnp}"; then
      pass "${name} no-new-privileges"
    else
      fail "${name} missing no-new-privileges security opt"
    fi

    if python3 - "${core_json}" <<'PY'
import json,sys
raw=sys.argv[1]
try:
    data=json.loads(raw)
except Exception:
    sys.exit(1)
if not data:
    sys.exit(1)
for item in data:
    name=(item.get("Name") or item.get("name") or "").lower()
    if name=="core":
        soft=item.get("Soft", item.get("soft"))
        hard=item.get("Hard", item.get("hard"))
        if soft==0 and hard==0:
            sys.exit(0)
sys.exit(1)
PY
    then
      pass "${name} core ulimit soft/hard are 0"
    else
      fail "${name} core ulimit not enforced to 0 (inspect=${core_json})"
    fi
  done
}

main() {
  log "CompliantAI ZRM preflight (fail-closed)"
  log "compose=${COMPOSE_FILE}"

  require_cmd uname || true
  require_cmd date || true
  require_cmd grep || true

  check_compose_file
  check_secret_env_files
  check_clock_sanity
  check_backend_reachability

  if check_linux_host; then
    check_swap_disabled
    check_core_dump_posture
    check_writable_mounts_linux
  fi

  check_docker_container_security

  log "----"
  if [[ "${FAILED}" -gt 0 ]]; then
    log "RESULT: FAILED (${FAILED} mandatory check(s) failed, ${WARNED} warning(s))"
    exit 1
  fi
  log "RESULT: PASSED (${WARNED} warning(s))"
  exit 0
}

main "$@"

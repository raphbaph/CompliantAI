#!/usr/bin/env bash
set -Eeuo pipefail

read_secret() {
  local destination="$1"
  local file_variable="$2"
  local file_path="${!file_variable:-}"
  local value

  if [[ -z "${file_path}" || ! -r "${file_path}" ]]; then
    printf >&2 '%s must reference a readable secret file\n' "${file_variable}"
    exit 1
  fi
  value="$(< "${file_path}")"
  if [[ -z "${value}" ]]; then
    printf >&2 '%s must not be empty\n' "${file_variable}"
    exit 1
  fi
  printf -v "${destination}" '%s' "${value}"
  export "${destination}"
}

read_secret GATEWAY_RUNTIME_PASSWORD GATEWAY_RUNTIME_PASSWORD_FILE
read_secret AUDIT_READER_PASSWORD AUDIT_READER_PASSWORD_FILE
read_secret SECURITY_ADMIN_PASSWORD SECURITY_ADMIN_PASSWORD_FILE

PGOPTIONS='-c pgaudit.log=none -c log_statement=none -c log_min_error_statement=panic' \
psql --set ON_ERROR_STOP=1 \
  --username "${POSTGRES_USER}" \
  --dbname "${POSTGRES_DB}" <<'SQL'
\getenv gateway_password GATEWAY_RUNTIME_PASSWORD
\getenv audit_reader_password AUDIT_READER_PASSWORD
\getenv security_admin_password SECURITY_ADMIN_PASSWORD
ALTER ROLE gateway_runtime PASSWORD :'gateway_password';
ALTER ROLE audit_reader PASSWORD :'audit_reader_password';
ALTER ROLE security_admin PASSWORD :'security_admin_password';
\unset gateway_password
\unset audit_reader_password
\unset security_admin_password
SQL

unset GATEWAY_RUNTIME_PASSWORD AUDIT_READER_PASSWORD SECURITY_ADMIN_PASSWORD

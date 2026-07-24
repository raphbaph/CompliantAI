SET ROLE migration_owner;

CREATE TABLE audit_identifiers (
  identifier_type TEXT NOT NULL CHECK (identifier_type IN ('model', 'backend', 'software_version')),
  identifier_value TEXT NOT NULL CHECK (
    identifier_value ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$'
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
  PRIMARY KEY (identifier_type, identifier_value)
);

CREATE TABLE audit_events (
  sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  run_id UUID NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('run_started', 'run_completed', 'run_failed', 'run_denied')),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
  principal_id UUID NOT NULL REFERENCES principals(id),
  auth_method TEXT NOT NULL CHECK (auth_method IN ('oidc', 'api_key', 'workload')),
  oidc_issuer_hash BYTEA CHECK (oidc_issuer_hash IS NULL OR octet_length(oidc_issuer_hash) = 32),
  policy_version_hash BYTEA NOT NULL CHECK (octet_length(policy_version_hash) = 32),
  decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
  decision_reason_codes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  requested_model TEXT NOT NULL CHECK (btrim(requested_model) <> ''),
  resolved_backend TEXT NOT NULL CHECK (btrim(resolved_backend) <> ''),
  request_hmac BYTEA NOT NULL CHECK (octet_length(request_hmac) = 32),
  response_hmac BYTEA CHECK (response_hmac IS NULL OR octet_length(response_hmac) = 32),
  request_bytes BIGINT NOT NULL DEFAULT 0 CHECK (request_bytes >= 0),
  response_bytes BIGINT CHECK (response_bytes IS NULL OR response_bytes >= 0),
  pii_categories TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  pii_match_counts JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (jsonb_typeof(pii_match_counts) = 'object'),
  health_indicator_categories TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  secret_categories TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  detector_bundle_hash BYTEA NOT NULL CHECK (octet_length(detector_bundle_hash) = 32),
  input_tokens BIGINT CHECK (input_tokens IS NULL OR input_tokens >= 0),
  output_tokens BIGINT CHECK (output_tokens IS NULL OR output_tokens >= 0),
  reserved_cost_micros BIGINT CHECK (reserved_cost_micros IS NULL OR reserved_cost_micros >= 0),
  actual_cost_micros BIGINT CHECK (actual_cost_micros IS NULL OR actual_cost_micros >= 0),
  status TEXT NOT NULL CHECK (status IN ('started', 'completed', 'failed', 'denied')),
  error_code TEXT CHECK (error_code IS NULL OR btrim(error_code) <> ''),
  previous_event_hash BYTEA NOT NULL CHECK (octet_length(previous_event_hash) = 32),
  event_hash BYTEA NOT NULL CHECK (octet_length(event_hash) = 32),
  software_version TEXT NOT NULL CHECK (btrim(software_version) <> ''),
  config_hash BYTEA NOT NULL CHECK (octet_length(config_hash) = 32),
  CHECK (
    (event_type = 'run_started' AND decision = 'allow' AND status = 'started') OR
    (event_type = 'run_completed' AND decision = 'allow' AND status = 'completed') OR
    (event_type = 'run_failed' AND decision = 'allow' AND status = 'failed') OR
    (event_type = 'run_denied' AND decision = 'deny' AND status = 'denied')
  )
);

CREATE INDEX audit_events_run_sequence_idx ON audit_events (run_id, sequence);
CREATE INDEX audit_events_principal_occurred_idx ON audit_events (principal_id, occurred_at);

CREATE TABLE audit_checkpoints (
  sequence BIGINT PRIMARY KEY,
  chain_head_hash BYTEA NOT NULL CHECK (octet_length(chain_head_hash) = 32),
  signing_key_id TEXT NOT NULL CHECK (btrim(signing_key_id) <> ''),
  signature BYTEA NOT NULL CHECK (octet_length(signature) > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
  export_status TEXT NOT NULL DEFAULT 'pending' CHECK (export_status IN ('pending', 'exported', 'witnessed')),
  witness_reference TEXT,
  FOREIGN KEY (sequence) REFERENCES audit_events(sequence)
);

RESET ROLE;

REVOKE ALL ON TABLE audit_identifiers, audit_events, audit_checkpoints FROM PUBLIC;
REVOKE ALL ON SEQUENCE audit_events_sequence_seq FROM PUBLIC;

SET ROLE migration_owner;

ALTER TABLE audit_identifiers
  DROP CONSTRAINT audit_identifiers_identifier_type_check;
ALTER TABLE audit_identifiers
  ADD CONSTRAINT audit_identifiers_identifier_type_check CHECK (
    identifier_type IN ('model', 'backend', 'software_version', 'content_hmac_key')
  );

INSERT INTO audit_identifiers (identifier_type, identifier_value)
VALUES ('content_hmac_key', 'legacy-v1')
ON CONFLICT DO NOTHING;

CREATE FUNCTION audit_code_is_valid(p_value TEXT) RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT p_value ~ '^[a-z][a-z0-9_]{0,63}$';
$$;

CREATE FUNCTION audit_code_set_is_valid(p_values TEXT[]) RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT
    cardinality(p_values) <= 64
    AND (
      cardinality(p_values) = 0 OR
      (array_ndims(p_values) = 1 AND array_lower(p_values, 1) = 1)
    )
    AND NOT EXISTS (
      SELECT 1
      FROM unnest(p_values) AS value
      WHERE NOT (value ~ '^[a-z][a-z0-9_]{0,63}$')
    )
    AND cardinality(p_values) = (
      SELECT count(DISTINCT value)
      FROM unnest(p_values) AS value
    );
$$;

CREATE FUNCTION audit_count_map_is_valid(p_values JSONB) RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT
    jsonb_typeof(p_values) = 'object'
    AND (SELECT count(*) FROM jsonb_each(p_values)) <= 64
    AND NOT EXISTS (
      SELECT 1
      FROM jsonb_each(p_values) AS entry(key, value)
      WHERE NOT (
        entry.key ~ '^[a-z][a-z0-9_]{0,63}$'
        AND CASE
          WHEN jsonb_typeof(entry.value) = 'number'
            AND entry.value #>> '{}' ~ '^(0|[1-9][0-9]*)$'
          THEN (entry.value #>> '{}')::NUMERIC <= 9223372036854775807
          ELSE FALSE
        END
      )
    );
$$;

ALTER TABLE audit_events
  ADD COLUMN schema_version SMALLINT NOT NULL DEFAULT 1,
  ADD COLUMN content_hmac_key_id TEXT NOT NULL DEFAULT 'legacy-v1';
ALTER TABLE audit_events
  ALTER COLUMN schema_version DROP DEFAULT,
  ALTER COLUMN content_hmac_key_id DROP DEFAULT;
ALTER TABLE audit_events
  ADD CONSTRAINT audit_events_schema_version_check CHECK (schema_version = 1),
  ADD CONSTRAINT audit_events_content_hmac_key_id_check CHECK (
    content_hmac_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$'
  ),
  ADD CONSTRAINT audit_events_auth_evidence_v1_check CHECK (
    (auth_method = 'oidc' AND oidc_issuer_hash IS NOT NULL) OR
    (auth_method IN ('api_key', 'workload') AND oidc_issuer_hash IS NULL)
  ) NOT VALID,
  ADD CONSTRAINT audit_events_oidc_issuer_hash_nonzero_v1_check CHECK (
    oidc_issuer_hash IS NULL OR oidc_issuer_hash <> decode(repeat('00', 32), 'hex')
  ) NOT VALID,
  ADD CONSTRAINT audit_events_policy_hash_nonzero_v1_check CHECK (
    policy_version_hash <> decode(repeat('00', 32), 'hex')
  ) NOT VALID,
  ADD CONSTRAINT audit_events_request_hmac_nonzero_v1_check CHECK (
    request_hmac <> decode(repeat('00', 32), 'hex')
  ) NOT VALID,
  ADD CONSTRAINT audit_events_response_hmac_nonzero_v1_check CHECK (
    response_hmac IS NULL OR response_hmac <> decode(repeat('00', 32), 'hex')
  ) NOT VALID,
  ADD CONSTRAINT audit_events_detector_hash_nonzero_v1_check CHECK (
    detector_bundle_hash <> decode(repeat('00', 32), 'hex')
  ) NOT VALID,
  ADD CONSTRAINT audit_events_config_hash_nonzero_v1_check CHECK (
    config_hash <> decode(repeat('00', 32), 'hex')
  ) NOT VALID,
  ADD CONSTRAINT audit_events_decision_reason_codes_v1_check CHECK (
    audit_code_set_is_valid(decision_reason_codes)
  ) NOT VALID,
  ADD CONSTRAINT audit_events_pii_categories_v1_check CHECK (
    audit_code_set_is_valid(pii_categories)
  ) NOT VALID,
  ADD CONSTRAINT audit_events_pii_match_counts_v1_check CHECK (
    audit_count_map_is_valid(pii_match_counts)
  ) NOT VALID,
  ADD CONSTRAINT audit_events_health_categories_v1_check CHECK (
    audit_code_set_is_valid(health_indicator_categories)
  ) NOT VALID,
  ADD CONSTRAINT audit_events_secret_categories_v1_check CHECK (
    audit_code_set_is_valid(secret_categories)
  ) NOT VALID,
  ADD CONSTRAINT audit_events_error_code_v1_check CHECK (
    error_code IS NULL OR audit_code_is_valid(error_code)
  ) NOT VALID;

DROP FUNCTION append_audit_event(
  UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT,
  BYTEA, BYTEA, BYTEA, BYTEA, BYTEA, TEXT, BYTEA
);

CREATE FUNCTION append_audit_event(
  p_schema_version SMALLINT,
  p_event_id UUID,
  p_run_id UUID,
  p_event_type TEXT,
  p_occurred_at TIMESTAMPTZ,
  p_principal_id UUID,
  p_auth_method TEXT,
  p_oidc_issuer_hash BYTEA,
  p_policy_version_hash BYTEA,
  p_decision TEXT,
  p_decision_reason_codes TEXT[],
  p_requested_model TEXT,
  p_resolved_backend TEXT,
  p_content_hmac_key_id TEXT,
  p_request_hmac BYTEA,
  p_response_hmac BYTEA,
  p_request_bytes BIGINT,
  p_response_bytes BIGINT,
  p_pii_categories TEXT[],
  p_pii_match_counts JSONB,
  p_health_indicator_categories TEXT[],
  p_secret_categories TEXT[],
  p_detector_bundle_hash BYTEA,
  p_input_tokens BIGINT,
  p_output_tokens BIGINT,
  p_reserved_cost_micros BIGINT,
  p_actual_cost_micros BIGINT,
  p_status TEXT,
  p_error_code TEXT,
  p_previous_event_hash BYTEA,
  p_event_hash BYTEA,
  p_software_version TEXT,
  p_config_hash BYTEA
) RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  inserted_sequence BIGINT;
BEGIN
  IF NOT (
    (p_event_type = 'run_started' AND p_decision = 'allow' AND p_status = 'started') OR
    (p_event_type = 'run_completed' AND p_decision = 'allow' AND p_status = 'completed') OR
    (p_event_type = 'run_failed' AND p_decision = 'allow' AND p_status = 'failed') OR
    (p_event_type = 'run_denied' AND p_decision = 'deny' AND p_status = 'denied')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid audit event state';
  END IF;

  IF public.audit_code_set_is_valid(p_decision_reason_codes) IS NOT TRUE
    OR public.audit_code_set_is_valid(p_pii_categories) IS NOT TRUE
    OR public.audit_count_map_is_valid(p_pii_match_counts) IS NOT TRUE
    OR public.audit_code_set_is_valid(p_health_indicator_categories) IS NOT TRUE
    OR public.audit_code_set_is_valid(p_secret_categories) IS NOT TRUE
    OR (
      p_error_code IS NOT NULL
      AND public.audit_code_is_valid(p_error_code) IS NOT TRUE
    )
  THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid audit event metadata';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.audit_identifiers
    WHERE identifier_type = 'model' AND identifier_value = p_requested_model
  ) OR NOT EXISTS (
    SELECT 1 FROM public.audit_identifiers
    WHERE identifier_type = 'backend' AND identifier_value = p_resolved_backend
  ) OR NOT EXISTS (
    SELECT 1 FROM public.audit_identifiers
    WHERE identifier_type = 'software_version' AND identifier_value = p_software_version
  ) OR NOT EXISTS (
    SELECT 1 FROM public.audit_identifiers
    WHERE identifier_type = 'content_hmac_key' AND identifier_value = p_content_hmac_key_id
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'unregistered audit identifier';
  END IF;

  INSERT INTO public.audit_events (
    schema_version,
    event_id,
    run_id,
    event_type,
    occurred_at,
    principal_id,
    auth_method,
    oidc_issuer_hash,
    policy_version_hash,
    decision,
    decision_reason_codes,
    requested_model,
    resolved_backend,
    content_hmac_key_id,
    request_hmac,
    response_hmac,
    request_bytes,
    response_bytes,
    pii_categories,
    pii_match_counts,
    health_indicator_categories,
    secret_categories,
    detector_bundle_hash,
    input_tokens,
    output_tokens,
    reserved_cost_micros,
    actual_cost_micros,
    status,
    error_code,
    previous_event_hash,
    event_hash,
    software_version,
    config_hash
  ) VALUES (
    p_schema_version,
    p_event_id,
    p_run_id,
    p_event_type,
    p_occurred_at,
    p_principal_id,
    p_auth_method,
    p_oidc_issuer_hash,
    p_policy_version_hash,
    p_decision,
    p_decision_reason_codes,
    p_requested_model,
    p_resolved_backend,
    p_content_hmac_key_id,
    p_request_hmac,
    p_response_hmac,
    p_request_bytes,
    p_response_bytes,
    p_pii_categories,
    p_pii_match_counts,
    p_health_indicator_categories,
    p_secret_categories,
    p_detector_bundle_hash,
    p_input_tokens,
    p_output_tokens,
    p_reserved_cost_micros,
    p_actual_cost_micros,
    p_status,
    p_error_code,
    p_previous_event_hash,
    p_event_hash,
    p_software_version,
    p_config_hash
  ) RETURNING sequence INTO inserted_sequence;

  RETURN inserted_sequence;
END;
$$;

RESET ROLE;

REVOKE ALL ON FUNCTION audit_code_is_valid(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_code_set_is_valid(TEXT[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_count_map_is_valid(JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION append_audit_event(
  SMALLINT, UUID, UUID, TEXT, TIMESTAMPTZ, UUID, TEXT, BYTEA, BYTEA, TEXT,
  TEXT[], TEXT, TEXT, TEXT, BYTEA, BYTEA, BIGINT, BIGINT, TEXT[], JSONB,
  TEXT[], TEXT[], BYTEA, BIGINT, BIGINT, BIGINT, BIGINT, TEXT, TEXT,
  BYTEA, BYTEA, TEXT, BYTEA
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION append_audit_event(
  SMALLINT, UUID, UUID, TEXT, TIMESTAMPTZ, UUID, TEXT, BYTEA, BYTEA, TEXT,
  TEXT[], TEXT, TEXT, TEXT, BYTEA, BYTEA, BIGINT, BIGINT, TEXT[], JSONB,
  TEXT[], TEXT[], BYTEA, BIGINT, BIGINT, BIGINT, BIGINT, TEXT, TEXT,
  BYTEA, BYTEA, TEXT, BYTEA
) TO gateway_runtime;

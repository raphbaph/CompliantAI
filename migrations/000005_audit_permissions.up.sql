SET ROLE migration_owner;

CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'audit history is append only';
END;
$$;

CREATE TRIGGER audit_events_no_update_or_delete
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();
CREATE TRIGGER audit_checkpoints_no_update_or_delete
  BEFORE UPDATE OR DELETE ON audit_checkpoints
  FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
CREATE TRIGGER audit_checkpoints_no_truncate
  BEFORE TRUNCATE ON audit_checkpoints
  FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();

ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_no_update_or_delete;
ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_no_truncate;
ALTER TABLE audit_checkpoints ENABLE ALWAYS TRIGGER audit_checkpoints_no_update_or_delete;
ALTER TABLE audit_checkpoints ENABLE ALWAYS TRIGGER audit_checkpoints_no_truncate;

CREATE OR REPLACE FUNCTION admin_register_audit_identifier(
  p_identifier_type TEXT,
  p_identifier_value TEXT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  INSERT INTO public.audit_identifiers (identifier_type, identifier_value)
  VALUES (p_identifier_type, p_identifier_value)
  ON CONFLICT DO NOTHING;
END;
$$;

CREATE OR REPLACE FUNCTION append_audit_event(
  p_run_id UUID,
  p_event_type TEXT,
  p_principal_id UUID,
  p_auth_method TEXT,
  p_decision TEXT,
  p_requested_model TEXT,
  p_resolved_backend TEXT,
  p_status TEXT,
  p_request_hmac BYTEA,
  p_policy_version_hash BYTEA,
  p_detector_bundle_hash BYTEA,
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

  IF NOT EXISTS (
    SELECT 1 FROM public.audit_identifiers
    WHERE identifier_type = 'model' AND identifier_value = p_requested_model
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'unregistered audit identifier';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.audit_identifiers
    WHERE identifier_type = 'backend' AND identifier_value = p_resolved_backend
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'unregistered audit identifier';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.audit_identifiers
    WHERE identifier_type = 'software_version' AND identifier_value = p_software_version
  ) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'unregistered audit identifier';
  END IF;

  INSERT INTO public.audit_events (
    run_id,
    event_type,
    principal_id,
    auth_method,
    policy_version_hash,
    decision,
    requested_model,
    resolved_backend,
    request_hmac,
    detector_bundle_hash,
    status,
    previous_event_hash,
    event_hash,
    software_version,
    config_hash
  ) VALUES (
    p_run_id,
    p_event_type,
    p_principal_id,
    p_auth_method,
    p_policy_version_hash,
    p_decision,
    p_requested_model,
    p_resolved_backend,
    p_request_hmac,
    p_detector_bundle_hash,
    p_status,
    p_previous_event_hash,
    p_event_hash,
    p_software_version,
    p_config_hash
  ) RETURNING sequence INTO inserted_sequence;
  RETURN inserted_sequence;
END;
$$;

RESET ROLE;

REVOKE ALL ON FUNCTION reject_audit_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION admin_register_audit_identifier(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION append_audit_event(UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, BYTEA, BYTEA, BYTEA, BYTEA, TEXT, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin_register_audit_identifier(TEXT, TEXT) TO security_admin;
GRANT EXECUTE ON FUNCTION append_audit_event(UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, BYTEA, BYTEA, BYTEA, BYTEA, TEXT, BYTEA) TO gateway_runtime;
GRANT SELECT ON audit_events, audit_checkpoints TO audit_reader;

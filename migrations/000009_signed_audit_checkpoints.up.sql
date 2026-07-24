SET ROLE migration_owner;

ALTER TABLE audit_checkpoints
  ADD CONSTRAINT audit_checkpoints_chain_head_nonzero
  CHECK (chain_head_hash <> decode(repeat('00', 32), 'hex')) NOT VALID,
  ADD CONSTRAINT audit_checkpoints_signing_key_id_canonical
  CHECK (signing_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$') NOT VALID,
  ADD CONSTRAINT audit_checkpoints_ed25519_signature
  CHECK (octet_length(signature) = 64) NOT VALID,
  ADD CONSTRAINT audit_checkpoints_created_at_microseconds
  CHECK (
    created_at NOT IN ('-infinity'::TIMESTAMPTZ, 'infinity'::TIMESTAMPTZ) AND
    created_at >= TIMESTAMPTZ '0001-01-01 00:00:00+00' AND
    created_at < TIMESTAMPTZ '10000-01-01 00:00:00+00' AND
    date_trunc('microseconds', created_at) = created_at
  ) NOT VALID;

CREATE FUNCTION get_audit_chain_head(
  OUT sequence BIGINT,
  OUT event_hash BYTEA
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  SELECT head.sequence, head.event_hash
  INTO sequence, event_hash
  FROM public.audit_chain_head AS head
  WHERE head.singleton;

  IF sequence IS NULL OR sequence <= 0 OR event_hash IS NULL OR octet_length(event_hash) <> 32 THEN
    RAISE EXCEPTION USING
      ERRCODE = '55000',
      MESSAGE = 'audit checkpoint unavailable';
  END IF;
END;
$$;

CREATE FUNCTION store_audit_checkpoint(
  p_sequence BIGINT,
  p_chain_head_hash BYTEA,
  p_signing_key_id TEXT,
  p_signature BYTEA,
  p_created_at TIMESTAMPTZ
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_sequence IS NULL OR p_sequence <= 0 OR
     p_chain_head_hash IS NULL OR octet_length(p_chain_head_hash) <> 32 OR
     p_chain_head_hash = decode(repeat('00', 32), 'hex') OR
     p_signing_key_id IS NULL OR
     p_signing_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$' OR
     p_signature IS NULL OR octet_length(p_signature) <> 64 OR
     p_created_at IS NULL OR
     p_created_at IN ('-infinity'::TIMESTAMPTZ, 'infinity'::TIMESTAMPTZ) OR
     p_created_at < TIMESTAMPTZ '0001-01-01 00:00:00+00' OR
     p_created_at >= TIMESTAMPTZ '10000-01-01 00:00:00+00' OR
     date_trunc('microseconds', p_created_at) <> p_created_at THEN
    RAISE EXCEPTION USING
      ERRCODE = '22023',
      MESSAGE = 'invalid audit checkpoint';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.audit_events AS event
    WHERE event.sequence = p_sequence
      AND event.event_hash = p_chain_head_hash
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '22023',
      MESSAGE = 'invalid audit checkpoint';
  END IF;

  INSERT INTO public.audit_checkpoints (
    sequence,
    chain_head_hash,
    signing_key_id,
    signature,
    created_at
  ) VALUES (
    p_sequence,
    p_chain_head_hash,
    p_signing_key_id,
    p_signature,
    p_created_at
  );
EXCEPTION
  WHEN unique_violation OR foreign_key_violation OR check_violation THEN
    RAISE EXCEPTION USING
      ERRCODE = '22023',
      MESSAGE = 'invalid audit checkpoint';
END;
$$;

RESET ROLE;

REVOKE ALL ON FUNCTION get_audit_chain_head() FROM PUBLIC;
REVOKE ALL ON FUNCTION store_audit_checkpoint(BIGINT, BYTEA, TEXT, BYTEA, TIMESTAMPTZ) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_audit_chain_head() TO security_admin;
GRANT EXECUTE ON FUNCTION store_audit_checkpoint(BIGINT, BYTEA, TEXT, BYTEA, TIMESTAMPTZ) TO security_admin;

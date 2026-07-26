SET ROLE migration_owner;

ALTER TABLE api_keys
  ADD CONSTRAINT api_keys_created_at_canonical_v1_check CHECK (
    created_at NOT IN ('-infinity'::timestamptz, 'infinity'::timestamptz) AND
    created_at >= TIMESTAMPTZ '0001-01-01 00:00:00+00' AND
    created_at < TIMESTAMPTZ '10000-01-01 00:00:00+00' AND
    created_at = date_trunc('microseconds', created_at)
  ) NOT VALID,
  ADD CONSTRAINT api_keys_expires_at_canonical_v1_check CHECK (
    expires_at IS NULL OR (
      expires_at NOT IN ('-infinity'::timestamptz, 'infinity'::timestamptz) AND
      expires_at >= TIMESTAMPTZ '0001-01-01 00:00:00+00' AND
      expires_at < TIMESTAMPTZ '10000-01-01 00:00:00+00' AND
      expires_at = date_trunc('microseconds', expires_at)
    )
  ) NOT VALID,
  ADD CONSTRAINT api_keys_last_used_at_canonical_v1_check CHECK (
    last_used_at IS NULL OR (
      last_used_at NOT IN ('-infinity'::timestamptz, 'infinity'::timestamptz) AND
      last_used_at >= TIMESTAMPTZ '0001-01-01 00:00:00+00' AND
      last_used_at < TIMESTAMPTZ '10000-01-01 00:00:00+00' AND
      last_used_at = date_trunc('microseconds', last_used_at)
    )
  ) NOT VALID,
  ADD CONSTRAINT api_keys_disabled_at_canonical_v1_check CHECK (
    disabled_at IS NULL OR (
      disabled_at NOT IN ('-infinity'::timestamptz, 'infinity'::timestamptz) AND
      disabled_at >= TIMESTAMPTZ '0001-01-01 00:00:00+00' AND
      disabled_at < TIMESTAMPTZ '10000-01-01 00:00:00+00' AND
      disabled_at = date_trunc('microseconds', disabled_at)
    )
  ) NOT VALID;

CREATE OR REPLACE FUNCTION admin_create_api_key(
  p_key_id TEXT,
  p_secret_verifier TEXT,
  p_principal_id UUID,
  p_expires_at TIMESTAMPTZ
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_key_id IS NULL OR p_key_id !~ '^[0-9a-f]{32}$' OR
     p_secret_verifier IS NULL OR p_secret_verifier !~ '^hmac-sha256:[0-9a-f]{64}$' OR
     p_principal_id IS NULL OR p_expires_at IS NULL OR
     p_expires_at IN ('-infinity'::timestamptz, 'infinity'::timestamptz) OR
     p_expires_at < TIMESTAMPTZ '0001-01-01 00:00:00+00' OR
     p_expires_at >= TIMESTAMPTZ '10000-01-01 00:00:00+00' OR
     p_expires_at <> date_trunc('microseconds', p_expires_at) OR
     p_expires_at <= statement_timestamp() OR
     NOT EXISTS (
       SELECT 1 FROM public.principals
       WHERE id = p_principal_id AND status = 'active'
     ) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'API key administration failed';
  END IF;

  BEGIN
    INSERT INTO public.api_keys (key_id, secret_verifier, principal_id, expires_at)
    VALUES (p_key_id, p_secret_verifier, p_principal_id, p_expires_at);
  EXCEPTION
    WHEN unique_violation OR foreign_key_violation OR check_violation OR not_null_violation THEN
      RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'API key administration failed';
  END;
END;
$$;

CREATE OR REPLACE FUNCTION admin_disable_api_key(p_key_id TEXT) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  affected_rows BIGINT;
BEGIN
  IF p_key_id IS NULL OR p_key_id !~ '^[0-9a-f]{32}$' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'API key administration failed';
  END IF;
  UPDATE public.api_keys
  SET disabled_at = COALESCE(disabled_at, statement_timestamp())
  WHERE key_id = p_key_id;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'API key administration failed';
  END IF;
END;
$$;

CREATE FUNCTION lookup_api_key_auth(p_key_id TEXT)
RETURNS TABLE (
  key_id TEXT,
  secret_verifier TEXT,
  principal_id UUID,
  principal_active BOOLEAN,
  expires_at TIMESTAMPTZ,
  disabled BOOLEAN
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT
    api_keys.key_id,
    api_keys.secret_verifier,
    api_keys.principal_id,
    principals.status = 'active',
    api_keys.expires_at,
    api_keys.disabled_at IS NOT NULL
  FROM public.api_keys
  JOIN public.principals ON principals.id = api_keys.principal_id
  WHERE api_keys.key_id = p_key_id
$$;

CREATE FUNCTION mark_api_key_used(p_key_id TEXT, p_principal_id UUID) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  marked BOOLEAN := FALSE;
BEGIN
  UPDATE public.api_keys
  SET last_used_at = statement_timestamp()
  WHERE api_keys.key_id = p_key_id
    AND api_keys.principal_id = p_principal_id
    AND api_keys.disabled_at IS NULL
    AND api_keys.expires_at IS NOT NULL
    AND api_keys.expires_at > statement_timestamp()
    AND EXISTS (
      SELECT 1 FROM public.principals
      WHERE principals.id = p_principal_id AND principals.status = 'active'
    )
  RETURNING TRUE INTO marked;
  RETURN COALESCE(marked, FALSE);
END;
$$;

RESET ROLE;

REVOKE SELECT ON principals, api_keys FROM gateway_runtime;
REVOKE ALL ON FUNCTION admin_create_api_key(TEXT, TEXT, UUID, TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION admin_disable_api_key(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION lookup_api_key_auth(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION mark_api_key_used(TEXT, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION admin_create_api_key(TEXT, TEXT, UUID, TIMESTAMPTZ) TO security_admin;
GRANT EXECUTE ON FUNCTION admin_disable_api_key(TEXT) TO security_admin;
GRANT EXECUTE ON FUNCTION lookup_api_key_auth(TEXT) TO gateway_runtime;
GRANT EXECUTE ON FUNCTION mark_api_key_used(TEXT, UUID) TO gateway_runtime;

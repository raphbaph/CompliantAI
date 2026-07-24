SET ROLE migration_owner;

CREATE TABLE principals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  external_subject TEXT,
  issuer TEXT,
  display_label TEXT,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
  disabled_at TIMESTAMPTZ,
  CHECK ((status = 'active' AND disabled_at IS NULL) OR status = 'disabled'),
  CHECK ((issuer IS NULL) = (external_subject IS NULL))
);

CREATE UNIQUE INDEX principals_oidc_identity_unique
  ON principals (issuer, external_subject)
  WHERE issuer IS NOT NULL AND external_subject IS NOT NULL;

CREATE TABLE api_keys (
  key_id TEXT PRIMARY KEY CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  secret_verifier TEXT NOT NULL CHECK (secret_verifier ~ '^hmac-sha256:[0-9a-f]{64}$'),
  principal_id UUID NOT NULL REFERENCES principals(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
  expires_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  disabled_at TIMESTAMPTZ,
  CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE OR REPLACE FUNCTION admin_create_principal(
  p_issuer TEXT,
  p_external_subject TEXT,
  p_display_label TEXT
) RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  created_id UUID;
BEGIN
  IF p_issuer IS NULL OR btrim(p_issuer) = '' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'issuer is required';
  END IF;
  IF p_external_subject IS NULL OR btrim(p_external_subject) = '' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'external subject is required';
  END IF;

  INSERT INTO public.principals (issuer, external_subject, display_label, status)
  VALUES (p_issuer, p_external_subject, p_display_label, 'active')
  RETURNING id INTO created_id;
  RETURN created_id;
END;
$$;

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
  INSERT INTO public.api_keys (key_id, secret_verifier, principal_id, expires_at)
  VALUES (p_key_id, p_secret_verifier, p_principal_id, p_expires_at);
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
  UPDATE public.api_keys
  SET disabled_at = statement_timestamp()
  WHERE key_id = p_key_id AND disabled_at IS NULL;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'API key is missing or disabled';
  END IF;
END;
$$;

RESET ROLE;

REVOKE ALL ON TABLE principals, api_keys FROM PUBLIC;
REVOKE ALL ON FUNCTION admin_create_principal(TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION admin_create_api_key(TEXT, TEXT, UUID, TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION admin_disable_api_key(TEXT) FROM PUBLIC;
GRANT SELECT ON principals, api_keys TO gateway_runtime;
GRANT EXECUTE ON FUNCTION admin_create_principal(TEXT, TEXT, TEXT) TO security_admin;
GRANT EXECUTE ON FUNCTION admin_create_api_key(TEXT, TEXT, UUID, TIMESTAMPTZ) TO security_admin;
GRANT EXECUTE ON FUNCTION admin_disable_api_key(TEXT) TO security_admin;

SET ROLE migration_owner;

CREATE FUNCTION lookup_oidc_principal(p_issuer TEXT, p_external_subject TEXT)
RETURNS TABLE (
  principal_id UUID,
  principal_active BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF p_issuer IS NULL OR btrim(p_issuer) = '' OR char_length(p_issuer) > 512 OR
     p_external_subject IS NULL OR btrim(p_external_subject) = '' OR char_length(p_external_subject) > 256 OR
     position(E'\n' in p_issuer) > 0 OR position(E'\r' in p_issuer) > 0 OR
     position(E'\n' in p_external_subject) > 0 OR position(E'\r' in p_external_subject) > 0 THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT
    principals.id,
    principals.status = 'active'
  FROM public.principals
  WHERE principals.issuer = p_issuer
    AND principals.external_subject = p_external_subject;
END;
$$;

REVOKE ALL ON FUNCTION lookup_oidc_principal(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_oidc_principal(TEXT, TEXT) TO gateway_runtime;

RESET ROLE;

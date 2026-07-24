SET ROLE migration_owner;

CREATE TABLE audit_chain_head (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  sequence BIGINT NOT NULL CHECK (sequence >= 0),
  event_hash BYTEA NOT NULL CHECK (octet_length(event_hash) = 32)
);

INSERT INTO audit_chain_head (singleton, sequence, event_hash)
SELECT
  TRUE,
  COALESCE(latest.sequence, 0),
  COALESCE(latest.event_hash, decode(repeat('00', 32), 'hex'))
FROM (
  SELECT sequence, event_hash
  FROM audit_events
  ORDER BY sequence DESC
  LIMIT 1
) AS latest
RIGHT JOIN (SELECT TRUE) AS required_row ON TRUE;

ALTER TABLE audit_events
  ADD CONSTRAINT audit_events_event_hash_nonzero_v1_check CHECK (
    event_hash <> decode(repeat('00', 32), 'hex')
  ) NOT VALID;

CREATE FUNCTION lock_audit_chain_head()
RETURNS TABLE (sequence BIGINT, event_hash BYTEA)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  RETURN QUERY
  SELECT head.sequence, head.event_hash
  FROM public.audit_chain_head AS head
  WHERE head.singleton
  FOR UPDATE;
END;
$$;

CREATE FUNCTION serialize_audit_chain_append() RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  head_sequence BIGINT;
  head_event_hash BYTEA;
BEGIN
  SELECT head.sequence, head.event_hash
  INTO head_sequence, head_event_hash
  FROM public.audit_chain_head AS head
  WHERE head.singleton
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'audit chain head unavailable';
  END IF;
  IF NEW.previous_event_hash <> head_event_hash THEN
    RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'audit chain head changed';
  END IF;

  NEW.sequence := head_sequence + 1;
  RETURN NEW;
END;
$$;

CREATE FUNCTION advance_audit_chain_head() RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  UPDATE public.audit_chain_head
  SET sequence = NEW.sequence,
      event_hash = NEW.event_hash
  WHERE singleton;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'audit chain head unavailable';
  END IF;
  RETURN NULL;
END;
$$;

CREATE TRIGGER audit_events_serialize_chain
  BEFORE INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION serialize_audit_chain_append();
CREATE TRIGGER audit_events_advance_chain_head
  AFTER INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION advance_audit_chain_head();

ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_serialize_chain;
ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_advance_chain_head;

RESET ROLE;

REVOKE ALL ON TABLE audit_chain_head FROM PUBLIC;
REVOKE ALL ON FUNCTION lock_audit_chain_head() FROM PUBLIC;
REVOKE ALL ON FUNCTION serialize_audit_chain_append() FROM PUBLIC;
REVOKE ALL ON FUNCTION advance_audit_chain_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lock_audit_chain_head() TO gateway_runtime;

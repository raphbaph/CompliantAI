SET ROLE migration_owner;

CREATE TABLE budget_accounts (
  principal_id UUID PRIMARY KEY REFERENCES principals(id),
  daily_limit_micros BIGINT NOT NULL CHECK (daily_limit_micros > 0),
  monthly_limit_micros BIGINT NOT NULL CHECK (monthly_limit_micros > 0),
  daily_period_start TIMESTAMPTZ NOT NULL,
  daily_period_end TIMESTAMPTZ NOT NULL,
  monthly_period_start TIMESTAMPTZ NOT NULL,
  monthly_period_end TIMESTAMPTZ NOT NULL,
  daily_committed_micros BIGINT NOT NULL DEFAULT 0 CHECK (daily_committed_micros >= 0),
  daily_reserved_micros BIGINT NOT NULL DEFAULT 0 CHECK (daily_reserved_micros >= 0),
  monthly_committed_micros BIGINT NOT NULL DEFAULT 0 CHECK (monthly_committed_micros >= 0),
  monthly_reserved_micros BIGINT NOT NULL DEFAULT 0 CHECK (monthly_reserved_micros >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
  CHECK (daily_period_end > daily_period_start),
  CHECK (monthly_period_end > monthly_period_start),
  CHECK (daily_committed_micros + daily_reserved_micros <= daily_limit_micros),
  CHECK (monthly_committed_micros + monthly_reserved_micros <= monthly_limit_micros)
);

CREATE TABLE spend_reservations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL UNIQUE,
  principal_id UUID NOT NULL REFERENCES principals(id),
  model_name TEXT NOT NULL CHECK (btrim(model_name) <> ''),
  reserved_max_micros BIGINT NOT NULL CHECK (reserved_max_micros > 0),
  settled_actual_micros BIGINT CHECK (settled_actual_micros >= 0),
  state TEXT NOT NULL CHECK (state IN ('reserved', 'settled', 'released', 'expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
  expires_at TIMESTAMPTZ NOT NULL,
  settled_at TIMESTAMPTZ,
  CHECK (expires_at > created_at),
  CHECK ((state = 'reserved' AND settled_at IS NULL) OR state <> 'reserved')
);

CREATE OR REPLACE FUNCTION admin_set_budget(
  p_principal_id UUID,
  p_daily_limit_micros BIGINT,
  p_monthly_limit_micros BIGINT
) RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_utc TIMESTAMPTZ := statement_timestamp();
BEGIN
  IF p_daily_limit_micros <= 0 OR p_monthly_limit_micros <= 0 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'budget limits must be positive';
  END IF;
  IF p_daily_limit_micros > p_monthly_limit_micros THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'daily limit must not exceed monthly limit';
  END IF;

  INSERT INTO public.budget_accounts (
    principal_id,
    daily_limit_micros,
    monthly_limit_micros,
    daily_period_start,
    daily_period_end,
    monthly_period_start,
    monthly_period_end
  ) VALUES (
    p_principal_id,
    p_daily_limit_micros,
    p_monthly_limit_micros,
    date_trunc('day', now_utc),
    date_trunc('day', now_utc) + interval '1 day',
    date_trunc('month', now_utc),
    date_trunc('month', now_utc) + interval '1 month'
  )
  ON CONFLICT (principal_id) DO UPDATE
  SET daily_limit_micros = EXCLUDED.daily_limit_micros,
      monthly_limit_micros = EXCLUDED.monthly_limit_micros,
      updated_at = statement_timestamp();
END;
$$;

RESET ROLE;

REVOKE ALL ON TABLE budget_accounts, spend_reservations FROM PUBLIC;
REVOKE ALL ON FUNCTION admin_set_budget(UUID, BIGINT, BIGINT) FROM PUBLIC;
GRANT SELECT ON budget_accounts, spend_reservations TO gateway_runtime;
GRANT EXECUTE ON FUNCTION admin_set_budget(UUID, BIGINT, BIGINT) TO security_admin;

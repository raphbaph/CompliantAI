SET ROLE migration_owner;

CREATE OR REPLACE FUNCTION budget_roll_periods(p_account public.budget_accounts, p_now TIMESTAMPTZ)
RETURNS public.budget_accounts
LANGUAGE plpgsql
STRICT
SET search_path = pg_catalog, public
AS $$
DECLARE
  account public.budget_accounts := p_account;
BEGIN
  IF p_now >= account.daily_period_end THEN
    account.daily_period_start := date_trunc('day', p_now);
    account.daily_period_end := account.daily_period_start + interval '1 day';
    -- Keep open reserved holds; only the committed window resets.
    account.daily_committed_micros := 0;
  END IF;
  IF p_now >= account.monthly_period_end THEN
    account.monthly_period_start := date_trunc('month', p_now);
    account.monthly_period_end := account.monthly_period_start + interval '1 month';
    account.monthly_committed_micros := 0;
  END IF;
  RETURN account;
END;
$$;

CREATE OR REPLACE FUNCTION reserve_budget(
  p_principal_id UUID,
  p_run_id UUID,
  p_model_name TEXT,
  p_reserved_max_micros BIGINT,
  p_ttl_seconds INTEGER
) RETURNS TABLE (reservation_id UUID)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_utc TIMESTAMPTZ := statement_timestamp();
  account public.budget_accounts;
  created_id UUID;
BEGIN
  IF p_principal_id IS NULL OR p_run_id IS NULL OR
     p_model_name IS NULL OR btrim(p_model_name) = '' OR char_length(p_model_name) > 128 OR
     p_reserved_max_micros IS NULL OR p_reserved_max_micros <= 0 OR
     p_ttl_seconds IS NULL OR p_ttl_seconds <= 0 OR p_ttl_seconds > 86400 THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid budget reservation';
  END IF;

  -- Lock principal first so disable cannot race past an earlier active check.
  PERFORM 1
  FROM public.principals
  WHERE id = p_principal_id AND status = 'active'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'budget denied';
  END IF;

  SELECT * INTO account
  FROM public.budget_accounts
  WHERE principal_id = p_principal_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'budget denied';
  END IF;

  account := public.budget_roll_periods(account, now_utc);

  IF account.daily_committed_micros + account.daily_reserved_micros + p_reserved_max_micros > account.daily_limit_micros OR
     account.monthly_committed_micros + account.monthly_reserved_micros + p_reserved_max_micros > account.monthly_limit_micros THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'budget denied';
  END IF;

  INSERT INTO public.spend_reservations (
    run_id,
    principal_id,
    model_name,
    reserved_max_micros,
    state,
    expires_at
  ) VALUES (
    p_run_id,
    p_principal_id,
    p_model_name,
    p_reserved_max_micros,
    'reserved',
    now_utc + make_interval(secs => p_ttl_seconds)
  )
  RETURNING id INTO created_id;

  UPDATE public.budget_accounts
  SET daily_period_start = account.daily_period_start,
      daily_period_end = account.daily_period_end,
      monthly_period_start = account.monthly_period_start,
      monthly_period_end = account.monthly_period_end,
      daily_committed_micros = account.daily_committed_micros,
      monthly_committed_micros = account.monthly_committed_micros,
      daily_reserved_micros = account.daily_reserved_micros + p_reserved_max_micros,
      monthly_reserved_micros = account.monthly_reserved_micros + p_reserved_max_micros,
      updated_at = now_utc
  WHERE principal_id = p_principal_id;

  reservation_id := created_id;
  RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION settle_budget(
  p_reservation_id UUID,
  p_actual_micros BIGINT
) RETURNS TABLE (settled_actual_micros BIGINT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_utc TIMESTAMPTZ := statement_timestamp();
  reservation public.spend_reservations;
  account public.budget_accounts;
  actual BIGINT;
BEGIN
  IF p_reservation_id IS NULL OR (p_actual_micros IS NOT NULL AND p_actual_micros < 0) THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid budget reservation';
  END IF;

  SELECT * INTO reservation
  FROM public.spend_reservations
  WHERE id = p_reservation_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'budget reservation not found';
  END IF;

  IF reservation.state <> 'reserved' THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid budget reservation';
  END IF;

  SELECT * INTO account
  FROM public.budget_accounts
  WHERE principal_id = reservation.principal_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'budget denied';
  END IF;

  account := public.budget_roll_periods(account, now_utc);

  actual := COALESCE(p_actual_micros, reservation.reserved_max_micros);
  IF actual > reservation.reserved_max_micros THEN
    actual := reservation.reserved_max_micros;
  END IF;

  IF account.daily_reserved_micros < reservation.reserved_max_micros OR
     account.monthly_reserved_micros < reservation.reserved_max_micros THEN
    RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid budget reservation';
  END IF;

  UPDATE public.spend_reservations
  SET state = 'settled',
      settled_actual_micros = actual,
      settled_at = now_utc
  WHERE id = p_reservation_id;

  UPDATE public.budget_accounts
  SET daily_period_start = account.daily_period_start,
      daily_period_end = account.daily_period_end,
      monthly_period_start = account.monthly_period_start,
      monthly_period_end = account.monthly_period_end,
      daily_reserved_micros = account.daily_reserved_micros - reservation.reserved_max_micros,
      monthly_reserved_micros = account.monthly_reserved_micros - reservation.reserved_max_micros,
      daily_committed_micros = account.daily_committed_micros + actual,
      monthly_committed_micros = account.monthly_committed_micros + actual,
      updated_at = now_utc
  WHERE principal_id = reservation.principal_id;

  settled_actual_micros := actual;
  RETURN NEXT;
END;
$$;

CREATE OR REPLACE FUNCTION expire_budget_reservations()
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  now_utc TIMESTAMPTZ := statement_timestamp();
  expired_count BIGINT := 0;
  reservation RECORD;
  account public.budget_accounts;
BEGIN
  FOR reservation IN
    SELECT *
    FROM public.spend_reservations
    WHERE state = 'reserved' AND expires_at <= now_utc
    FOR UPDATE SKIP LOCKED
  LOOP
    SELECT * INTO account
    FROM public.budget_accounts
    WHERE principal_id = reservation.principal_id
    FOR UPDATE;

    IF FOUND THEN
      account := public.budget_roll_periods(account, now_utc);
      IF account.daily_reserved_micros >= reservation.reserved_max_micros THEN
        account.daily_reserved_micros := account.daily_reserved_micros - reservation.reserved_max_micros;
      ELSE
        account.daily_reserved_micros := 0;
      END IF;
      IF account.monthly_reserved_micros >= reservation.reserved_max_micros THEN
        account.monthly_reserved_micros := account.monthly_reserved_micros - reservation.reserved_max_micros;
      ELSE
        account.monthly_reserved_micros := 0;
      END IF;

      UPDATE public.budget_accounts
      SET daily_period_start = account.daily_period_start,
          daily_period_end = account.daily_period_end,
          monthly_period_start = account.monthly_period_start,
          monthly_period_end = account.monthly_period_end,
          daily_committed_micros = account.daily_committed_micros,
          monthly_committed_micros = account.monthly_committed_micros,
          daily_reserved_micros = account.daily_reserved_micros,
          monthly_reserved_micros = account.monthly_reserved_micros,
          updated_at = now_utc
      WHERE principal_id = reservation.principal_id;
    END IF;

    UPDATE public.spend_reservations
    SET state = 'expired',
        settled_at = now_utc
    WHERE id = reservation.id;

    expired_count := expired_count + 1;
  END LOOP;

  RETURN expired_count;
END;
$$;

REVOKE ALL ON FUNCTION budget_roll_periods(public.budget_accounts, TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION reserve_budget(UUID, UUID, TEXT, BIGINT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION settle_budget(UUID, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION expire_budget_reservations() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION reserve_budget(UUID, UUID, TEXT, BIGINT, INTEGER) TO gateway_runtime;
GRANT EXECUTE ON FUNCTION settle_budget(UUID, BIGINT) TO gateway_runtime;
GRANT EXECUTE ON FUNCTION expire_budget_reservations() TO gateway_runtime;

CREATE INDEX IF NOT EXISTS spend_reservations_state_expires_idx
  ON public.spend_reservations (state, expires_at)
  WHERE state = 'reserved';

RESET ROLE;

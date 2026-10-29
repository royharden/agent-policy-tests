-- Migration 2 of 2: quota RPCs for the classify-line edge function (PLAN A16, A17; M7 AC2).
-- Both functions are SECURITY DEFINER with a pinned search_path and are executable only by service_role: the browser
-- never calls them (it has no grant), only the edge function's service-role client does, after it has verified the
-- caller's JWT with auth.getUser(token).
--
-- Concurrency model: every reservation takes ONE global row lock (`app_limits ... for update`), so reservations are
-- serialised in a single order: no cross-user race on the caps and no lock-order deadlock. The caps are COUNT caps per
-- UTC day; reserved and error rows stay charged, so a crash after reserve or a failed provider call still counts.
--
-- Outcomes of reserve_model_call:
--   reserved             new row inserted (status 'reserved'); the caller makes exactly one provider call, then finishes it
--   duplicate_completed  same (user, request_id), same provider and input digest, row completed: return the stored
--                        label/confidence, no new paid call (HTTP 200, duplicate: true)
--   pending              same request, same payload, row still 'reserved' (in flight or crashed): HTTP 409, no new call
--   conflict             same (user, request_id) but a different input digest or provider: HTTP 409, nothing charged
--   duplicate_error      same request, same payload, row 'error': fallback provider_error, no new paid call
--   capped               per-user or global daily count reached: HTTP 429, nothing inserted
-- A duplicate is answered even when today's cap is reached: it costs nothing.

create function public.reserve_model_call(
  p_user uuid,
  p_request uuid,
  p_provider text,
  p_model text,
  p_input_chars integer,
  p_input_sha256 text
)
returns table (
  reservation_id uuid,
  outcome text,
  stored_status text,
  stored_label text,
  stored_confidence double precision
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_limits public.app_limits%rowtype;
  v_existing public.model_call_log%rowtype;
  v_day date := (now() at time zone 'utc')::date;
  v_user_count bigint;
  v_global_count bigint;
  v_id uuid;
begin
  if p_user is null or p_request is null then
    raise exception 'reserve_model_call: p_user and p_request are required' using errcode = '22004';
  end if;
  if p_provider is null or p_provider not in ('jev', 'llm') then
    raise exception 'reserve_model_call: unknown provider' using errcode = '22023';
  end if;
  if p_model is null or char_length(p_model) not between 1 and 200 then
    raise exception 'reserve_model_call: model id missing or too long' using errcode = '22023';
  end if;
  if p_input_sha256 is null or p_input_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'reserve_model_call: input digest must be 64 lower-case hex characters' using errcode = '22023';
  end if;

  -- The single global lock. Every reservation serialises here before reading counts or existing rows.
  select * into v_limits from public.app_limits where id for update;
  if not found then
    raise exception 'reserve_model_call: app_limits row missing' using errcode = 'P0002';
  end if;

  -- The edge function checks the length first; this is defence in depth against a lowered limit or a direct call.
  if p_input_chars is null or p_input_chars < 1 or p_input_chars > v_limits.max_input_chars then
    raise exception 'reserve_model_call: input length outside 1..max_input_chars' using errcode = '22023';
  end if;

  -- Idempotency (PLAN A17): unique (user_id, request_id), matched against the stored digest and provider.
  select * into v_existing
    from public.model_call_log l
   where l.user_id = p_user and l.request_id = p_request;
  if found then
    if v_existing.input_sha256 <> p_input_sha256 or v_existing.provider <> p_provider then
      return query select null::uuid, 'conflict'::text, null::text, null::text, null::double precision;
      return;
    end if;
    if v_existing.status = 'completed' then
      return query select v_existing.id, 'duplicate_completed'::text, v_existing.status, v_existing.label,
                          v_existing.confidence;
    elsif v_existing.status = 'error' then
      return query select v_existing.id, 'duplicate_error'::text, v_existing.status, null::text,
                          null::double precision;
    else
      return query select v_existing.id, 'pending'::text, v_existing.status, null::text, null::double precision;
    end if;
    return;
  end if;

  -- Count caps over every status: reserved and error rows stay charged.
  select count(*) into v_user_count from public.model_call_log l where l.user_id = p_user and l.day = v_day;
  select count(*) into v_global_count from public.model_call_log l where l.day = v_day;
  if v_user_count >= v_limits.per_user_daily or v_global_count >= v_limits.global_daily then
    return query select null::uuid, 'capped'::text, null::text, null::text, null::double precision;
    return;
  end if;

  insert into public.model_call_log (user_id, request_id, day, provider, model, input_chars, input_sha256, status)
  values (p_user, p_request, v_day, p_provider, p_model, p_input_chars, p_input_sha256, 'reserved')
  returning id into v_id;

  return query select v_id, 'reserved'::text, 'reserved'::text, null::text, null::double precision;
end;
$$;

comment on function public.reserve_model_call(uuid, uuid, text, text, integer, text) is
  'Atomically reserve one paid classify-line call under per-user and global daily count caps. service_role only.';

-- finish_model_call: records the outcome of the caller's OWN reservation. It updates only the row with that id AND that
-- user AND status 'reserved'; anything else (another user's row, an already finished row, an unknown id) is a no-op
-- that returns false. p_status 'completed' needs a label (the provider answered with a valid enum value); 'error'
-- covers every fallback (timeout, provider error, unparsable, off-enum) and stores no label or confidence.
create function public.finish_model_call(
  p_reservation uuid,
  p_user uuid,
  p_status text,
  p_label text,
  p_confidence double precision,
  p_usage jsonb,
  p_input_tokens integer,
  p_output_tokens integer,
  p_est_cost bigint
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if p_reservation is null or p_user is null then
    raise exception 'finish_model_call: p_reservation and p_user are required' using errcode = '22004';
  end if;
  if p_status is null or p_status not in ('completed', 'error') then
    raise exception 'finish_model_call: status must be completed or error' using errcode = '22023';
  end if;
  if p_status = 'completed' and p_label is null then
    raise exception 'finish_model_call: a completed call needs a label' using errcode = '22023';
  end if;

  update public.model_call_log l
     set status = p_status,
         label = case when p_status = 'completed' then p_label end,
         confidence = case when p_status = 'completed' then p_confidence end,
         usage = p_usage,
         input_tokens = p_input_tokens,
         output_tokens = p_output_tokens,
         est_cost_microusd = p_est_cost,
         finished_at = now()
   where l.id = p_reservation
     and l.user_id = p_user
     and l.status = 'reserved';

  return found;
end;
$$;

comment on function public.finish_model_call(uuid, uuid, text, text, double precision, jsonb, integer, integer, bigint) is
  'Finish the caller''s own reserved classify-line call (completed with label, or error). service_role only.';

-- Execute rights: service_role only. Revoking from PUBLIC removes PostgreSQL's default EXECUTE grant; anon and
-- authenticated are revoked explicitly because Supabase default privileges grant them EXECUTE on new functions.
revoke all on function public.reserve_model_call(uuid, uuid, text, text, integer, text)
  from public, anon, authenticated;
revoke all on function public.finish_model_call(uuid, uuid, text, text, double precision, jsonb, integer, integer, bigint)
  from public, anon, authenticated;
grant execute on function public.reserve_model_call(uuid, uuid, text, text, integer, text) to service_role;
grant execute on function public.finish_model_call(uuid, uuid, text, text, double precision, jsonb, integer, integer, bigint)
  to service_role;

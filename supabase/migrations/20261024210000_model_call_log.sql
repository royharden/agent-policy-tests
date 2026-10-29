-- Migration 1 of 2: live-classifier quota limits and call ledger (PLAN A2, A16, A17; M7 AC1).
-- The only server state of this app. Policies, answers, fixtures and approvals never reach the database.
-- No line text is ever stored: only its length, its SHA-256 digest, the label enum and the confidence.
-- Deliberate spec deviation (PLAN M8 AC4, BOLT-HANDOFF.md): the extra singleton table `app_limits` beside
-- `model_call_log`, so the owner can change the caps in SQL without a redeploy.

-- ---------------------------------------------------------------------------------------------------------------
-- app_limits: one row, read and locked only by the quota RPCs (service role). No client access at all.
-- ---------------------------------------------------------------------------------------------------------------
create table public.app_limits (
  id boolean primary key default true check (id),
  per_user_daily integer not null check (per_user_daily >= 0),
  global_daily integer not null check (global_daily >= 0),
  -- Upper bound 4096: the edge function rejects bodies over 4 KiB before parsing, so a larger limit could never apply.
  max_input_chars integer not null check (max_input_chars between 1 and 4096),
  updated_at timestamptz not null default now()
);

comment on table public.app_limits is
  'Singleton quota configuration for the classify-line edge function (count caps per UTC day). Service role only.';

insert into public.app_limits (id, per_user_daily, global_daily, max_input_chars)
values (true, 30, 500, 300);

alter table public.app_limits enable row level security;
-- No policies: anon and authenticated can neither read nor write it. Table grants are revoked as well (defence in
-- depth against Supabase default privileges).
revoke all on table public.app_limits from public, anon, authenticated;
grant select, insert, update, delete on table public.app_limits to service_role;

-- ---------------------------------------------------------------------------------------------------------------
-- model_call_log: one row per reserved paid provider call. Reserved and error rows stay charged (count toward caps).
-- ---------------------------------------------------------------------------------------------------------------
create table public.model_call_log (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  request_id uuid not null,
  day date not null,
  provider text not null check (provider in ('jev', 'llm')),
  model text not null check (char_length(model) between 1 and 200),
  input_chars integer not null check (input_chars between 1 and 4096),
  input_sha256 text not null check (input_sha256 ~ '^[0-9a-f]{64}$'),
  status text not null default 'reserved' check (status in ('reserved', 'completed', 'error')),
  label text check (
    label in ('destructive-shell-fs', 'secrets-paths', 'network-egress', 'git-release', 'data-money', 'manual')
  ),
  confidence double precision check (confidence >= 0 and confidence <= 1),
  input_tokens integer check (input_tokens >= 0),
  output_tokens integer check (output_tokens >= 0),
  est_cost_microusd bigint check (est_cost_microusd >= 0),
  usage jsonb,
  created_at timestamptz not null default now(),
  finished_at timestamptz,
  constraint model_call_log_user_request_key unique (user_id, request_id),
  -- A completed row always has a label; reserved and error rows never carry a label or confidence.
  constraint model_call_log_label_matches_status check (
    (status = 'completed' and label is not null)
    or (status <> 'completed' and label is null and confidence is null)
  ),
  constraint model_call_log_finished_matches_status check ((status = 'reserved') = (finished_at is null))
);

comment on table public.model_call_log is
  'Ledger of live classifier calls for count caps and idempotency. Never stores the classified line text.';
comment on column public.model_call_log.input_sha256 is
  'Lower-case hex SHA-256 of the UTF-8 bytes of the line as received; lets a retried request_id be matched to its payload.';
comment on column public.model_call_log.est_cost_microusd is
  'Estimate only (provider-reported tokens x a dated price constant in the function); null when no price is pinned.';

create index model_call_log_day_idx on public.model_call_log (day);
create index model_call_log_user_day_idx on public.model_call_log (user_id, day);

alter table public.model_call_log enable row level security;

-- Signed-in users (including anonymous sign-ins) may read their own rows. No insert/update/delete policy exists:
-- every write goes through the service-role-only RPCs in migration 2.
create policy model_call_log_select_own
  on public.model_call_log
  for select
  to authenticated
  using ((select auth.uid()) = user_id);

revoke all on table public.model_call_log from public, anon, authenticated;
grant select on table public.model_call_log to authenticated;
grant select, insert, update, delete on table public.model_call_log to service_role;

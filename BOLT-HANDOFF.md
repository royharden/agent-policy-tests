# Bolt infrastructure handoff: Agent NOT-List Builder (agent-policy-tests)

## Final source-delivery boundary (M8)

All planned source slices now exist, including the review UI, bundle export, runner build source and offline/live eval
adapters. They remain **source constructed, runtime unverified**. Dependencies/lockfile, type/lint/tests, frontend and
runner builds, browser downloads and every backend/provider check remain pending. A source file is not a deployment
receipt. No remote, GitHub import, migration, function deployment, owner review or paid call has occurred.

Export requires the same M6 content-bound approval helpers, recomputes the report and hashes final bytes of seven
entries. Missing same-origin runner assets fail explicitly; build:runner must run before dev export. The standalone
Node20 ESM runner ignores saved report outcomes and uses invalid/Fail=1, otherwise strict Gap=2, otherwise 0.
Current Fail reports may export visibly; manual acknowledgement preserves Gap.

The fixture expected-field deviation is `expected_local` plus `expected_policy`; see docs/EVALUATION.md. The
additional app_limits table deviation below remains deliberate. Roy's held-out sample approval and provider/model
activation decisions are pending. Local eval models are pinned in eval/config/models.json; Jev 1.13.0 is intentional,
Haiku 4.5 is a dated legacy choice, and prices/availability need re-verification before paid use. The M5 local Jev
adapter follows the 2026-10-24 documentation read; the separately written M7 deployed wire shape and platform behavior
still require D-M7-1…9. Do not infer M7 readiness from M5 source.

The local JSONL call ledger enforces conservative pre-call reservations up to $2 per run; the deployed function has
daily count caps and estimated cost only. Unknown usage remains unknown. Never put either provider key in frontend
configuration. No environment values were read or entered during this construction.

**Status: locally built, never run; provisioning pending.** The migrations, the `classify-line` edge function and the
browser adapter below exist as source (PLAN M7). They were written in Dirty Mode: only static checks were performed
(source inspection, a type-strip syntax parse of the `.ts` files). Nothing has been installed, built, type-checked,
deployed or applied, and no check in this file has a receipt. Use only the "Inspect and prepare only" prompt until the
pending checks below (and `docs/DEFERRED-VALIDATION.md` D-1, D-8..D-11, D-16, D-18) have recorded outcomes.

## Target and readiness

- Repository / branch / prepared revision: local git repo `agent-policy-tests`, branch `main`; no remote yet (a GitHub
  remote is required before Bolt import).
- App root: repository root.
- Database: **Bolt Database** (PLAN A2). The only server state is the live-classifier quota and call ledger.
  Policies, answers, fixtures and approvals stay in the browser (memory, `localStorage` drafts, JSON export).
- Target: fresh, empty Bolt Database; nothing to preserve.
- Existing baseline / applied migrations: none (no migration has ever been applied anywhere).
- Hosting: Bolt hosting (proposed; the final origin is needed for `ALLOWED_ORIGINS`, D-18).
- Publication: prepare only.
- Bolt action: inspect and prepare only.
- Status: locally built, never run (static checks only); infrastructure pending.
- Owner prerequisites: GitHub remote and access; anonymous sign-ins enabled on the auth provider (D-11); TypeSafe
  and/or Anthropic API keys only if live classifiers are wanted.

**Deliberate spec deviation:** the spec names one table (`model_call_log`). This app adds a second, singleton table
`app_limits` (per-user and global daily count caps, max input length) so the owner can change the caps in SQL
without a redeploy, and so every reservation can take one global lock on a single row (PLAN A16).

## Build and connection

| Item | Exact command or configuration name |
|---|---|
| Runtime / package manager | Node >= 20, npm; `package-lock.json` not generated yet (D-19) |
| Frozen install / dev | `npm ci` (after D-19) / `npm run dev` |
| Build / output | `npm run build` (= `npm run build:runner && tsc -b && vite build`) → `dist/` incl. `policy-runner.mjs` |
| Type/lint/tests | `npm run typecheck`, `npm run lint`, `npm test` — never run (D-1). ESLint ignores `supabase/functions/**`; check the function with `deno check` / `deno lint` (D-16) |
| Client file / public env names | `src/lib/supabase.ts`; `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`, `VITE_CLASSIFIER_MODE` |
| Missing config behavior | `supabase` is `null`; the app shows a "Mock mode" banner and uses local classifiers only; `src/providers/remote.ts` returns `not_configured` |

## Database

| Order | Exact migration file | Resources / dependencies | Applied status |
|---|---|---|---|
| 1 | `supabase/migrations/20261024210000_model_call_log.sql` | tables `app_limits` (singleton `id boolean pk check (id)`, seeded 30 / 500 / 300) and `model_call_log` (`user_id` → `auth.users`, `request_id`, UTC `day`, `provider`, `model`, `input_chars`, `input_sha256`, `status` reserved/completed/error, `label` enum, `confidence`, tokens, `est_cost_microusd`, `usage`, timestamps; `unique (user_id, request_id)`; indexes `(day)`, `(user_id, day)`); **no line text column**; RLS enabled on both; policy `model_call_log_select_own`; table grants revoked from `public`, `anon`, `authenticated` except `select` on `model_call_log` for `authenticated`. Needs `gen_random_uuid()` (core PostgreSQL 13+) and the `auth` schema | pending (never applied) |
| 2 | `supabase/migrations/20261024210100_quota_rpcs.sql` | `reserve_model_call(p_user, p_request, p_provider, p_model, p_input_chars, p_input_sha256)` → `(reservation_id, outcome, stored_status, stored_label, stored_confidence)`; `finish_model_call(p_reservation, p_user, p_status, p_label, p_confidence, p_usage, p_input_tokens, p_output_tokens, p_est_cost)` → boolean. Both `security definer`, `set search_path = public, pg_temp`; `execute` revoked from `public`, `anon`, `authenticated`, granted to `service_role` only. Depends on migration 1 | pending (never applied) |

- Access model: `model_call_log` — `authenticated` (including anonymous sign-ins) may `select` only rows where
  `auth.uid() = user_id`; no client insert/update/delete policy or grant. `app_limits` — no client access at all.
- Ownership checks: the edge function derives `p_user` from `auth.getUser(token)`, never from the request body;
  `finish_model_call` updates only the row with that id **and** that user **and** `status = 'reserved'`.
- Reservation outcomes: `reserved | duplicate_completed | pending | conflict | duplicate_error | capped` under a single
  global `select … from app_limits for update` lock; reserved and error rows stay charged (count toward the caps).
- Extensions/RPC permissions/Realtime: no extensions beyond the defaults; RPC grants as above; Realtime not required.
- Seeds: the `app_limits` row inside migration 1 (limits only, no user data). Change limits later with
  `update public.app_limits set per_user_daily = …, global_daily = …, max_input_chars = … where id;`.
- Retry rule: inspect migration tracking, apply only pending changes, preserve existing data; verify timeouts before
  retry and report drift instead of dropping/recreating resources. Migration 1 is not idempotent by design (plain
  `create table`, plain seed insert): do not replay it on a database where it already ran.

## Functions

| Name / source | Caller + auth | Input / output | Resources + secret names | Deploy config |
|---|---|---|---|---|
| `classify-line`; `supabase/functions/classify-line/index.ts` + `contract.ts` (same folder) | signed-in user via a Supabase **anonymous sign-in** JWT, requested by the browser only after the user explicitly opts into a remote classifier (`src/providers/remote.ts`). Gateway `verify_jwt = true`; the handler also verifies the bearer with `auth.getUser(token)` (the anon key sent as Bearer → 401) | POST `{request_id: uuid, provider: "jev"\|"llm", line}` (strict: no other keys; body ≤ 4 KiB checked on bytes before parsing; one line, no control characters; ≤ `app_limits.max_input_chars` code points) → 200 `{request_id, status: "ok"\|"fallback", label, confidence\|null, provider, model, reason?, duplicate?}`; 400/413 invalid input, 401, 403 origin, 405, 409 `pending`/`conflict`, 429 `capped`, 503 `{status:"unavailable", reason: missing_secret\|model_not_configured\|server_not_configured}`, 500 `internal` | RPCs `reserve_model_call`, `finish_model_call`; table `app_limits` (read `max_input_chars`); secrets `TYPESAFE_API_KEY`, `ANTHROPIC_API_KEY`, `LLM_MODEL`, `ALLOWED_ORIGINS`; platform-injected `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`; outbound `https://api.typesafe.ai/v1/systemone`, `https://api.anthropic.com/v1/messages` | `[functions.classify-line] verify_jwt = true` in `supabase/config.toml`; entrypoint `index.ts`; imports only `./contract.ts` and pinned `npm:@supabase/supabase-js@2.45.4` (no import from `src/` or other functions) |

- CORS/preflight: `ALLOWED_ORIGINS` is a comma-separated list of exact origins (e.g. the `bolt.host` origin and, for
  local dev, `http://localhost:5173`). `OPTIONS` from an allowed origin → 204 with `Access-Control-Allow-Origin: <origin>`,
  methods `POST, OPTIONS`, headers `authorization, x-client-info, apikey, content-type`; a browser `Origin` not in the
  list → 403 (an empty or unset list rejects every browser origin). Requests without an `Origin` header are not CORS
  requests and still need a valid user JWT. CORS is not authentication.
- Identity/ownership and abuse controls: per-user 30/day and global 500/day **count** caps (UTC day) under one
  serialised lock; idempotent `request_id` bound to the SHA-256 of the line (same id + same digest + completed → cached
  label, `duplicate: true`; in flight → 409 `pending`; different digest or provider → 409 `conflict`; errored →
  fallback `provider_error`, no new paid call). Secret/model configuration is checked **before** any reservation.
- Paid API limits: one provider request per reservation, 15 s `AbortController` timeout, no automatic retry; Jev
  model pinned `jev-1.13.0`; LLM `max_tokens` 256, model from `LLM_MODEL` with no default. Cost is recorded as an
  estimate only (Jev: input tokens × $0.042/M, dated 2026-10-13; LLM: null). The $2 hard dollar cap applies to the
  local eval ledger, not the deployed function.
- Provider failures: off-enum or unparsable answers, refusals, timeouts and HTTP errors return 200
  `status: "fallback"` with `label: "manual"` and the reason; never a fabricated label.
- Webhooks: not required.
- Platform credentials: `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are expected to be injected by the platform
  (verify availability on Bolt Database; if they are absent the function answers 503 `server_not_configured`). Never
  copy values from another project.

## Server secrets to enter through settings

| Name | Consumer | Required / optional | Owner source |
|---|---|---|---|
| `TYPESAFE_API_KEY` | `classify-line` (provider `jev`) | optional; required for live Jev classification | TypeSafe account |
| `ANTHROPIC_API_KEY` | `classify-line` (provider `llm`) | optional; required for live LLM classification | Anthropic account |
| `LLM_MODEL` | `classify-line` (provider `llm`) | required with `ANTHROPIC_API_KEY`; no default in code | owner's choice of a current Claude model id (re-verify against current docs, D-15) |
| `ALLOWED_ORIGINS` | `classify-line` (CORS allow-list) | required for any browser use | the deployed app origin(s), comma-separated, no paths |
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | `classify-line` (auth check + RPCs) | required; platform-injected | platform, not the owner |

Missing-secret behavior: 503 `{status:"unavailable", reason:"missing_secret"|"model_not_configured"|"server_not_configured"}`
before any reservation, so nothing is charged; values are never logged or returned. Only public configuration goes
in frontend env; backend secrets never use public prefixes.

## Auth, storage, and external steps

- Auth providers/confirmation: **anonymous sign-ins must be enabled by the owner.** If the Bolt Database target does
  not support them, that is a named activation blocker (D-11): do not remove JWT auth, disable `verify_jwt`, make the
  function public, or switch databases to work around it. Consider the auth provider's anonymous sign-in rate limit
  and CAPTCHA option as additional abuse controls (not configured by this repo).
- Site URL and callback/recovery routes: not required (no email or OAuth flows).
- Buckets: not required.
- Realtime: not required.
- Scheduled/long jobs: not required.
- Outside services: TypeSafe (Jev) and Anthropic accounts, only for live classifiers.
- Real integrations: `classify-line` → TypeSafe System One and Anthropic Messages (written, never called).
  Explicit demos/stubs: `mock` and `keyword` classifiers (local, network-free; the app default).

## Acceptance checks and receipts

All pending. Use synthetic data and authorised accounts only.

| Check | Expected result | Outcome / receipt |
|---|---|---|
| Import/install/build | intended branch loads; `npm ci` and `npm run build` pass | pending (D-1, D-2, D-19) |
| Function static check | `deno check supabase/functions/classify-line/index.ts` and `deno lint supabase/functions` pass | pending (D-16) |
| Schema | both migrations applied in order; tables, RLS enabled, `model_call_log_select_own` policy, table grants, RPC `execute` only for `service_role` | pending (D-8) |
| Quota RPCs | parallel reservations at the global cap admit exactly the cap; duplicate outcomes as listed; user B cannot finish user A's row | pending (D-9) |
| Function round trip | app (after opt-in) reaches `classify-line` and receives an A18 response | pending (D-10) |
| Auth/isolation | no token or anon key as Bearer → 401; user B cannot read user A's `model_call_log` rows via the anon client | pending (D-10) |
| Missing secret | 503 with reason, no value disclosure, no `model_call_log` row created | pending (D-10) |
| CORS | allowed origin preflight 204; other origin 403 | pending (D-10, D-18) |
| Anonymous sign-in | enabled on the target; first remote classify creates an anonymous user | pending (D-11) |
| Uploads, webhooks, jobs | not required | n/a |
| Publish | not requested | n/a |

## One prompt after GitHub import

The checks above have no receipts yet, so only the inspection prompt is provided. A "Provision backend" prompt is
added once D-1, D-2, D-8..D-11 and D-16 have recorded outcomes.

### Inspect and prepare only

> Read BOLT-HANDOFF.md and inspect the imported source at the intended branch/revision. The target is a **fresh Bolt
> Database**. Compare the listed resources with the implemented files: the two migrations in
> `supabase/migrations/` (in filename order), the `classify-line` function in `supabase/functions/classify-line/`
> with `verify_jwt = true` from `supabase/config.toml`, and the browser adapter `src/providers/remote.ts`. Confirm
> whether this target supports anonymous sign-ins, injects `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` into
> functions, and can deploy a function that imports a sibling file (`./contract.ts`) and a pinned `npm:` package.
> Report concrete deployment gaps and owner/external blockers, including the secret names `TYPESAFE_API_KEY`,
> `ANTHROPIC_API_KEY`, `LLM_MODEL` and `ALLOWED_ORIGINS` the owner would need to enter. Preserve the app design and any
> existing database/data. Prepare a reviewable setup plan with actual file/resource names and the pending checks. Do
> not create or change cloud resources, apply migrations, deploy functions, enter secrets, enable schedules, or
> publish. Do not describe proposed resources or unexecuted checks as complete.

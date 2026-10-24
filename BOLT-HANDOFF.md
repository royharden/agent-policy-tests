# Bolt infrastructure handoff: Agent NOT-List Builder (agent-policy-tests)

**Status: specification only.** Milestone M1 (scaffold) is the only code in this repo. The database, migrations,
edge function and remote provider below are **proposed** (PLAN M7) and do not exist yet. No check in this file has
run. This file is completed in M7; until then use only the "Inspect and prepare only" prompt.

## Target and readiness

- Repository / branch / prepared revision: local git repo `agent-policy-tests`, branch `main`; no remote yet (a GitHub
  remote is required before Bolt import).
- App root: repository root.
- Database: **Bolt Database** (PLAN A2). The only server state is the live-classifier quota and call ledger.
  Policies, answers, fixtures and approvals stay in the browser (memory, `localStorage` drafts, JSON export).
- Target: fresh, empty Bolt Database; nothing to preserve.
- Existing baseline / applied migrations: none (no migration has ever been applied).
- Hosting: Bolt hosting (proposed; final origin needed for CORS, D-18).
- Publication: prepare only.
- Bolt action: inspect and prepare only.
- Status: specification only / implementation incomplete (M1 of M8); infrastructure pending.
- Owner prerequisites: GitHub remote and access; anonymous sign-ins enabled on the auth provider (D-11); TypeSafe
  and Anthropic API keys only if live classifiers are wanted.

## Build and connection

| Item | Exact command or configuration name |
|---|---|
| Runtime / package manager | Node >= 20, npm; lockfile not generated yet (D-19) |
| Frozen install / dev | `npm ci` (after D-19) / `npm run dev` |
| Build / output | `npm run build` (= `npm run build:runner && tsc -b && vite build`) → `dist/` incl. `policy-runner.mjs` |
| Type/lint/tests | `npm run typecheck`, `npm run lint`, `npm test` — never run (D-1) |
| Client file / public env names | `src/lib/supabase.ts`; `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`, `VITE_CLASSIFIER_MODE` |
| Missing config behavior | `supabase` is `null`; the app shows a "Mock mode" banner and uses local classifiers only |

## Database (proposed, M7)

| Order | Exact migration file | Resources / dependencies | Applied status |
|---|---|---|---|
| 1 | `supabase/migrations/20261024210000_model_call_log.sql` (not written yet) | tables `app_limits` (singleton, seeded 30/500/300) and `model_call_log` (no line text); RLS on both | pending |
| 2 | `supabase/migrations/20261024210100_quota_rpcs.sql` (not written yet) | `reserve_model_call`, `finish_model_call` (security definer, `service_role` only) | pending |

- Access model: `model_call_log` select own rows for `authenticated`; no client insert/update/delete; `app_limits`
  service role only.
- Ownership checks: `finish_model_call` updates only the caller's own `reserved` row.
- Extensions/RPC permissions/Realtime: RPC execute revoked from `public`, `anon`, `authenticated`; Realtime not required.
- Seeds: `app_limits` row only (limits, no user data).
- Retry rule: inspect migration tracking, apply only pending changes, preserve existing data; verify timeouts before
  retry and report drift instead of dropping/recreating resources.

## Functions (proposed, M7)

| Name / source | Caller + auth | Input / output | Resources + secret names | Deploy config |
|---|---|---|---|---|
| `classify-line`; `supabase/functions/classify-line/index.ts` (not written yet) | signed-in user via Supabase anonymous sign-in JWT, requested only on explicit remote opt-in; handler verifies with `auth.getUser(token)` | `{request_id, provider: jev\|llm, line}` (body ≤ 4 KiB, line ≤ 300 chars) → `{request_id, status: ok\|fallback, label, confidence\|null, provider, model, reason?, duplicate?}` | `app_limits`, `model_call_log` via RPCs; `TYPESAFE_API_KEY`, `ANTHROPIC_API_KEY`, `LLM_MODEL` | `verify_jwt = true` in `supabase/config.toml` |

- CORS/preflight: allow-list of the deployed app origin (D-18); CORS is not authentication.
- Identity/ownership and abuse controls: per-user 30/day and global 500/day count caps under one serialised lock;
  idempotent `request_id` with input digest (PLAN A16/A17).
- Paid API limits: count caps server-side; cost recorded as an estimate only. The $2 hard dollar cap applies to the
  local eval ledger, not the deployed function.
- Webhooks: not required.
- Platform credentials: Supabase URL and service-role credential are platform-injected (verify availability); never
  copied from another project.

## Server secrets to enter through settings

| Name | Consumer | Required / optional | Owner source |
|---|---|---|---|
| `TYPESAFE_API_KEY` | `classify-line` (provider `jev`) | optional; required for live Jev classification | TypeSafe account |
| `ANTHROPIC_API_KEY` | `classify-line` (provider `llm`) | optional; required for live LLM classification | Anthropic account |
| `LLM_MODEL` | `classify-line` (provider `llm`) | required with `ANTHROPIC_API_KEY`; no default | owner's choice of a current model id |

Missing-secret behavior (planned): 503 `{status:'unavailable', reason:'missing_secret'|'model_not_configured'}` before
any reservation; never a fabricated label. Only public configuration goes in frontend env; backend secrets never use
public prefixes.

## Auth, storage, and external steps

- Auth providers/confirmation: anonymous sign-ins (if unsupported on the target, this is a named activation blocker,
  D-11 — do not remove JWT auth).
- Site URL and callback/recovery routes: not required (no email or OAuth flows).
- Buckets: not required.
- Realtime: not required.
- Scheduled/long jobs: not required.
- Outside services: TypeSafe (Jev) and Anthropic accounts, only for live classifiers.
- Real integrations: none yet. Explicit demos/stubs: `mock` and `keyword` classifiers (local, network-free).

## Acceptance checks and receipts

All pending. Use synthetic data and authorised accounts only.

| Check | Expected result | Outcome / receipt |
|---|---|---|
| Import/install/build | intended branch loads; `npm ci` and `npm run build` pass | pending |
| Schema | both migrations applied; tables, RLS and RPC grants as above | pending (not written) |
| Function round trip | app reaches `classify-line` with a contract response | pending (not written) |
| Auth/isolation | anon key as Bearer → 401; user B cannot read or finish user A's rows | pending |
| Missing secret | 503 with reason, no value disclosure, nothing charged | pending |
| Uploads, webhooks, jobs | not required | n/a |
| Publish | not requested | n/a |

## One prompt after GitHub import

### Inspect and prepare only

> Read BOLT-HANDOFF.md and inspect the imported source at the intended branch/revision. Compare
> proposed resources with implemented files, reconcile unknown migration baselines through
> read-only history/schema inspection when access is available, and report concrete deployment
> gaps and owner/external blockers. Preserve the app design and existing database/data. Prepare
> a reviewable setup plan with actual file/resource names and pending checks. Do not create or
> change cloud resources, apply migrations, deploy functions, enter secrets, enable schedules,
> or publish. Do not describe proposed resources or unexecuted checks as complete.

The "Provision backend" prompt is added in M7, once migrations and the function exist and their local checks have
results to record.

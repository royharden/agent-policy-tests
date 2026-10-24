# Deferred validation

This project is being built in **Dirty Mode**: source only, static checks only. Nothing below has run. A row leaves
this list only when its command has actually been executed and its outcome recorded (with the date) in the
"Outcome" column. Until then, nothing it covers may be described as "tested" or "working".

Static checks that *were* performed during construction (source inspection, `JSON.parse` of data files, a
type-strip + `node --check` syntax parse of erasable `.ts` files, SHA-256 of data files with `node:crypto`) are
recorded in the milestone reports, not here.

## Core list (PLAN §3/§7: Claude §6 D-1..D-18, refreshed D-10/D-15, plus D-19)

| # | What | Why deferred | Exact command or steps | Outcome |
|---|---|---|---|---|
| D-1 | All vitest suites, ESLint and the type checker | Written, never executed (no install in Dirty Mode; tsc/eslint not available locally) | `npm ci && npm run typecheck && npm run lint && npm test`; fix every failure | pending |
| D-2 | Build (Vite + esbuild runner) | Never run | `npm run build`; confirm `public/policy-runner.mjs` and `dist/policy-runner.mjs` exist and `dist/index.html` loads | pending |
| D-3 | Runner is dependency-free | Assumed from the esbuild config (M8) | Inspect `dist/policy-runner.mjs` for any import that is not `node:*`; copy it with an exported bundle into an empty directory and run `node policy-runner.mjs` with Node 20, no `node_modules`, network disabled | pending |
| D-4 | Normaliser and guard vs the gold dev set | Source-inspected only; runtime behaviour unverified | `npm run eval -- --split dev`; fix; record named failures in `results/results.md` | pending |
| D-5 | Held-out published number | Not run | Roy reviews a 20-row sample of the held-out gold; thresholds and B4 frozen and hashed; then exactly one `npm run eval -- --split heldout`; confirm manifest hashes match and the run is appended to `results/heldout-runs.jsonl` | pending |
| D-6 | Runner exit codes | Test source written for `main()`, never executed; real CLI never run | Run `npm test` (runner tests), then on a real exported bundle: unchanged → exit 0; flip one expected verdict in `fixtures.json` → 1; corrupt `policy.json` → 1 with a structured error; a Gap with `--strict` → 2 | pending |
| D-7 | Browser UI and approvals journey | Never rendered | `npm run dev` with no `.env`; walk PLAN/Claude §1.3 in mock mode: load sample answers, compile, free text, fixtures, replay, report, acknowledge, edit Q12 (approvals stale, export disabled), re-replay, export; reload (drafts survive); import an oversized and an invalid JSON file (structured errors) | pending |
| D-8 | Migrations | Never applied (not written until M7) | Bolt applies `supabase/migrations/20261024210000_model_call_log.sql` then `20261024210100_quota_rpcs.sql` to a fresh Bolt Database; verify tables, RLS enabled, policies, and that RPC execute is granted only to `service_role` | pending |
| D-9 | Quota RPC concurrency and idempotency | Untested | Against the applied schema: parallel reservations from two users at the global cap (exactly the cap succeeds); duplicate `request_id` with the same digest; a crash after reserve stays charged; user B cannot finish user A's reservation | pending |
| D-10 | `classify-line` edge function | Never deployed | Deploy; anonymous-session JWT accepted; anon key as Bearer → 401; over cap → 429; completed duplicate with the same `request_id` and input digest → 200 with the stored label and `duplicate: true`; in-flight duplicate → 409 `pending`; same id with a different digest → 409 `conflict`; missing secret/model → 503 before any reservation; CORS allows only the app origin | pending |
| D-11 | Anonymous sign-in on the Bolt target | Availability unverified | Owner enables anonymous sign-ins; sign in from the app after opting into a remote provider. If unsupported, record it as a named activation blocker — do not remove JWT auth or switch databases | pending |
| D-12 | Live classifiers (Jev, LLM) | Adapters unexercised | Keys in the shell only; `npm run eval -- --live --split dev` to choose thresholds, then held-out once; `callledger` total ≤ $2 | pending |
| D-13 | B3 live LLM judge baseline | "not yet measured" | Three live runs via `npm run eval -- --live`; record flakiness (agreement across runs) and cost | pending |
| D-14 | Shared-contract module field names (`evalkit`, `rulings`, `callledger`) | Aligned with shared-contract §3 from the file text only | Check whether a TypeScript port of these modules exists; reuse it or keep the local versions and record the decision | pending |
| D-15 | Provider facts | Jev endpoint/model/price from the 2026-10-13 guide; Claude model ids not verified | Re-read docs.typesafe.ai and Anthropic model docs; confirm `jev-1.13.0`; pin the edge `LLM_MODEL` secret value; pin eval models in `eval/config/models.json` (hashed into results); update the dated price table | pending |
| D-16 | Deno edge function dependencies | Pinned imports assumed resolvable; ESLint ignores `supabase/functions/**` | `deno check supabase/functions/classify-line/index.ts` and `deno lint supabase/functions` when Deno is available; confirm no import from `src/` or another function | pending |
| D-17 | Sensitivity performance | ≤ 200 × 2,000 guard calls assumed fast enough | Time delete-one sensitivity in the browser on a 200-rule / 2,000-fixture policy; move to a Web Worker only if it exceeds ~2 s | pending |
| D-18 | CORS origin | Assumed app origin | After hosting is chosen, set the function's allow-list to the deployed origin and re-run the CORS part of D-10 | pending |
| D-19 | `package-lock.json` | Cannot be produced without an install | `npm install --package-lock-only` (resolves the exact pinned versions in `package.json`), commit the lockfile, then `npm ci` | pending |

## Added during construction (M1)

| # | What | Why deferred | Exact command or steps | Outcome |
|---|---|---|---|---|
| D-20 | `tsconfig.json` + `tsconfig.node.json` project layout under `tsc -b` | Follows the Vite 5.4 template pattern (`noEmit` projects, `tsBuildInfoFile` under `node_modules/.tmp`); never compiled | `npm run typecheck`. If TypeScript reports that a referenced project must be `composite` (TS6306/TS6310), set `"composite": true, "emitDeclarationOnly": true, "declarationDir": "./node_modules/.tmp/node-types"` in `tsconfig.node.json` and drop its `noEmit` | pending |
| D-21 | ESLint static bans actually fire (PLAN A23) | Flat config, esquery selectors and typed-lint project list never loaded | `npm run lint` passes on the tree; then, as throwaway local edits that are reverted: a regex literal in `src/policyfix/match.ts`, `import 'node:fs'` and `import 'react'` in a `src/policyfix/` file, `import('child_process')` and `eval('1')` in a `src/` file, and an `enum` in any `.ts` file — each must produce a lint error | pending |
| D-22 | Zod issue → structured error mapping | Mapping in `src/policyfix/errors.ts` assumes zod 3.23.8 issue shapes (`received: 'nan'`, `expected: 'integer'`, `unrecognized_keys`, `invalid_union_discriminator`, custom `params.code`) | Covered by `tests/action.test.ts` under D-1: `npx vitest run tests/action.test.ts` | pending |
| D-23 | `@noble/hashes` 1.5.0 subpath imports | `@noble/hashes/sha256` and `@noble/hashes/utils` assumed to resolve in Vite, vitest, tsx and esbuild | `npx vitest run tests/digest-vectors.test.ts`, then `npm run build` (D-2) | pending |
| D-24 | `.tsx` files (`src/main.tsx`, `src/ui/App.tsx`, `src/ui/ModeBanner.tsx`) | The type-strip syntax check cannot parse JSX; inspected by eye only | `npm run typecheck && npm run lint`, then `npm run dev` with no `.env`: the page shows the "Mock mode" banner and no console error | pending |
| D-25 | Canonicaliser vs hard-coded digest vectors | Expected hashes were computed with `node:crypto` over hand-derived canonical strings; `canonicalJson` itself never ran | `npx vitest run tests/digest-vectors.test.ts`; on a mismatch, decide whether the code or the hand-derived string is wrong — never regenerate vectors from the code under test | pending |
| D-26 | Large-input cap tests | `tests/action.test.ts` builds ~16 MiB strings and 2,000-row arrays; memory/time on CI unmeasured | Run D-1 on the slowest target machine; the vitest timeout is 30 s | pending |

## Added during the M1 review rework

| # | What | Why deferred | Exact command or steps | Outcome |
|---|---|---|---|---|
| D-27 | `tests/gold-integrity.test.ts` | Never run, never type-checked, never linted (only the type-strip syntax parse) | `npx vitest run tests/gold-integrity.test.ts`, `npx eslint tests/gold-integrity.test.ts` and `npm run typecheck` (D-1 covers `tests/`); fix every failure | pending |
| D-28 | Product schema vs gold `invalid` labels | `tests/gold-integrity.test.ts` checks `invalid` rows against its own local copy of the CONTRACTS C1 rules, not against `src/policyfix/action.ts`, so the two can drift | Once `src/policyfix/action.ts` is stable, add a test that runs the product action schema over every gold row (dev and held-out) and asserts it rejects exactly the rows whose `expected` is `invalid` and accepts every other row; run it with `npx vitest run` | pending |
| D-29 | Roy's held-out sample review | Requires the owner; not something an agent can perform | Before the published held-out run (D-5), Roy reviews a 20-row sample of the held-out gold (`eval/gold/actions.heldout.jsonl`, `eval/gold/classifier.heldout.jsonl`; drawn with the `seed` recorded in `eval/gold/MANIFEST.json`) against `eval/gold/RUBRIC.md` and records the outcome here; D-5 must not run until this row is closed. Any label correction changes the file hashes, so re-generate `eval/gold/MANIFEST.json` before D-5 | pending |

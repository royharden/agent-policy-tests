# Agent instructions: agent-policy-tests

Product repo for the Agent NOT-List Builder (S21). Local git only; no remote, never pushed. Build plan and contracts
live outside this repo (`../PLAN.md`, `../CONTRACTS.md`); this file states the rules that travel with the code.

## Synthetic data and no real actions (binding)

- **All data is synthetic.** Paths use invented roots (`/workspace/demo`, `C:\workspace\demo`, `/home/dev`); hosts and
  domains use the reserved `.test` TLD (`*.example.test`); recipients are `@example.test`. Never add real hostnames,
  customer names, real repositories, real credentials or production data to fixtures, gold sets, docs or tests.
- **Nothing executes a fixture action.** Shell commands, SQL, git, HTTP, payments and messages are data. They are
  normalised lexically and replayed only through in-memory fake tools. Never add code that runs a command
  (`child_process`, `eval`, `new Function`), opens a socket, reads the real filesystem/environment during
  normalisation, or resolves DNS. ESLint enforces the main bans (PLAN A23); review enforces the rest.
- **No real model calls without explicit authorisation.** Live classifiers (`jev`, `llm`, B3 judge) need keys from the
  shell environment and the `--live` flag; the mock and keyword paths are network-free. Never put a key in source,
  `.env.example`, tests or docs, and never give a server secret a `VITE_` prefix.
- Do not bundle third-party benchmark rows (e.g. AgentHarm) or copy code from AGPL/BUSL/unlicensed projects; prior art
  is idea-only (README "Prior art").

## Layout

- `src/policyfix/` — framework-free core (zod + @noble/hashes only; no React, DOM, `node:` or Deno imports).
- `src/lib/` — app adapters (nullable Supabase client). `src/ui/` — React UI. `src/main.tsx` — entry.
- `tests/` — vitest suites; every test names the bug it catches (`// what_bug_this_catches:`).
- `eval/` — gold data and the eval command; `eval/gold/**` is frozen once its manifest has `frozen_at`.
- `docs/DEFERRED-VALIDATION.md` — everything not yet executed, with the exact command to run it.

## Commands (none has been run yet; see docs/DEFERRED-VALIDATION.md)

`npm ci` · `npm run dev` · `npm run typecheck` · `npm run lint` · `npm test` · `npm run build` · `npm run eval`

## Style

Erasable TypeScript only (no `enum`, `namespace`, parameter properties, `import =`), ESM, strict types, explicit
return types on exported functions, no regex in `src/policyfix/match.ts` / `glob.ts`. Wording rule: nothing is
"tested" or "working" until the matching deferred check has actually run.

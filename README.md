# Agent NOT-List Builder

Turn an agent's NOT list ("never delete outside the project", "never push to main", "never send money over $50")
into an executable, regex-free policy, generate tests for it, replay them through fake tools, and export a bundle
with a dependency-free CI runner.

## Status — read this first

**Built in Dirty Mode: never installed, built, tested or run.** This repository contains source only. No
`npm install` has been run, so there is no lockfile yet; the type checker, linter, test suites, build and eval have
never executed. Every unverified behaviour is listed with its exact activation command in
[`docs/DEFERRED-VALIDATION.md`](docs/DEFERRED-VALIDATION.md). This README contains no metrics: none have been
measured.

What exists now (milestone M1, scaffold and core contracts):

- Project configuration (Vite + React + TypeScript, vitest, ESLint flat config with the static bans).
- `src/policyfix/`: Zod strict schemas for the seven action kinds, the regex-free match AST, rules, manual items,
  dispositions, policies and fixtures; named caps; pre-parse byte and depth checks; structured errors; canonical
  JSON + SHA-256 digests; version constants.
- A nullable Supabase client and an app shell that shows a mock-mode banner when no Supabase config is present.
- Tests for the schemas/caps, digest vectors and the environment contract (written, not run).

Not built yet: questionnaire, templates, compiler, matcher, normalisers, guard, fixture generator, replay, scoring,
free-text classifier, approvals, export bundle, runner, eval command, Supabase migrations and edge function.

## What it will do (planned)

1. Answer a 12-question questionnaire (or load sample answers) and add free-text NOT lines.
2. Compile answers into rules over a structured match language (no regex), with every answer given a disposition.
3. Normalise shell (posix, PowerShell, cmd), paths, URLs, SQL and git lexically against a synthetic evaluation
   context; anything it cannot analyse becomes `ask`, never `allow`.
4. Generate prohibited and permitted fixtures plus mutated evasions, replay them through fake tools, and report
   Pass / Fail / Gap per NOT item.
5. Export `policy.json`, `fixtures.json`, `report.json`, `MANUAL-ITEMS.md` and `policy-runner.mjs` for CI.

Replay checks this evaluator only. It is not a security boundary and does not prove that an agent enforces the
policy.

## Commands (not yet run)

```sh
npm ci                # needs a lockfile first: npm install --package-lock-only (D-19)
npm run dev           # app in mock mode without .env
npm run typecheck
npm run lint
npm test
npm run build         # build:runner (M8) + tsc -b + vite build
npm run eval          # M8
```

Node 20 or newer. Copy `.env.example` to `.env` only when connecting a Supabase project; without it the app runs in
mock mode with local classifiers.

## Configuration

Public (browser) variables: `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`, `VITE_CLASSIFIER_MODE`
(`keyword` default, `mock`; remote modes need Supabase and an explicit opt-in). Note the two different defaults:
copying `.env.example` sets `VITE_CLASSIFIER_MODE=mock`, while an unset (or unknown) `VITE_CLASSIFIER_MODE` falls
back to the `keyword` classifier. The "mock mode" banner is separate: it reflects missing Supabase config, not the
classifier choice. Server secrets are listed in [`BOLT-HANDOFF.md`](BOLT-HANDOFF.md) and never use a public prefix.

## Prior art (ideas only)

Ideas from frenum (MIT), Microsoft Agent Governance Toolkit (MIT), Codex execpolicy (Apache-2.0) and agentguard
(Apache-2.0); AgentWard (BUSL) was read only. No code is copied from these or from AGPL/unlicensed projects.

## Licence

MIT — see [`LICENSE`](LICENSE).

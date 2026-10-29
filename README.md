# Agent NOT-List Builder

Turn a questionnaire and an agent's NOT lines into structured policy rules, generated tests and an exportable runner.
Review what is executable, what is blocked and what still needs a human.

**Source constructed; never installed, built, tested or run.** This is a Dirty Mode source delivery. No runtime,
browser, evaluation, model-call or infrastructure result is claimed. The lockfile is still absent. All pending work
has exact activation steps in [DEFERRED-VALIDATION.md](docs/DEFERRED-VALIDATION.md); [results/results.md](results/results.md)
is an unmeasured placeholder. Coding agents wrote this source; source inspection and syntax parsing are the only
checks performed. Type checking, lint, tests and independent runtime validation remain pending.

## Later local activation

Node 20+ and npm are intended. After the owner opens the runtime-validation phase, from this repository:

```sh
npm install --package-lock-only   # D-19: resolve/record exact pinned dependencies; review and commit the lockfile
npm ci
npm run typecheck
npm run lint
npm test
npm run build                    # bundles public/policy-runner.mjs before tsc/Vite
npm run dev                      # use the machine's assigned local port when starting a server
npm run eval                     # offline dev evaluation; not held-out, no keys/network
```

These commands have not run and may expose source/dependency issues. The mock journey requires no account or key.
`npm run dev` alone does not generate the runner asset; build it with `npm run build:runner` before downloading a
bundle from dev mode. Missing/non-success/empty runner responses produce an explicit export error.

## Intended review journey

Load sample answers in either synthetic context; inspect the twelve answers; add and classify `never run terraform
destroy`, `never push to the hotfix branch`, and `never be rude to customers`. Review extracted parameters, compile,
generate fixtures and replay through fake tools. Inspect Pass/Fail/Gap, local versus policy expectations, fake-effect
logs, answer/executable coverage, sensitivity and raw baseline comparisons. Approve free-text-derived rules and
acknowledge manual markers. Manual acknowledgement keeps Gap. Edits stale the report and affected approvals.

Export writes seven entries: policy.json, fixtures.json, report.json with approvals, MANUAL-ITEMS.md,
policy-runner.mjs, README.md and bundle-manifest.json. The builder recomputes outcomes and hashes final bytes.
Current Fail reports may export visibly; readiness does not hide a failing policy. The standalone runner ignores
saved report outcomes and recomputes policy plus fixtures, with no dependencies/network after its build:

```sh
node policy-runner.mjs --strict
```

Invalid input or Fail exits 1; otherwise strict Gap exits 2; otherwise 0. Policy unmatched ask is a separate setting.
No fixture action is executed. This evaluator is **not a security boundary**, and replay does not prove agent enforcement.

## Architecture and data

React/Vite UI → framework-free TypeScript compiler/templates → bounded POSIX/PowerShell/cmd normalization and
regex-free matching → guard → fixtures, fake replay, scoring → digest-bound review → byte-hashed export.
The local eval command compares raw substring/prefix baselines, frozen dev-authored B4 regex, the guard and local
classifiers. B3 and live classifier evidence are **not yet measured**. Mock is a fixed demo stub excluded from accuracy.
All data is synthetic. Gold was builder-authored and frozen before normalization, rather than independently labelled.

Inputs can be saved in localStorage or imported as Draft JSON. Reports, approvals, classifier replies and remote opt-in
reset after reload/import. Policies and review state stay client-side. See [GRAMMAR](docs/GRAMMAR.md),
[QUESTIONNAIRE](docs/QUESTIONNAIRE.md), [TRAPS](docs/TRAPS.md), [EVALUATION](docs/EVALUATION.md) and
[LIMITATIONS](docs/LIMITATIONS.md).

Two deliberate spec deviations: a singleton `app_limits` table accompanies `model_call_log` for atomic count caps;
fixture `expected` is represented by `expected_local` and optional `expected_policy` to preserve conflict ownership.

## Configuration and future providers

Without Supabase configuration the app shows mock mode and uses local classifiers. Browser variables are only
`VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`, `VITE_CLASSIFIER_MODE`. Unset classifier mode defaults to keyword;
copying .env.example explicitly selects mock. Remote mode requires explicit opt-in and anonymous sign-in.

Bolt Database is the selected backend path. Migrations, JWT-protected classify-line, quota RPCs and browser adapter
exist as source only. Anonymous auth support, RLS/isolation, CORS, quota behavior and provider contracts have no
execution receipts. [BOLT-HANDOFF.md](BOLT-HANDOFF.md) is the single infrastructure inventory and inspection prompt.
No cloud resources, GitHub remote, deployment or publication were created.

Only a future authorized `--live` eval reads shell `TYPESAFE_API_KEY`/`ANTHROPIC_API_KEY`; no credential file is read.
It requires dated model/price verification, dev-calibrated thresholds for live held-out and durable pre-call reservations
under a per-run $2 estimate cap. Failed/crashed/unknown-usage calls stay charged; provider usage/cost unknowns stay null.
Jev is pinned to 1.13.0. Dated Haiku 4.5 is legacy; availability/pricing must be reverified. No paid call was made.

Roy's held-out 20-row sample review is still pending. The eval command requires a matching owner receipt and claims
attempts atomically; a later attempt needs a recorded rerun reason. Nothing in this repo fabricates that receipt.

## Prior art and licence

Ideas only: frenum and Microsoft Agent Governance Toolkit (MIT), Codex execpolicy and agentguard (Apache-2.0).
AgentWard (BUSL) was read only. No AGPL/unlicensed implementation or benchmark rows were copied. MIT; see LICENSE.

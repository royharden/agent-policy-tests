# Limitations and activation status

All behavior is runtime-unverified. Source was constructed in Dirty Mode; dependencies, tests, type checking, lint,
builds, browser flows, exported runners, migrations and provider calls have not run. The deferred ledger names the
remaining checks. No observed gold failures exist yet; `eval/run.ts` will publish named mismatches with ids/traps in
`results/results.md` and full JSONL observations after an authorized run. No success rate is claimed.

This evaluator is **not a security boundary**. Fake replay proves only this evaluator's behavior on supplied inputs;
it does not prove an agent enforces a rule. It never executes a shell/SQL/git action, sends a fixture HTTP request,
payment or message, or reads real filesystem/environment/DNS/repository state during normalization. An `ask` is blocked
pending review; this app has no approve-and-execute facility.

The lexical grammar is bounded and incomplete; see `GRAMMAR.md`. Unknown constructs ask, while ordinary unmodeled
executables' internal effects are outside the model. Symlinks, mounts, runtime globs, shell configuration, git hooks
and network use hidden inside package managers are not resolved. SQL recognizes only its documented tautologies.
Regex-free matching does not make this a sandbox. B4 is a separate intentionally limited regex comparator.

Gold was authored by the builder before the normalizer, not independently labelled. Roy's 20-row held-out sample
review is pending. Generated fixtures measure template self-consistency. Difficult parameter choices can legitimately
lack two successful isolated permitted/prohibited witnesses; those remain Gap. Conflict rows cannot fill the minimum.

Only inputs survive draft reload/import. Reports, approvals, classifier replies, auth and remote opt-in reset. This
prevents an imported report from becoming evidence. A free-text source removed from every surviving policy field
cannot be reconstructed by the standalone runner; preserve the original NOT list when auditing completeness.

Local live costs are estimates from reported usage and a dated price table. Unknown/error/crashed calls retain their
worst-case reservation. The $2 pre-call cap depends on verified model prices and conservative token bounds; unexpected
provider usage is recorded as a bound breach and stops further calls. It is not a provider billing-account spending
limit. No live model has been called, calibrated or shown to outperform keyword. Jev remains pinned to 1.13.0; the
dated Haiku 4.5 model is legacy and availability/pricing must be reverified. Confidence thresholds are uncalibrated.

The deployed M7 function has count caps, not a dollar cap. Its provider wire shapes, auth gateway behavior, CORS,
quota concurrency/idempotency, anonymous sign-in and database policies remain pending. Inspect `BOLT-HANDOFF.md` and
D-M7-1…9 before activation. No cloud resources were provisioned, and no repository was pushed or published.

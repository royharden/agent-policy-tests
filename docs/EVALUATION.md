# Reproducing evaluation later

Nothing in this document has been executed. First close the source-only construction phase, generate the lockfile
and complete D-1/D-2. From the inner repository, `npm run eval` defaults to the dev split and no network/keys. It
verifies the exact bytes of every file in `eval/gold/MANIFEST.json`, evaluates frozen reference answers per context,
and writes `results/results.md` plus an appended `results/results.jsonl` record. Seeded order is deterministic.

Action comparisons include B1 raw substring, B2 raw prefix, frozen B4 regex and the structured guard. Baselines use
the same answers/context without the policy normalizer. Their wins, ties and regressions are computed, never
presumed. B4 was authored in one source pass from dev rows only, without execution. Its enclosing observed interval
was 2026-10-24 22:34:52–22:38:16 UTC, including unrelated construction; exact active effort was not measured. This is
within the 30-minute effort cap. Do not tune it on held-out outcomes. Both descriptors and source bytes are hashed.

Classification reports keyword and, only after activation, Jev/LLM. Mock is a fixed demo stub excluded from accuracy.
The results contain routed labels, raw labels, confidence, abstentions, per-label precision/recall/F1, accuracy among
non-abstentions, label false compiles and actual rule false compiles. Raw predictions support dev threshold selection;
calibrate only on classifier.dev.jsonl and record that file hash in eval/config/thresholds.json. Uncalibrated remote
outputs remain manual. Injection screening and code parameter extraction remain active for every provider.

## Held-out owner review and single publication

After Roy authorizes sample review, `npm run eval -- --sample-heldout` prints a deterministic 20-row sample with its
manifest digest and ids; it makes no model calls or evaluation claims. The sample is drawn from the combined held-out
action/classifier ids with the manifest seed. Roy reviews it against RUBRIC.md. Only after Roy approves, record a
single JSONL review event in `results/heldout-runs.jsonl` with fields `kind:"owner-review"`, `reviewer:"Roy"`,
`approved:true`, the exact `manifest_sha256`, exact `sample_ids`, and the actual ISO `reviewed_at`. No receipt exists
yet; do not fabricate one. D-29 remains pending until this happens. This local owner record is not cryptographic identity.

`npm run eval -- --split heldout` requires the matching review event. The command atomically appends an attempt before
evaluating; a failed/crashed attempt still counts as exposure. Any later attempt requires a nonempty
`--rerun-reason "specific reason"`, preserved with results. Exclusive journal locks serialize attempt claims; they do not hold exclusivity throughout evaluation. A stale
crash-left lock requires operator inspection; there is no automatic lock takeover. Corrections to frozen labels
require an authorized rubric/manifest revision and a documented reason, never fitting expected values to the guard.

## Live models and ledger

No live run is currently authorized or performed. At later activation, reverify model availability, request shapes,
prices and token bounds. Record dated verification in `eval/config/models.json` as `activation_status:"verified: …"`.
Only explicit `--live` reads `TYPESAFE_API_KEY`/`ANTHROPIC_API_KEY` from the shell; no credential file is read. Live
held-out also requires dev-calibrated thresholds bound to the frozen dev classifier file. Never tune on held-out.

Each injected provider call durably reserves conservative worst-case cost before fetch, with one 15-second attempt,
no automatic retry and a per-run $2 cap. Reservations include serialized UTF-8 bytes plus 8,192 protocol tokens at
twice input rate and bounded output cost; verify these assumptions before paid activation. Error/unknown-usage calls
retain their reservation. Successful reported usage settles the estimate; a breach retains the greater cost and
halts further calls. `results/live/calls.jsonl` is ignored by git and records run/span/provider/model/prompt hash,
option order, repeat identity, raw usage, reported input/output/cached/reasoning tokens, latency, null TTFT, retries,
dated estimates and charges. Missing provider fields remain null. A failed finish leaves a durable charged reservation.

Cache identity includes exact question/body, model, explicit Choice option order and B3 run/row/repeat. A repeated
call in a run reuses its result/error; pending calls do not retry. Cache hits are counted and cost no new request.
B3 requires three complete independent draws on every schema-valid action; incomplete trials retain named errors
and no aggregate accuracy. Variability uses valid-action rows only. Schema-invalid actions are rejected identically
before every baseline, including B3, and require no model call. B3 is not yet measured in this source delivery.

## Metrics and bundle semantics

Every rate retains `k/n`; zero denominators display N/A. Exact verdict requires equality. Blocked means deny/ask
(schema invalid also counts blocked in gold). Evasion uses the frozen explicit flag only on prohibited rows;
opaque rows are reported separately. False-block and permitted-allow rates use permitted rows. Per-trap counts,
named failures and all comparisons are preserved. Reports separate answer/executable/deciding-rule coverage,
shadowed rules and delete-one sensitivity; the fixed opaque fallback is excluded from removable-rule denominators.

**Deliberate spec deviation:** fixture `expected` is realized as immutable `expected_local` plus optional
`expected_policy`. Local examples are checked in owning-rule isolation with unmatched allow. Only declared conflict
ownership may override composition; undeclared blocking is Fail. Missing successful isolated minima remain Gap.
Imported sidecar reports are not trusted: runner evaluation reconstructs minima and conflicts from policy/fixtures.

`policy_sha`, `fixtures_sha`, `context_sha` and `engine_version` bind reports; approvals add the M6 source-input digest
and content-bound records. Approvals do not change policy_sha. Export requires current review/acknowledgements;
current Fail reports may export visibly. The builder recomputes outcomes and hashes each final bundle entry's bytes.
Runner invalid input/Fail exits 1; otherwise Gap with CLI `--strict` exits 2; otherwise 0. The policy's unmatched ask
mode is independent of that CLI flag. Unlike tools that use 1 for strict Gap, this runner reserves 2 for that case.

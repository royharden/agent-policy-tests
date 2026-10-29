// Source-only construction: importing this file does not evaluate data or call a provider.
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { validateAction, type Verdict } from '../src/policyfix/action';
import { buildBaselines } from '../src/policyfix/baselines';
import { compile } from '../src/policyfix/compile';
import { guard } from '../src/policyfix/guard';
import { parseReferenceAnswers, summariseAnswer } from '../src/policyfix/questionnaire';
import { QUESTION_IDS } from '../src/policyfix/action';
import { formatRatio, summarizeMetrics, type MetricObservation } from '../src/policyfix/score';
import { classifyLine, type Classification } from '../src/policyfix/freetext/classify';
import { FREE_TEXT_LABELS } from '../src/policyfix/freetext/labels';
import { parseThresholdConfig, thresholdFor } from '../src/policyfix/freetext/thresholds';
import { ENGINE_VERSION } from '../src/policyfix/version';
import { createLedgerTransport, fileJournalStore, ledgerEvents, ledgerSummary, PRICE_TABLE } from '../src/lib/callledger';
import { claimHeldout, classifierMetrics, compareMethods, exactSha256, GoldActionSchema, GoldLineSchema, parseJsonl, seededOrder, verifyManifest, type LabelObservation } from '../src/lib/evalkit';
import { evaluateB4, B4_AUTHORING, B4_RULES } from './baselines/b4-regex';
import { classifyJev, JEV_MODEL } from './providers/jev';
import { classifyLlm } from './providers/llm';
import { judgeB3 } from './providers/b3-judge';
import type { CallReply, ProviderRequest } from './providers/types';

export interface EvalOptions { readonly split: 'dev' | 'heldout'; readonly live: boolean; readonly rerun_reason: string | null; readonly sample_only: boolean }
export function parseOptions(argv: readonly string[]): EvalOptions {
  let split: 'dev' | 'heldout' = 'dev'; let live = false; let reason: string | null = null; let sampleOnly = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--live') live = true;
    else if (arg === '--sample-heldout') { sampleOnly = true; split = 'heldout'; }
    else if (arg === '--split' && (argv[i + 1] === 'dev' || argv[i + 1] === 'heldout')) { split = argv[i + 1] === 'heldout' ? 'heldout' : 'dev'; i += 1; }
    else if (arg === '--rerun-reason' && (argv[i + 1]?.trim().length ?? 0) > 0) { reason = argv[i + 1] ?? null; i += 1; }
    else throw new Error(`Invalid argument ${arg ?? ''}. Use [--split dev|heldout] [--live] [--rerun-reason reason] [--sample-heldout].`);
  }
  if (sampleOnly && live) throw new Error('Sampling never makes live calls.');
  if (sampleOnly && split !== 'heldout') throw new Error('The owner review sample must use the held-out split.');
  return { split, live, rerun_reason: reason, sample_only: sampleOnly };
}

/** Only constructed/invoked by explicit --live. Abort after one attempt; never retry automatically. */
async function send(request: ProviderRequest, key: string, timeoutMs: number): Promise<CallReply> {
  const started = performance.now(); const controller = new AbortController();
  const timer = setTimeout(() => { controller.abort(); }, timeoutMs);
  try {
    const response = await fetch(request.url, { method: request.method, headers: { ...request.headers, [request.auth_header]: request.auth_prefix + key }, body: JSON.stringify(request.body), signal: controller.signal, redirect: 'error' });
    const raw = await response.text();
    let body: unknown = null;
    if (raw.length <= 1_000_000) { try { body = JSON.parse(raw) as unknown; } catch { /* An unparsable answer remains an error, never a fabricated label. */ } }
    return { status: response.ok ? 'ok' : 'error', http_status: response.status, body, latency_ms: performance.now() - started, cached: false };
  } catch { return { status: controller.signal.aborted ? 'timeout' : 'error', http_status: null, body: null, latency_ms: performance.now() - started, cached: false }; }
  finally { clearTimeout(timer); }
}

const ModelsSchema = z.object({ schema_version: z.literal(1), jev: z.string().min(1), llm: z.string().min(1), b3: z.string().min(1), documentation_checked_at: z.string(), activation_status: z.string() }).strict();
interface MethodResult { readonly status: 'measured' | 'incomplete' | 'not yet measured'; readonly observations: readonly MetricObservation[]; readonly errors: readonly { id: string; reason: string }[] }

export async function main(argv: readonly string[], root = fileURLToPath(new URL('../', import.meta.url))): Promise<number> {
  let heldoutClaimed = false; let runId = ''; const journal = fileJournalStore(resolve(root, 'results/heldout-runs.jsonl'));
  try {
    const options = parseOptions(argv); runId = randomUUID();
    const gold = resolve(root, 'eval/gold');
    const manifestText = await readFile(resolve(gold, 'MANIFEST.json'), 'utf8');
    const manifest = await verifyManifest(manifestText, async (name) => new Uint8Array(await readFile(resolve(gold, name))));
    const actionsText = await readFile(resolve(gold, `actions.${options.split}.jsonl`), 'utf8');
    const linesText = await readFile(resolve(gold, `classifier.${options.split}.jsonl`), 'utf8');
    const actions = parseJsonl(actionsText, GoldActionSchema); const lines = parseJsonl(linesText, GoldLineSchema);
    const sampleIds = options.split === 'heldout' ? seededOrder([...actions.map((row) => row.id), ...lines.map((row) => row.id)], manifest.seed).slice(0, 20) : [];
    if (options.sample_only) { process.stdout.write(`${JSON.stringify({ status: 'review sample only; no evaluation', manifest_sha256: manifest.manifest_sha256, sample_ids: sampleIds, rows: [...actions, ...lines].filter((row) => sampleIds.includes(row.id)) }, null, 2)}\n`); return 0; }
    const modelsText = await readFile(resolve(root, 'eval/config/models.json'), 'utf8');
    const thresholdsText = await readFile(resolve(root, 'eval/config/thresholds.json'), 'utf8');
    const models = ModelsSchema.parse(JSON.parse(modelsText) as unknown); const thresholds = parseThresholdConfig(JSON.parse(thresholdsText) as unknown);
    if (thresholds === null || models.jev !== JEV_MODEL) throw new Error('Invalid thresholds or Jev model does not match the pinned adapter.');
    if (options.live && !models.activation_status.startsWith('verified:')) throw new Error('Reverify provider availability/pricing, then record activation_status as verified: <dated evidence> before --live.');
    if (options.live && options.split === 'heldout' && (thresholdFor('jev', thresholds) === null || thresholdFor('llm', thresholds) === null || thresholds.provenance.dataset_sha256 !== manifest.file_hashes['classifier.dev.jsonl'])) throw new Error('Live held-out requires dev-calibrated thresholds pinned to classifier.dev.jsonl.');
    if (options.split === 'heldout') {
      await claimHeldout(journal, { kind: 'attempt', run_id: runId, manifest_sha256: manifest.manifest_sha256, at: new Date().toISOString(), rerun_reason: options.rerun_reason }, sampleIds);
      heldoutClaimed = true;
    }
    const referenceText = await readFile(resolve(gold, 'reference-answers.json'), 'utf8'); const referenceJson: unknown = JSON.parse(referenceText);
    const contexts = (['posix', 'windows'] as const).map((key) => {
      const parsed = parseReferenceAnswers(referenceJson, key); if (!parsed.ok) throw new Error(JSON.stringify(parsed.errors));
      const compiled = compile(parsed.value.answers, [], parsed.value.context, { default_unmatched: parsed.value.default_unmatched });
      if (!compiled.ok) throw new Error(JSON.stringify(compiled.errors));
      return { key, ref: parsed.value, policy: compiled.value.policy, baselines: buildBaselines(parsed.value.answers, parsed.value.context, parsed.value.default_unmatched) };
    });
    const ledger = fileJournalStore(resolve(root, 'results/live/calls.jsonl'));
    const deps = createLedgerTransport({ live: options.live, run_id: runId, store: ledger, credential: (name) => options.live ? process.env[name] : undefined, send, now: () => new Date().toISOString() });
    const methods: Record<string, MethodResult> = Object.fromEntries(['guard', 'B1', 'B2', 'B4', 'B3-1', 'B3-2', 'B3-3'].map((name) => [name, { status: name.startsWith('B3') && !options.live ? 'not yet measured' : 'measured', observations: [], errors: [] }]));
    const observations: Record<string, MetricObservation[]> = Object.fromEntries(Object.keys(methods).map((key) => [key, []]));
    const errors: Record<string, { id: string; reason: string }[]> = Object.fromEntries(Object.keys(methods).map((key) => [key, []]));
    let passingTasks = 0;
    for (const row of seededOrder(actions, manifest.seed)) {
      const context = contexts.find((entry) => entry.key === row.context); if (context === undefined) throw new Error('Unknown gold context');
      const action = validateAction(row.action);
      const add = (method: string, actual: Verdict | 'invalid'): void => { observations[method]?.push({ id: row.id, expected: row.expected, actual, traps: row.traps, evasion: row.evasion }); };
      if (!action.ok) { for (const name of Object.keys(methods)) if (!name.startsWith('B3') || options.live) add(name, 'invalid'); continue; }
      add('guard', guard(context.policy, action.value, context.ref.context).verdict);
      add('B1', context.baselines.B1.evaluate(action.value).verdict); add('B2', context.baselines.B2.evaluate(action.value).verdict);
      add('B4', evaluateB4(action.value, context.ref.answers, context.ref.context));
      if (options.live) for (const repeat of [0, 1, 2] as const) {
        const judged = await judgeB3({ not_list: QUESTION_IDS.map((id) => `${id}: ${summariseAnswer(context.ref.answers, id)}`), action: action.value, run_id: runId, row_id: row.id, repeat }, deps, models.b3);
        if (judged.kind === 'ok') { add(`B3-${repeat + 1}`, judged.verdict); if (judged.verdict === row.expected) passingTasks += 1; }
        else errors[`B3-${repeat + 1}`]?.push({ id: row.id, reason: judged.reason });
      }
    }
    for (const name of Object.keys(methods)) methods[name] = { status: !options.live && name.startsWith('B3') ? 'not yet measured' : (observations[name]?.length === actions.length ? 'measured' : 'incomplete'), observations: observations[name] ?? [], errors: errors[name] ?? [] };
    const classifiers: Record<string, unknown> = {};
    const classifierRows: Record<string, unknown[]> = {};
    const defaultContext = contexts[0]; if (defaultContext === undefined) throw new Error('Reference context missing');
    for (const provider of ['keyword', 'mock', ...(options.live ? ['jev', 'llm'] as const : [])] as const) {
      const measured: LabelObservation[] = []; const rawRows: unknown[] = [];
      for (const row of seededOrder(lines, manifest.seed)) {
        const classified: Classification = await classifyLine({ id: row.id, line: row.line, provider, context: defaultContext.ref.context }, { thresholds, remote: async ({ line, provider: selected }) => selected === 'jev' ? classifyJev(line, deps, seededOrder(FREE_TEXT_LABELS, manifest.seed + row.id.length)) : classifyLlm(line, deps, models.llm) });
        const compiled = compile(defaultContext.ref.answers, [classified.item], defaultContext.ref.context);
        const actualRule = compiled.ok && compiled.value.rules.some((rule) => rule.source_answer === `freetext:${row.id}`);
        if ((provider === 'jev' || provider === 'llm') && classified.item.label === row.label) passingTasks += 1;
        measured.push({ id: row.id, expected: row.label, actual: classified.item.label, raw_label: classified.raw_label, rule_compiled: actualRule });
        rawRows.push({ id: row.id, expected: row.label, actual: classified.item.label, raw_label: classified.raw_label, confidence: classified.confidence, status: classified.status, reason: classified.reason, params: classified.item.params ?? null, rule_compiled: actualRule });
      }
      classifierRows[provider] = rawRows;
      classifiers[provider] = provider === 'mock' ? { status: 'demo stub; excluded from accuracy', rows: rawRows } : classifierMetrics(measured);
    }
    const ledgerRows = options.live ? ledgerEvents(await ledger.read()) : [];
    const cost = { ...ledgerSummary(ledgerRows, runId, passingTasks), price_table: PRICE_TABLE, passing_task_definition: 'Correct end-to-end Jev/LLM routed classifications plus correct valid-action B3 trials; cached/manual pipeline outcomes are included and separately visible.' };
    const b3Complete = ['B3-1', 'B3-2', 'B3-3'].every((name) => methods[name]?.status === 'measured');
    const validRows = actions.filter((row) => validateAction(row.action).ok);
    const b3Disagreements = b3Complete ? validRows.filter((row) => new Set(['B3-1', 'B3-2', 'B3-3'].map((name) => methods[name]?.observations.find((observation) => observation.id === row.id)?.actual)).size > 1).map((row) => row.id) : null;
    const b4Source = await readFile(resolve(root, 'eval/baselines/b4-regex.ts'), 'utf8');
    const metadata = { run_id: runId, at: new Date().toISOString(), split: options.split, live: options.live, seed: manifest.seed, engine_version: ENGINE_VERSION, dataset_sha256: { actions: exactSha256(actionsText), classifier: exactSha256(linesText) }, manifest_sha256: manifest.manifest_sha256, b4_source_sha256: exactSha256(b4Source), b4_rules_sha256: exactSha256(JSON.stringify(B4_RULES)), b4_authoring: B4_AUTHORING, thresholds_sha256: exactSha256(thresholdsText), models_config_sha256: exactSha256(modelsText), reference_answers_sha256: exactSha256(referenceText), rerun_reason: options.rerun_reason };
    const result = { metadata, methods: Object.fromEntries(Object.entries(methods).map(([name, method]) => [name, { ...method, metrics: method.status === 'measured' ? summarizeMetrics(method.observations) : null, failures: method.observations.filter((row) => row.actual !== row.expected) }])), classifiers, classifier_rows: classifierRows, cost, b3_flakiness: b3Complete ? { k: b3Disagreements?.length ?? 0, n: validRows.length, row_ids: b3Disagreements } : 'not yet measured: three complete independent trials required', comparison: Object.fromEntries(['B1', 'B2', 'B4'].map((name) => [name, compareMethods((methods[name]?.observations ?? []).map((row) => ({ id: row.id, expected: row.expected, baseline: row.actual, guard: methods['guard']?.observations.find((entry) => entry.id === row.id)?.actual ?? 'invalid' })))])) };
    const markdown = resultsMarkdown(result.metadata, methods, cost, classifiers, b3Disagreements);
    await mkdir(resolve(root, 'results'), { recursive: true });
    await fileJournalStore(resolve(root, 'results/results.jsonl')).append(`${JSON.stringify(result)}\n`);
    await writeFile(resolve(root, 'results/results.md'), markdown, 'utf8');
    if (heldoutClaimed) await journal.exclusive(async () => { await journal.append(`${JSON.stringify({ kind: 'completed', run_id: runId, at: new Date().toISOString(), results_sha256: exactSha256(JSON.stringify(result)), manifest_sha256: manifest.manifest_sha256 })}\n`); });
    process.stdout.write(markdown); return 0;
  } catch (error: unknown) {
    if (heldoutClaimed) await journal.exclusive(async () => { await journal.append(`${JSON.stringify({ kind: 'failed', run_id: runId, at: new Date().toISOString(), message: error instanceof Error ? error.message : 'Evaluation failed' })}\n`); });
    process.stderr.write(`${JSON.stringify({ ok: false, error: error instanceof Error ? error.message : 'Evaluation failed' })}\n`); return 1;
  }
}

function resultsMarkdown(metadata: { readonly run_id: string; readonly split: string; readonly live: boolean }, methods: Readonly<Record<string, MethodResult>>, cost: unknown, classifiers: unknown, disagreements: readonly string[] | null): string {
  const table = Object.entries(methods).map(([name, method]) => {
    const metric = method.status === 'measured' ? summarizeMetrics(method.observations).metrics : null;
    return `| ${name} | ${method.status} | ${metric === null ? 'N/A' : formatRatio(metric.exact_verdict_accuracy)} | ${metric === null ? 'N/A' : formatRatio(metric.prohibited_block_rate)} | ${metric === null ? 'N/A' : formatRatio(metric.evasion_block_rate)} | ${metric === null ? 'N/A' : formatRatio(metric.permitted_allow_rate)} |`;
  });
  return [`# Evaluation results`, '', `Run ${metadata.run_id}; split ${metadata.split}; live ${metadata.live}. Gold is builder-authored, not independently labelled.`, '', '| Method | Status | Exact verdict | Prohibited block | Evasion block | Permitted allow |', '|---|---|---|---|---|---|', ...table, '', '## Named failures and incomplete calls', '', ...Object.entries(methods).flatMap(([name, method]) => [...method.observations.filter((row) => row.actual !== row.expected).map((row) => `- ${name} ${row.id}: expected ${row.expected}, actual ${row.actual}; traps ${row.traps.join(', ') || 'none'}.`), ...method.errors.map((error) => `- ${name} ${error.id}: unavailable (${error.reason}).`)]), '', '## Classifiers (mock excluded from accuracy)', '', '```json', JSON.stringify(classifiers, null, 2), '```', '', '## Cost and B3 variability', '', '```json', JSON.stringify({ cost, b3_disagreement_ids: disagreements }, null, 2), '```', '', 'Full observations, per-trap counts and wins/ties/regressions are in results.jsonl. Missing usage remains unknown. No metric proves agent enforcement.', ''].join('\n');
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) void main(process.argv.slice(2)).then((code) => { process.exitCode = code; });

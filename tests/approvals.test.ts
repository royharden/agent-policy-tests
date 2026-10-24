import { describe, expect, it } from 'vitest';
import { acceptedItems } from '../src/lib/review';
import type { Fixture } from '../src/policyfix/action';
import { type ApprovalRequirement, approvalRequirements, bindReviewReport, checkReportBinding, exportReadiness, isApproved, recordApproval, type ReviewInputs, reviewInputsSha, type ReviewSnapshot } from '../src/policyfix/approvals';
import { type CompileOutput, compile } from '../src/policyfix/compile';
import { policySha } from '../src/policyfix/digest';
import { generateFixtures } from '../src/policyfix/fixtures';
import { classifyLine } from '../src/policyfix/freetext/classify';
import { type ThresholdConfig, UNCALIBRATED_THRESHOLDS } from '../src/policyfix/freetext/thresholds';
import { guardInIsolation } from '../src/policyfix/guard';
import { evaluatePolicy } from '../src/policyfix/score';
import { reference } from './helpers/reference';

const DECIDED = '2026-10-24T16:00:00.000Z';
function baseInputs(): ReviewInputs {
  return { answers: reference('posix').answers, default_unmatched: 'allow', lines: [], thresholds: UNCALIBRATED_THRESHOLDS, thresholds_text: JSON.stringify(UNCALIBRATED_THRESHOLDS), raw_answers: {}, revision: 0 };
}
async function inputsWithLines(): Promise<ReviewInputs> {
  const inputs = baseInputs();
  const descriptions = [
    { id: 'command', text: 'never run terraform destroy' },
    { id: 'path', text: 'never delete /workspace/demo/private' },
    { id: 'branch', text: 'never push to the hotfix branch' },
    { id: 'courtesy', text: 'never be rude to customers' },
  ];
  const lines = await Promise.all(descriptions.map(async ({ id, text }) => {
    const classification = await classifyLine({ id, line: text, context: inputs.answers.Q01.context, provider: 'keyword' });
    return { id, text, provider: 'keyword' as const, classification, params_text: JSON.stringify(classification.item.params ?? {}) };
  }));
  return { ...inputs, lines };
}
function compiled(inputs: ReviewInputs): CompileOutput {
  const accepted = acceptedItems(inputs);
  if (!accepted.ok) throw new Error(JSON.stringify(accepted.errors));
  const result = compile(inputs.answers, accepted.value, inputs.answers.Q01.context, { default_unmatched: inputs.default_unmatched });
  if (!result.ok) throw new Error(JSON.stringify(result.errors));
  return result.value;
}

async function classifiedInputs(text: string): Promise<ReviewInputs> {
  const inputs = baseInputs();
  const classification = await classifyLine({ id: 'scope', line: text, context: inputs.answers.Q01.context, provider: 'keyword' });
  return { ...inputs, lines: [{ id: 'scope', text, provider: 'keyword', classification, params_text: JSON.stringify(classification.item.params ?? {}) }] };
}
function requirements(output: CompileOutput, inputs: ReviewInputs, fixtures: readonly Fixture[] = []): readonly ApprovalRequirement[] {
  const result = approvalRequirements(output, fixtures, inputs);
  if (!result.ok) throw new Error(JSON.stringify(result.errors));
  return result.value;
}
function find(items: readonly ApprovalRequirement[], id: string): ApprovalRequirement {
  const item = items.find((entry) => entry.item_id === id || entry.source_answer === `freetext:${id}`);
  if (item === undefined) throw new Error(`Missing requirement ${id}`);
  return item;
}
function snapshot(inputs: ReviewInputs, fixtures: readonly Fixture[] = []): ReviewSnapshot {
  const output = compiled(inputs); const source = reviewInputsSha(inputs);
  const scored = evaluatePolicy(output.policy, fixtures);
  if (!source.ok || !scored.ok) throw new Error('Snapshot inputs invalid');
  const report = bindReviewReport(scored.value, inputs, []);
  if (!report.ok) throw new Error('Report binding invalid');
  return { policy: output.policy, fixtures, inputs, provenance: output.provenance, compiled_source_sha256: source.value, requirements: requirements(output, inputs, fixtures), report: report.value, approvals: [] };
}

describe('content-bound review and export preflight', () => {
  it('carries the demo push scope through classification, editor acceptance and compilation', async () => {
    // what_bug_this_catches: the strict editor schema rejected M5 git_operation before the demo could compile;
    // bypassing acceptedItems in approval-test helpers hid this integration failure.
    const inputs = await inputsWithLines();
    const accepted = acceptedItems(inputs);
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) throw new Error(JSON.stringify(accepted.errors));
    expect(accepted.value.find((item) => item.id === 'branch')?.params).toEqual({ branch: 'hotfix', git_operation: 'push' });
    const output = compiled(inputs);
    const rule = output.rules.find((candidate) => candidate.source_answer === 'freetext:branch');
    expect(rule).toBeDefined();
    if (rule === undefined) throw new Error('demo push rule missing');
    const context = inputs.answers.Q01.context;
    expect(guardInIsolation(rule, { kind: 'git', args: ['push', 'origin', 'HEAD:hotfix'] }, context).verdict).toBe('deny');
    expect(guardInIsolation(rule, { kind: 'git', args: ['branch', '-D', 'hotfix'] }, context).verdict).toBe('allow');
    expect(output.dispositions.find((item) => item.source_answer === 'freetext:branch')?.disposition).toBe('restricted');
  });

  it.each([
    { text: 'only call api.example.test', polarity: 'allow-list', blocked: 'other.example.test', permitted: 'api.example.test' },
    { text: 'never call api.example.test', polarity: 'block-list', blocked: 'api.example.test', permitted: 'other.example.test' },
  ])('preserves HTTP polarity through the real acceptance path: $text', async ({ text, polarity, blocked, permitted }) => {
    // what_bug_this_catches: dropping/rejecting extracted polarity prevents network rules or reverses an allow-list
    // into a block-list; isolation avoids the questionnaire's Q06 rule masking that error.
    const inputs = await classifiedInputs(text);
    expect(inputs.lines[0]?.classification?.status).toBe('compiled-candidate');
    const accepted = acceptedItems(inputs);
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) throw new Error(JSON.stringify(accepted.errors));
    expect(accepted.value[0]?.params).toEqual({ hosts: ['api.example.test'], polarity });
    const output = compiled(inputs);
    const rule = output.rules.find((candidate) => candidate.source_answer === 'freetext:scope');
    expect(rule).toBeDefined();
    if (rule === undefined) throw new Error('network rule missing');
    const context = inputs.answers.Q01.context;
    expect(guardInIsolation(rule, { kind: 'http', method: 'GET', url: `https://${blocked}/` }, context).verdict).toBe('deny');
    expect(guardInIsolation(rule, { kind: 'http', method: 'GET', url: `https://${permitted}/` }, context).verdict).toBe('allow');
  });

  it('preserves domain block polarity and leaves an edited unsupported domain allow-list manual', async () => {
    // what_bug_this_catches: editor acceptance must preserve domain polarity too; accepting an allow-list enum must
    // not silently turn M5's unsupported single-rule domain allow-list into an executable block-list.
    const original = await classifiedInputs('never message recipients at example.test');
    const classification = original.lines[0]?.classification;
    expect(classification?.status).toBe('compiled-candidate');
    if (classification === null || classification === undefined) throw new Error('domain classification missing');
    for (const polarity of ['block-list', 'allow-list'] as const) {
      const inputs: ReviewInputs = { ...original, lines: original.lines.map((line) => ({ ...line, params_text: JSON.stringify({ ...classification.item.params, polarity }) })) };
      const accepted = acceptedItems(inputs);
      expect(accepted.ok).toBe(true);
      if (!accepted.ok) throw new Error(JSON.stringify(accepted.errors));
      expect(accepted.value[0]?.params).toEqual({ domain: 'example.test', polarity });
      const output = compiled(inputs);
      const rule = output.rules.find((candidate) => candidate.source_answer === 'freetext:scope');
      if (polarity === 'allow-list') {
        expect(rule).toBeUndefined();
        expect(output.manual_items.some((item) => item.source_answer === 'freetext:scope')).toBe(true);
      } else {
        expect(rule).toBeDefined();
        if (rule === undefined) throw new Error('domain block rule missing');
        expect(guardInIsolation(rule, { kind: 'message', channel: 'email', to: 'ops@example.test' }, inputs.answers.Q01.context).verdict).toBe('deny');
        expect(guardInIsolation(rule, { kind: 'message', channel: 'email', to: 'ops@other.example.test' }, inputs.answers.Q01.context).verdict).toBe('allow');
      }
    }
  });

  it.each([
    { text: 'never push to the hotfix branch', params: { branch: 'hotfix', git_operation: 'fetch' } },
    { text: 'only call api.example.test', params: { hosts: ['api.example.test'], polarity: 'allow-anything' } },
  ])('rejects unsupported editor enum values after a valid classification: $text', async ({ text, params }) => {
    // what_bug_this_catches: fixing strict-schema omissions with unrestricted strings or passthrough would accept
    // semantics outside the M5 parameter contract rather than its bounded enum values.
    const original = await classifiedInputs(text);
    expect(original.lines[0]?.classification?.status).toBe('compiled-candidate');
    const inputs = { ...original, lines: original.lines.map((line) => ({ ...line, params_text: JSON.stringify(params) })) };
    expect(acceptedItems(inputs).ok).toBe(false);
  });

  it('invalidates changed answers and consumed context while preserving unrelated approvals', async () => {
    // what_bug_this_catches: a single global approval hash discarding every review, or context-dependent rules retaining approval after Q01 changes.
    const before = await inputsWithLines(); const output = compiled(before); const original = requirements(output, before);
    const records = original.map((item) => recordApproval(item, DECIDED));
    const changed: ReviewInputs = { ...before, answers: { ...before.answers, Q12: { limit_cents: 6000, currency: 'USD' } }, revision: 1 };
    const after = requirements(compiled(changed), changed);
    expect(isApproved(find(after, 'q12-over-limit'), records)).toBe(false);
    expect(isApproved(find(after, 'branch'), records)).toBe(true);
    expect(isApproved(find(after, 'courtesy'), records)).toBe(true);
    const contextChanged: ReviewInputs = { ...before, answers: { ...before.answers, Q01: { context: { ...before.answers.Q01.context, cwd: '/workspace/demo/sub' } } }, revision: 1 };
    const contextRequirements = requirements(compiled(contextChanged), contextChanged);
    expect(isApproved(find(contextRequirements, 'path'), records)).toBe(false);
    expect(isApproved(find(contextRequirements, 'branch'), records)).toBe(true);
  });

  it('binds source text, parameter edits and raw questionnaire edits even when old compiled bytes remain visible', async () => {
    // what_bug_this_catches: approving the old rule while a visible uncommitted text/parameter edit still has the same compiled policy bytes.
    const inputs = await inputsWithLines(); const output = compiled(inputs); const original = requirements(output, inputs);
    const records = original.map((item) => recordApproval(item, DECIDED));
    const changed: ReviewInputs = { ...inputs, lines: inputs.lines.map((line) => line.id === 'command' ? { ...line, params_text: '{"command":"terraform plan"}' } : line), revision: 1 };
    const after = requirements(output, changed);
    expect(isApproved(find(after, 'command'), records)).toBe(false);
    expect(isApproved(find(after, 'branch'), records)).toBe(true);
    const raw = requirements(output, { ...inputs, raw_answers: { 'Q12:Currency': 'usd ' }, revision: 1 });
    expect(isApproved(find(raw, 'q12-over-limit'), records)).toBe(false);
    expect(isApproved(find(raw, 'branch'), records)).toBe(true);
  });

  it('invalidates the owner and declared conflict owner of an edited fixture only', async () => {
    // what_bug_this_catches: fixture edits preserving an obsolete approval, or declaring a conflict without invalidating the affected owner's review.
    const inputs = await inputsWithLines(); const output = compiled(inputs); const own = find(requirements(output, inputs), 'command');
    const fixture: Fixture = { id: 'linked', rule_id: own.item_id, source_answer: own.source_answer, action: { kind: 'shell', dialect: 'posix', command: 'terraform destroy' }, expected_local: 'deny', origin: 'freetext' };
    const original = requirements(output, inputs, [fixture]); const records = original.map((item) => recordApproval(item, DECIDED));
    const after = requirements(output, inputs, [{ ...fixture, action: { kind: 'shell', dialect: 'posix', command: 'true' } }]);
    expect(isApproved(find(after, 'command'), records)).toBe(false);
    expect(isApproved(find(after, 'branch'), records)).toBe(true);
    const conflict = { ...fixture, rule_id: 'q03-inside-delete', conflict: { owner_rule: own.item_id, reason: 'Declared owner changed.' } };
    expect(find(requirements(output, inputs, [conflict]), 'command').content_sha256).not.toBe(own.content_sha256);
  });

  it('binds remote thresholds per provider and keeps local approvals independent of calibration', async () => {
    // what_bug_this_catches: changing Jev calibration invalidating an unrelated LLM or keyword approval, or leaving the Jev approval current.
    const threshold: ThresholdConfig = { schema_version: 1, provenance: { status: 'dev-calibrated', split: 'dev', dataset_sha256: 'a'.repeat(64) }, jev: 0.5, llm: 0.5 };
    let inputs = await inputsWithLines();
    const remoteLines = await Promise.all((['jev', 'llm'] as const).map(async (provider) => {
      const text = 'never push to the hotfix branch';
      const classification = await classifyLine({ id: provider, line: text, provider, context: inputs.answers.Q01.context }, { thresholds: threshold, remote: async () => ({ kind: 'ok', label: 'git-release', confidence: 0.9 }) });
      return { id: provider, text, provider, classification, params_text: JSON.stringify(classification.item.params ?? {}) };
    }));
    inputs = { ...inputs, lines: [...inputs.lines, ...remoteLines], thresholds: threshold, thresholds_text: JSON.stringify(threshold) };
    const output = compiled(inputs); const original = requirements(output, inputs); const records = original.map((item) => recordApproval(item, DECIDED));
    const changed = { ...inputs, thresholds: { ...threshold, jev: 0.8 }, thresholds_text: JSON.stringify({ ...threshold, jev: 0.8 }), revision: 1 };
    const after = requirements(output, changed);
    expect(isApproved(find(after, 'jev'), records)).toBe(false);
    expect(isApproved(find(after, 'llm'), records)).toBe(true);
    expect(isApproved(find(after, 'command'), records)).toBe(true);
  });

  it('stales a report on source-only edits and all four required report bindings', async () => {
    // what_bug_this_catches: exporting a report with an unchanged policy hash after a threshold/raw-input edit, or trusting any one missing hash check.
    const inputs = await inputsWithLines(); const current = snapshot(inputs);
    const rawChanged = { ...inputs, revision: inputs.revision + 1 };
    expect(policySha(current.policy)).toEqual(policySha(compiled(rawChanged).policy));
    const dirty = exportReadiness({ ...current, inputs: rawChanged });
    expect(dirty.ok && dirty.value.report_current).toBe(false);
    if (current.report === null) throw new Error('Missing report');
    for (const key of ['policy_sha', 'fixtures_sha', 'context_sha', 'engine_version'] as const) {
      const changed = { ...current, report: { ...current.report, [key]: 'mismatched' } };
      const readiness = exportReadiness(changed);
      expect(readiness.ok && readiness.value.report_current, key).toBe(false);
      expect(checkReportBinding(changed).ok, key).toBe(false);
    }
  });

  it('recomputes mandatory requirements, and appends decisions without changing policy/report hashes', async () => {
    // what_bug_this_catches: an empty UI requirement list bypassing approval, or an acknowledgement mutating policy_sha and staling its own report.
    const current = snapshot(await inputsWithLines());
    const before = exportReadiness({ ...current, requirements: [] });
    expect(before.ok && before.value.missing_item_ids.length).toBeGreaterThan(0);
    const approved = { ...current, approvals: current.requirements.map((item) => recordApproval(item, DECIDED)) };
    const after = exportReadiness(approved);
    expect(after.ok && after.value.missing_item_ids).toEqual([]);
    expect(after.ok && after.value.report_current).toBe(true);
    expect(current.report?.policy_sha).toEqual(approved.report?.policy_sha);
    expect(approved.approvals.every((record) => record.decided_at === DECIDED)).toBe(true);
  });

  it('keeps a manual Gap after acknowledgement while permitting a current Gap review', async () => {
    // what_bug_this_catches: treating a manual acknowledgement as executable coverage, or rejecting every Gap despite the documented acknowledgement flow.
    const base = baseInputs();
    const classification = await classifyLine({ id: 'manual', line: 'never be rude to customers', context: base.answers.Q01.context });
    const inputs: ReviewInputs = { ...base, answers: { ...base.answers, Q02: { block: false }, Q03: { block: false, except: [] }, Q04: { block: false }, Q05: { secret_globs: [], exceptions: [] }, Q06: { enabled: false, hosts: [] }, Q07: { enabled: false, domains: [] }, Q08: { block: false }, Q09: { branches: [] }, Q10: { mode: 'none' }, Q11: { block: false }, Q12: { limit_cents: null, currency: 'USD' } }, lines: [{ id: 'manual', text: classification.item.text, provider: 'keyword', classification, params_text: '{}' }] };
    const output = compiled(inputs); const generated = generateFixtures(output, { mutate: false, dialects: ['posix', 'powershell', 'cmd'] });
    if (!generated.ok) throw new Error(JSON.stringify(generated.errors));
    const current = snapshot(inputs, generated.value.fixtures);
    const approved = { ...current, approvals: current.requirements.map((item) => recordApproval(item, DECIDED)) };
    const ready = exportReadiness(approved);
    expect(current.report?.items.find((item) => item.source_answer === 'freetext:manual')?.status).toBe('Gap');
    expect(current.report?.status).toBe('Gap');
    expect(ready.ok && ready.value.ready).toBe(true);
    expect(checkReportBinding(approved).ok).toBe(true);
    expect(current.report?.metrics.executable_coverage.k).toBe(0);
  });
});

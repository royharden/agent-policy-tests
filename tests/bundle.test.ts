import { describe, expect, it } from 'vitest';
import { approvalRequirements, bindReviewReport, recordApproval, reviewInputsSha, type ReviewInputs, type ReviewSnapshot } from '../src/policyfix/approvals';
import { buildBundle, BUNDLE_NAMES, hashBytes } from '../src/policyfix/bundle';
import { compile } from '../src/policyfix/compile';
import { UNCALIBRATED_THRESHOLDS } from '../src/policyfix/freetext/thresholds';
import { MAX_FILE_BYTES } from '../src/policyfix/limits';
import { evaluatePolicy } from '../src/policyfix/score';
import { createBundleDownload } from '../src/lib/export-bundle';
import { reference } from './helpers/reference';

function snapshot(manual = false): ReviewSnapshot {
  const ref = reference('posix');
  const item = { id: 'courtesy', text: 'never be rude to customers', label: 'manual' as const, reason: 'Subjective restriction.' };
  const inputs: ReviewInputs = { answers: ref.answers, default_unmatched: 'allow', lines: manual ? [{ id: item.id, text: item.text, provider: 'keyword', params_text: '{}', classification: { item, raw_label: 'manual', confidence: null, provider: 'keyword', status: 'manual', reason: item.reason } }] : [], thresholds: UNCALIBRATED_THRESHOLDS, thresholds_text: JSON.stringify(UNCALIBRATED_THRESHOLDS), raw_answers: {}, revision: 0 };
  const output = compile(inputs.answers, manual ? [item] : [], ref.context); const source = reviewInputsSha(inputs);
  if (!output.ok || !source.ok) throw new Error('Invalid source fixture');
  const scored = evaluatePolicy(output.value.policy, []); if (!scored.ok) throw new Error('Invalid score fixture');
  const bound = bindReviewReport(scored.value, inputs, []); const requirements = approvalRequirements(output.value, [], inputs);
  if (!bound.ok || !requirements.ok) throw new Error('Invalid review fixture');
  return { policy: output.value.policy, fixtures: [], inputs, provenance: output.value.provenance, compiled_source_sha256: source.value, requirements: requirements.value, report: bound.value, approvals: [] };
}

describe('bundle integrity and export adapter', () => {
  it('emits seven final-byte entries, recomputes outcomes and excludes the manifest from its own hashes', () => {
    // what_bug_this_catches: trusting a forged saved outcome, hashing pre-serialization objects, or recursively hashing the manifest.
    const current = snapshot(); if (current.report === null) throw new Error('Missing report');
    const result = buildBundle({ ...current, report: { ...current.report, status: 'Pass' } }, new TextEncoder().encode('// built runner fixture'));
    expect(result.ok).toBe(true); if (!result.ok) return;
    expect(Object.keys(result.value.files).sort()).toEqual([...BUNDLE_NAMES].sort());
    const manifest = JSON.parse(new TextDecoder().decode(result.value.files['bundle-manifest.json'])) as { files: Record<string, { bytes: number; sha256: string }> };
    expect(manifest.files['bundle-manifest.json']).toBeUndefined();
    for (const name of BUNDLE_NAMES.filter((entry) => entry !== 'bundle-manifest.json')) expect(manifest.files[name]).toEqual({ bytes: result.value.files[name].length, sha256: hashBytes(result.value.files[name]) });
    const report: unknown = JSON.parse(new TextDecoder().decode(result.value.files['report.json']));
    expect(report).toMatchObject({ status: 'Gap', approvals: [] });
  });

  it('uses the existing content-bound approvals gate and keeps a manual Gap after acknowledgement', () => {
    // what_bug_this_catches: a second weakened approval gate or treating manual acknowledgement as executable evidence.
    const current = snapshot(true); const runner = new Uint8Array([47, 47, 32, 120]);
    expect(buildBundle(current, runner).ok).toBe(false);
    const approvals = current.requirements.filter((item) => item.required).map((item) => recordApproval(item, '2026-10-24T22:00:00Z'));
    const result = buildBundle({ ...current, approvals }, runner);
    expect(result.ok && result.value.status).toBe('Gap');
    expect(buildBundle({ ...current, approvals, inputs: { ...current.inputs, revision: 1 } }, runner).ok).toBe(false);
  });

  it('caps report.json including approvals rather than silently exporting an unreadable file', () => {
    // what_bug_this_catches: checking policy/fixtures but overlooking a huge append-only approval history in report.json.
    const current = snapshot();
    const result = buildBundle({ ...current, approvals: [{ item_id: 'history', content_sha256: 'a'.repeat(64), decision: 'approve', decided_at: 'x'.repeat(MAX_FILE_BYTES) }] }, new Uint8Array([47, 47]));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors[0]).toMatchObject({ code: 'export_too_large', pointer: '/report.json' });
  });

  it('fails explicitly for missing, empty or HTML runner assets and rechecks latest state after fetch', async () => {
    // what_bug_this_catches: Vite SPA fallbacks or a draft edited during fetch producing a zip with a missing/stale runner.
    const current = snapshot();
    for (const [ok, data] of [[false, 'missing'], [true, ''], [true, '<html>fallback</html>']] as const) {
      const result = await createBundleDownload(current, async () => ({ ok, status: ok ? 200 : 404, arrayBuffer: async () => new TextEncoder().encode(data).buffer as ArrayBuffer }));
      expect(result.ok).toBe(false);
    }
    const stale = await createBundleDownload(() => null, async () => ({ ok: true, status: 200, arrayBuffer: async () => new TextEncoder().encode('// runner').buffer as ArrayBuffer }));
    expect(stale.ok).toBe(false);
  });
});

import { describe, expect, it } from 'vitest';
import { draftFromInputs, loadDraft, parseDraft, saveDraft, validateDraft } from '../src/lib/drafts';
import type { ReviewInputs } from '../src/policyfix/approvals';
import { UNCALIBRATED_THRESHOLDS } from '../src/policyfix/freetext/thresholds';
import { MAX_FILE_BYTES, MAX_JSON_DEPTH } from '../src/policyfix/limits';
import { reference } from './helpers/reference';

function inputs(): ReviewInputs {
  return { answers: reference('posix').answers, default_unmatched: 'allow', lines: [{ id: 'draft-line', text: 'never run terraform destroy', provider: 'jev', classification: null, params_text: '{"command":"terraform destroy"}' }], thresholds: UNCALIBRATED_THRESHOLDS, thresholds_text: JSON.stringify(UNCALIBRATED_THRESHOLDS), raw_answers: {}, revision: 12 };
}
function draft(): object {
  const result = draftFromInputs(inputs()); if (!result.ok) throw new Error(JSON.stringify(result.errors)); return result.value;
}

describe('untrusted input-only drafts', () => {
  it('round-trips inputs without retaining approvals, reports, classification replies or opt-in', () => {
    // what_bug_this_catches: a saved file silently granting remote permission or treating a cached classifier/report as a fresh review.
    const source = draft(); const restored = parseDraft(JSON.stringify(source));
    expect(restored.ok).toBe(true);
    for (const extra of [{ optedIn: { jev: true } }, { approvals: [] }, { report: {} }]) expect(validateDraft({ ...source, ...extra }).ok).toBe(false);
    expect(validateDraft({ ...source, lines: [{ ...inputs().lines[0], classification: {} }] }).ok).toBe(false);
  });

  it('rejects oversized, overdeep, malformed and duplicate-id imports with structured errors', () => {
    // what_bug_this_catches: allocating a hostile draft before applying shared caps, or silently accepting ambiguous duplicate line ids.
    const oversized = parseDraft(' '.repeat(MAX_FILE_BYTES + 1));
    expect(!oversized.ok && oversized.errors[0]?.code).toBe('file_too_large');
    const deep = parseDraft('['.repeat(MAX_JSON_DEPTH + 1) + '0' + ']'.repeat(MAX_JSON_DEPTH + 1));
    expect(!deep.ok && deep.errors[0]?.code).toBe('too_deep');
    expect(parseDraft('{').ok).toBe(false);
    const line = { id: 'same', text: 'never run terraform destroy', provider: 'keyword', params_text: '{}' };
    const duplicate = validateDraft({ ...draft(), lines: [line, line] });
    expect(!duplicate.ok && duplicate.errors[0]?.code).toBe('duplicate_id');
  });

  it('refuses visible raw values or threshold text that disagree with the active inputs', () => {
    // what_bug_this_catches: importing a draft that shows a safe value but compiles a different payment limit or remote confidence threshold.
    expect(validateDraft({ ...draft(), raw_answers: { 'Q12:Limit in cents (empty = no limit)': '9000' } }).ok).toBe(false);
    expect(validateDraft({ ...draft(), thresholds_text: JSON.stringify({ ...UNCALIBRATED_THRESHOLDS, jev: 0.3 }) }).ok).toBe(false);
    const valid = validateDraft({ ...draft(), raw_answers: { 'Q12:Limit in cents (empty = no limit)': '5000 ', 'Q12:Currency': 'usd' } });
    expect(valid.ok).toBe(true);
  });

  it('survives blocked storage and preserves the last valid draft when an answer is invalid', () => {
    // what_bug_this_catches: storage exceptions breaking the app, or JSON.stringify(NaN) converting an invalid limit to null (no limit) on reload.
    const blocked = { getItem: (): string => { throw new Error('blocked'); }, setItem: (): void => { throw new Error('full'); } };
    expect(loadDraft(blocked).ok).toBe(false); expect(saveDraft(blocked, inputs()).ok).toBe(false);
    let text = '';
    const memory = { getItem: (): string => text, setItem: (_key: string, value: string): void => { text = value; } };
    expect(saveDraft(memory, inputs()).ok).toBe(true); const previous = text;
    const invalid = { ...inputs(), answers: { ...inputs().answers, Q12: { limit_cents: Number.NaN, currency: 'USD' } } };
    expect(saveDraft(memory, invalid).ok).toBe(false); expect(text).toBe(previous); expect(loadDraft(memory).ok).toBe(true);
  });
});

import { describe, expect, it } from 'vitest';
import { QUESTION_IDS } from '../src/policyfix/action';
import { compile } from '../src/policyfix/compile';
import { QUESTIONS, validateAnswers } from '../src/policyfix/questionnaire';
import { compileOrThrow, reference } from './helpers/reference';

describe('questionnaire compilation', () => {
  it('accounts for each stable question exactly once and links Q01 to consumers', () => {
    // what_bug_this_catches: renamed or silently dropped answers inflate answer coverage while removing restrictions.
    const ref = reference('posix');
    const output = compileOrThrow(ref.answers, ref.context);
    expect(QUESTIONS.map((question) => question.id)).toEqual(QUESTION_IDS);
    expect(output.dispositions.map((entry) => entry.source_answer)).toEqual(QUESTION_IDS);
    expect(output.dispositions[0]?.disposition).toBe('parameter');
    expect(output.provenance.parameters['Q01']?.length).toBeGreaterThan(0);
    for (const id of output.provenance.parameters['Q01'] ?? []) {
      expect(output.provenance.rules[id]?.parameters).toContain('Q01');
    }
  });

  it('distinguishes disabled allow-lists from enabled empty deny-all lists', () => {
    // what_bug_this_catches: inferring enabled state from list length silently permits all outbound destinations.
    const ref = reference('posix');
    for (const enabled of [false, true]) {
      const output = compileOrThrow({ ...ref.answers, Q06: { enabled, hosts: [] }, Q07: { enabled, domains: [] } }, ref.context);
      for (const source of ['Q06', 'Q07']) {
        const disposition = output.dispositions.find((entry) => entry.source_answer === source);
        expect(disposition?.disposition).toBe(enabled ? 'restricted' : 'not-restricted');
        expect(disposition?.rule_ids.length).toBe(enabled ? 1 : 0);
        if (!enabled) expect(output.witnesses[source]?.length).toBeGreaterThanOrEqual(2);
      }
    }
  });

  it('preserves manual free-text restrictions and rejects duplicate source ids', () => {
    // what_bug_this_catches: unsupported restrictions disappearing from dispositions would hide a manual Gap.
    const ref = reference('posix');
    const item = { id: 'courtesy', text: 'never be rude to customers', label: 'manual' as const };
    const output = compileOrThrow(ref.answers, ref.context, [item, { id: 'unextractable', text: 'never push there', label: 'git-release' }]);
    expect(output.manual_items).toHaveLength(2);
    expect(output.dispositions.filter((entry) => entry.disposition === 'manual')).toHaveLength(2);
    const duplicate = compile(ref.answers, [item, item], ref.context);
    expect(duplicate.ok).toBe(false);
    if (!duplicate.ok) expect(duplicate.errors.some((error) => error.code === 'duplicate_id')).toBe(true);
  });

  it('rejects invalid cents and a compilation context that disagrees with Q01', () => {
    // what_bug_this_catches: invalid form numbers or an ignored Q01 must not compile a silently weaker policy.
    const ref = reference('posix');
    for (const cents of [NaN, Infinity, -1, 0.5]) {
      expect(validateAnswers({ ...ref.answers, Q12: { limit_cents: cents, currency: 'USD' } }).ok).toBe(false);
    }
    expect(compile(ref.answers, [], { ...ref.context, cwd: '/workspace/elsewhere' }).ok).toBe(false);
  });
});

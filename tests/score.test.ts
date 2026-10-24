import { describe, expect, it } from 'vitest';
import type { Fixture, Policy, Rule } from '../src/policyfix/action';
import { buildBaselines } from '../src/policyfix/baselines';
import { generateFixtures } from '../src/policyfix/fixtures';
import { evaluatePolicy, formatRatio, type ScoreReport, summarizeMetrics } from '../src/policyfix/score';
import { ruleSensitivity } from '../src/policyfix/sensitivity';
import { compileOrThrow, reference, referenceOutput } from './helpers/reference';

function report(policy: Policy, fixtures: readonly Fixture[]): ScoreReport {
  const result = evaluatePolicy(policy, fixtures);
  if (!result.ok) throw new Error(JSON.stringify(result.errors));
  return result.value;
}

function paymentFixture(id: string, cents: number, expected: 'deny' | 'ask' | 'allow'): Fixture {
  return { id, rule_id: 'q12-over-limit', source_answer: 'Q12', action: { kind: 'payment', amount_cents: cents, currency: 'USD' }, expected_local: expected, origin: 'template' };
}

describe('scoring and coverage', () => {
  it('requires exact prohibited verdicts and keeps Fail above missing-witness Gap', () => {
    // what_bug_this_catches: counting any block as an exact pass, or overwriting a real mismatch with a coverage Gap.
    const output = referenceOutput('posix');
    const result = report(output.policy, [paymentFixture('wrong', 5001, 'ask')]);
    expect(result.rows[0]?.status).toBe('Fail');
    expect(result.items.find((item) => item.source_answer === 'Q12')?.status).toBe('Fail');
    expect(result.status).toBe('Fail');
    expect(result.findings.some((finding) => finding.code === 'missing-permitted-witness')).toBe(true);
  });

  it('reconstructs gaps from missing fixture rows and detects omitted source dispositions', () => {
    // what_bug_this_catches: a saved report claiming full coverage after import removed fixtures or an answer.
    const output = referenceOutput('posix');
    const policy = { ...output.policy, dispositions: output.policy.dispositions.filter((entry) => entry.source_answer !== 'Q11') };
    const result = report(policy, []);
    expect(result.silent_drops).toBeGreaterThan(0);
    expect(result.items.find((item) => item.source_answer === 'Q11')?.status).toBe('Fail');
    expect(result.items.find((item) => item.source_answer === 'Q12')?.status).toBe('Gap');
    expect(result.minima.every((minimum) => minimum.prohibited_fixture_ids.length === 0 && minimum.permitted_fixture_ids.length === 0)).toBe(true);
  });

  it('counts explained manual coverage separately from executable coverage and keeps the manual Gap', () => {
    // what_bug_this_catches: an acknowledged manual item pretending to be an executable restriction or losing its coverage credit.
    const ref = reference('posix');
    const output = compileOrThrow(ref.answers, ref.context, [{ id: 'courtesy', text: 'never be rude to customers', label: 'manual' }]);
    const generated = generateFixtures(output, { mutate: false });
    if (!generated.ok) throw new Error(JSON.stringify(generated.errors));
    const result = report(output.policy, generated.value.fixtures);
    expect(result.metrics.answer_coverage).toEqual({ k: 13, n: 13 });
    expect(result.metrics.executable_coverage).toEqual({ k: 12, n: 13 });
    expect(result.items.find((item) => item.source_answer === 'freetext:courtesy')?.status).toBe('Gap');
  });

  it('distinguishes deciding coverage from delete-one sensitivity and shadowing', () => {
    // what_bug_this_catches: matched-but-never-deciding rules inflating rule coverage, or identical blockers falsely claiming sensitivity.
    const output = referenceOutput('posix');
    const own = output.rules.find((rule) => rule.id === 'q12-over-limit');
    if (own === undefined) throw new Error('Reference payment rule missing');
    const duplicate: Rule = { ...own, id: 'zz-duplicate' };
    const policy: Policy = { ...output.policy, rules: [...output.rules, duplicate], dispositions: output.dispositions.map((entry) => entry.source_answer === 'Q12' ? { ...entry, rule_ids: [...entry.rule_ids, duplicate.id] } : entry) };
    const sensitivity = ruleSensitivity(policy, [paymentFixture('over', 5001, 'deny'), paymentFixture('under', 100, 'allow')]);
    expect(sensitivity.find((entry) => entry.rule_id === duplicate.id)).toMatchObject({ untested: true, shadowed: true, deciding_fixture_ids: [] });
    expect(sensitivity.find((entry) => entry.rule_id === own.id)).toMatchObject({ untested: true, shadowed: false, deciding_fixture_ids: ['over'] });
    expect(sensitivity.some((entry) => entry.rule_id === 'opaque-construct')).toBe(false);
  });

  it('keeps disabled restrictions covered under an explicit strict unmatched default', () => {
    // what_bug_this_catches: mapping a permitted witness to strict ask must not relabel its local expectation or manufacture an answer Gap.
    const ref = reference('posix');
    const output = compileOrThrow({ ...ref.answers, Q06: { enabled: false, hosts: [] } }, ref.context, [], 'ask');
    const generated = generateFixtures(output, { mutate: false });
    if (!generated.ok) throw new Error(JSON.stringify(generated.errors));
    const result = report(output.policy, generated.value.fixtures);
    expect(result.items.find((item) => item.source_answer === 'Q06')?.status).toBe('Pass');
    expect(generated.value.fixtures.filter((fixture) => fixture.source_answer === 'Q06').every((fixture) => fixture.expected_local === 'allow' && fixture.expected_policy === 'ask')).toBe(true);
  });

  it('reports metric numerators/denominators, explicit evasion rows and N/A honestly', () => {
    // what_bug_this_catches: including permitted/opaque-only rows in evasion, confusing exact accuracy with blocking, or dividing by zero.
    const summary = summarizeMetrics([
      { id: 'evasion', expected: 'deny', actual: 'ask', traps: ['flag-reorder'], evasion: true },
      { id: 'opaque', expected: 'ask', actual: 'allow', traps: ['opaque'], evasion: false },
      { id: 'permit', expected: 'allow', actual: 'deny', traps: ['near-miss-permitted'], evasion: false },
    ]);
    expect(summary.metrics.exact_verdict_accuracy).toEqual({ k: 0, n: 3 });
    expect(summary.metrics.prohibited_block_rate).toEqual({ k: 1, n: 2 });
    expect(summary.metrics.evasion_block_rate).toEqual({ k: 1, n: 1 });
    expect(summary.metrics.false_block_rate).toEqual({ k: 1, n: 1 });
    expect(summary.per_trap.opaque).toEqual({ total: 1, prohibited: 1, blocked: 0, permitted: 0, allowed: 0 });
    expect(formatRatio({ k: 0, n: 0 })).toBe('N/A');
    expect(formatRatio({ k: 1, n: 2 })).toBe('1/2 (50.0%)');
  });

  it('binds report digests to current fixtures and policy parameters', () => {
    // what_bug_this_catches: exporting approvals against stale expectations or a changed strict policy default.
    const output = referenceOutput('posix');
    const first = report(output.policy, [paymentFixture('one', 5001, 'deny')]);
    const second = report(output.policy, [paymentFixture('two', 5002, 'deny')]);
    expect(first.policy_sha).toBe(second.policy_sha);
    expect(first.fixtures_sha).not.toBe(second.fixtures_sha);
    const strict = report({ ...output.policy, default_unmatched: 'ask' }, [paymentFixture('one', 5001, 'deny')]);
    expect(strict.policy_sha).not.toBe(first.policy_sha);
    expect(strict.context_sha).toBe(first.context_sha);
  });

  it('builds raw substring/prefix baselines from the same answers without assuming a win', () => {
    // what_bug_this_catches: baselines quietly reusing normalization, ignoring answer toggles, or publishing presumed improvements.
    const ref = reference('posix');
    const base = buildBaselines(ref.answers, ref.context);
    const action = { kind: 'shell' as const, dialect: 'posix' as const, command: 'echo sudo demo' };
    expect(base.B1.evaluate(action).verdict).toBe('deny');
    expect(base.B2.evaluate(action).verdict).toBe('allow');
    const off = buildBaselines({ ...ref.answers, Q04: { block: false } }, ref.context);
    expect(off.B1.evaluate(action).verdict).toBe('allow');
  });
});

import { describe, expect, it } from 'vitest';
import type { Rule } from '../src/policyfix/action';
import { evaluateRules, guardInput } from '../src/policyfix/guard';
import { reference, referencePolicy, verdictOf } from './helpers/reference';

function dropRule(id: string, effect: 'deny' | 'ask'): Rule {
  return { id, source_answer: 'Q11', template: 'data-money', effect, intent: 'Restrict DROP', match: [{ op: 'in', field: 'sql.verb', values: ['DROP'] }] };
}

describe('guard composition', () => {
  it('combines deny before ask, then chooses the lowest id and returns all matching ids', () => {
    // what_bug_this_catches: evaluation order must not let an earlier ask hide a deny or make tie-breaking unstable.
    const context = reference('posix').context;
    const result = evaluateRules({ rules: [dropRule('z-deny', 'deny'), dropRule('a-ask', 'ask'), dropRule('b-deny', 'deny')], default_unmatched: 'allow' }, { kind: 'sql', statement: 'DROP TABLE demo' }, context);
    expect(result.verdict).toBe('deny');
    expect(result.rule_id).toBe('b-deny');
    expect(result.matched_rule_ids).toEqual(['a-ask', 'b-deny', 'z-deny']);
  });

  it('keeps a visible deny alongside opaque findings and asks for opaque-only input', () => {
    // what_bug_this_catches: treating opaque input as allow, or letting it discard already-visible prohibitions.
    const mixed = verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'rm -rf / ; eval "$X"' });
    expect(mixed.verdict).toBe('deny');
    expect(mixed.matched_rule_ids).toContain('opaque-construct');
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: "eval 'rm -rf /'" }).verdict).toBe('ask');
  });

  it('fails closed for template-incompatible matches and glob budget exhaustion', () => {
    // what_bug_this_catches: imported rules bypassing template field checks or expensive matching falling through to allow.
    const context = reference('posix').context;
    const invalid: Rule = { ...dropRule('bad', 'deny'), template: 'git-release' };
    expect(evaluateRules({ rules: [invalid], default_unmatched: 'allow' }, { kind: 'sql', statement: 'SELECT 1' }, context).rule_id).toBe('opaque-construct');
    const costly: Rule = { id: 'costly', source_answer: 'Q05', template: 'secrets-paths', effect: 'deny', intent: 'Check secret names', match: [{ op: 'glob', field: 'fs.name_ci', patterns: Array.from({ length: 6 }, () => '*'.repeat(3999) + 'x') }] };
    const result = evaluateRules({ rules: [costly], default_unmatched: 'allow' }, { kind: 'fs', op: 'read', path: 'README.md' }, context);
    expect(result.verdict).toBe('ask');
    expect(result.rule_id).toBe('opaque-construct');
  });

  it('keeps invalid actions outside evaluation and supports strict unmatched policy mode', () => {
    // what_bug_this_catches: invalid payment shapes reaching normalization or strict mode being confused with a CLI exit flag.
    const { policy, context } = referencePolicy('posix');
    expect(guardInput(policy, { kind: 'payment', amount_cents: '5000', currency: 'USD' }, context).ok).toBe(false);
    const unmatched = evaluateRules({ rules: [], default_unmatched: 'ask' }, { kind: 'payment', amount_cents: 1, currency: 'USD' }, context);
    expect(unmatched).toMatchObject({ verdict: 'ask', rule_id: null, matched_rule_ids: [] });
  });
});

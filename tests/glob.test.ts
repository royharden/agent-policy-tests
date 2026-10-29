import { describe, expect, it } from 'vitest';
import { globMatch } from '../src/policyfix/glob';
import { createBudget } from '../src/policyfix/normalise/opaque';

describe('bounded glob language', () => {
  it.each([
    ['release/*', 'release/october', 'match'],
    ['release/*', 'release/october/fix', 'no-match'],
    ['secrets/**', 'secrets', 'match'],
    ['secrets/**', 'secrets/a/key', 'match'],
    ['**/.env', '.env', 'match'],
    ['**/.env', 'nested/.env', 'match'],
    ['file[0-9]?.txt', 'file7x.txt', 'match'],
    ['file[!0-9].txt', 'file7.txt', 'no-match'],
    ['literal\\*', 'literal*', 'match'],
  ] as const)('%s against %s yields %s', (pattern, value, expected) => {
    // what_bug_this_catches: path and branch stars crossing segments or mishandled classes weaken exception predicates.
    expect(globMatch(pattern, value, createBudget(), { fold: false, separator: '/' })).toBe(expected);
  });

  it('folds only when asked and charges parsing even against empty text', () => {
    // what_bug_this_catches: secrets require case folding; long patterns must not bypass the action budget on empty values.
    expect(globMatch('*.PEM', 'key.pem', createBudget(), { fold: true, separator: null })).toBe('match');
    expect(globMatch('*.PEM', 'key.pem', createBudget(), { fold: false, separator: null })).toBe('no-match');
    expect(globMatch('*'.repeat(200), '', createBudget(10), { fold: false, separator: null })).toBe('budget-exceeded');
  });
});

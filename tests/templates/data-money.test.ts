import { describe, expect, it } from 'vitest';
import { validateAction } from '../../src/policyfix/action';
import { compileOrThrow, expectTemplateExamplesHold, reference, referenceOutput, verdictOf } from '../helpers/reference';

describe('data-money template', () => {
  it('ships truthful isolation examples for every SQL and payment rule', () => {
    // what_bug_this_catches: template-authored expectations diverging from their own match predicates.
    expectTemplateExamplesHold(referenceOutput('posix'), 'data-money');
  });

  it('keeps exact cent boundaries and currency mismatch semantics', () => {
    // what_bug_this_catches: floating-point dollars, >= comparison, or comparing foreign currency to a USD threshold.
    expect(verdictOf('posix', { kind: 'payment', amount_cents: 5000, currency: 'USD' }).verdict).toBe('allow');
    expect(verdictOf('posix', { kind: 'payment', amount_cents: 5001, currency: 'USD' }).verdict).toBe('deny');
    expect(verdictOf('posix', { kind: 'payment', amount_cents: 9000, currency: 'EUR' }).verdict).toBe('ask');
  });

  it('does not invent invalid over-limit actions at the safe-integer ceiling', () => {
    // what_bug_this_catches: adding one cent to MAX_SAFE_INTEGER creates fixtures the action schema rejects.
    const ref = reference('posix');
    const output = compileOrThrow({ ...ref.answers, Q12: { limit_cents: Number.MAX_SAFE_INTEGER, currency: 'USD' } }, ref.context);
    const examples = output.examples['q12-over-limit'] ?? [];
    expect(examples.filter((example) => example.kind === 'prohibited')).toHaveLength(0);
    expect(examples.every((example) => validateAction(example.action).ok)).toBe(true);
  });
});

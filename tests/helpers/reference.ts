// Shared test helpers: the compiled reference policy (eval/gold/reference-answers.json) per context, and a checker for
// a template's declared examples in isolation. Not a test file (vitest only collects *.test.ts).
import { expect } from 'vitest';
import referenceAnswersJson from '../../eval/gold/reference-answers.json';
import type { Action, Policy, TemplateId } from '../../src/policyfix/action';
import { compile, type CompileOutput, type FreeTextItem } from '../../src/policyfix/compile';
import type { EvaluationContext } from '../../src/policyfix/context';
import { guard, guardInIsolation, type GuardResult } from '../../src/policyfix/guard';
import { type Answers, type ContextKey, parseReferenceAnswers, type ReferenceAnswers } from '../../src/policyfix/questionnaire';

export function reference(key: ContextKey): ReferenceAnswers {
  const parsed = parseReferenceAnswers(referenceAnswersJson as unknown, key);
  if (!parsed.ok) throw new Error(`reference answers invalid: ${JSON.stringify(parsed.errors)}`);
  return parsed.value;
}

export function compileOrThrow(
  answers: Answers,
  context: EvaluationContext,
  freeText: readonly FreeTextItem[] = [],
  defaultUnmatched: 'allow' | 'ask' = 'allow',
): CompileOutput {
  const result = compile(answers, freeText, context, { default_unmatched: defaultUnmatched });
  if (!result.ok) throw new Error(`compile failed: ${JSON.stringify(result.errors)}`);
  return result.value;
}

export function referenceOutput(key: ContextKey): CompileOutput {
  const ref = reference(key);
  return compileOrThrow(ref.answers, ref.context, [], ref.default_unmatched);
}

export function referencePolicy(key: ContextKey): { policy: Policy; context: EvaluationContext } {
  const output = referenceOutput(key);
  return { policy: output.policy, context: output.policy.context };
}

export function verdictOf(key: ContextKey, action: Action): GuardResult {
  const { policy, context } = referencePolicy(key);
  return guard(policy, action, context);
}

/**
 * Every rule of `template` declares ≥2 prohibited and ≥2 permitted examples, and each example's expected_local is
 * what the rule produces in isolation (only that rule + opaque-construct).
 */
export function expectTemplateExamplesHold(output: CompileOutput, template: TemplateId): void {
  const rules = output.rules.filter((rule) => rule.template === template);
  expect(rules.length).toBeGreaterThan(0);
  for (const rule of rules) {
    const examples = output.examples[rule.id] ?? [];
    const prohibited = examples.filter((example) => example.kind === 'prohibited');
    const permitted = examples.filter((example) => example.kind === 'permitted');
    expect(prohibited.length, `${rule.id} prohibited examples`).toBeGreaterThanOrEqual(2);
    expect(permitted.length, `${rule.id} permitted examples`).toBeGreaterThanOrEqual(2);
    for (const example of examples) {
      const result = guardInIsolation(rule, example.action, output.policy.context);
      expect(result.verdict, `${rule.id}/${example.id}: ${JSON.stringify(example.action)} — ${result.reason}`).toBe(
        example.expected_local,
      );
      if (example.kind === 'prohibited') {
        // The owning rule must decide — an `ask` from opaque-construct would hide a rule that never matches.
        expect(result.rule_id, `${rule.id}/${example.id} decided by ${String(result.rule_id)}`).toBe(rule.id);
      }
    }
  }
}

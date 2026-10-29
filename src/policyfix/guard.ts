// The guard (PLAN M3 AC5, A6, A9, A10; Claude §2.5 "Guard pipeline"; RUBRIC §2).
//   validate → normalise to sub-actions → evaluate every rule on every sub-action → combine deny > ask > allow
//   (ties → lowest rule id by code-unit order; every matching id is returned in matched_rule_ids) → default.
// Opaque findings, budget hits, invalid rules and unexpected evaluator exceptions are `ask` findings of the fixed
// built-in `opaque-construct` rule — never `allow`. A visible deny elsewhere in the same action still wins.
// Unmatched → policy.default_unmatched (`allow`, or `ask` in strict policy mode).
// Framework-free.
import {
  type Action,
  type DefaultUnmatched,
  evaluateValidated,
  OPAQUE_RULE_ID,
  type Policy,
  type Rule,
  type RuleEffect,
  type Verdict,
} from './action';
import type { EvaluationContext } from './context';
import type { Result } from './errors';
import { checkMatch, matchRule, type NodeOutcome } from './match';
import { describeSubAction, type Normalised, normaliseAction } from './normalise/index';
import { createBudget } from './normalise/opaque';
import { TEMPLATES_BY_ID } from './templates/index';

export interface GuardResult {
  readonly verdict: Verdict;
  /** Deciding rule id (`opaque-construct` for opaque asks); null when the default decided. */
  readonly rule_id: string | null;
  readonly reason: string;
  /** Every rule id that matched any sub-action (sorted, unique), including `opaque-construct`. */
  readonly matched_rule_ids: readonly string[];
}

/** The minimum a guard evaluation needs: the rules and the unmatched default. */
export interface RuleSet {
  readonly rules: readonly Rule[];
  readonly default_unmatched: DefaultUnmatched;
}

/** The fixed built-in fallback (PLAN A10): effect ask, source builtin, never part of policy.rules. */
export const OPAQUE_RULE = {
  id: OPAQUE_RULE_ID,
  source: 'builtin',
  effect: 'ask',
  intent: 'Ask before running anything the bounded lexical analysis cannot see into.',
} as const;

interface Finding {
  readonly rule_id: string;
  readonly effect: RuleEffect;
  readonly reason: string;
}

function compareIds(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function opaqueFindingOf(detail: string): Finding {
  return { rule_id: OPAQUE_RULE_ID, effect: 'ask', reason: `opaque construct: ${detail}` };
}

function decide(findings: readonly Finding[], defaultUnmatched: DefaultUnmatched): GuardResult {
  const matched = [...new Set(findings.map((finding) => finding.rule_id))].sort(compareIds);
  for (const effect of ['deny', 'ask'] as const) {
    const candidates = findings.filter((finding) => finding.effect === effect);
    if (candidates.length === 0) continue;
    const winner = [...candidates].sort((a, b) => compareIds(a.rule_id, b.rule_id))[0];
    if (winner === undefined) continue;
    return { verdict: effect, rule_id: winner.rule_id, reason: winner.reason, matched_rule_ids: matched };
  }
  return {
    verdict: defaultUnmatched,
    rule_id: null,
    reason:
      defaultUnmatched === 'allow'
        ? 'No rule matched; the policy default allows unmatched actions.'
        : 'No rule matched; strict policy mode asks for every unmatched action.',
    matched_rule_ids: matched,
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'unknown error';
}

/** Evaluates a schema-valid action against a rule set. Never throws; never allows on an error. */
export function evaluateRules(ruleSet: RuleSet, action: Action, context: EvaluationContext): GuardResult {
  const findings: Finding[] = [];
  for (const rule of ruleSet.rules) {
    const problem = checkMatch(rule.match, TEMPLATES_BY_ID[rule.template].fields);
    if (problem !== null) {
      return decide([opaqueFindingOf(`rule "${rule.id}" cannot be evaluated: ${problem}`)], ruleSet.default_unmatched);
    }
  }
  const budget = createBudget();
  let normalised: Normalised;
  try {
    normalised = normaliseAction(action, context, budget);
  } catch (error: unknown) {
    return decide([opaqueFindingOf(`evaluator error during normalisation: ${errorMessage(error)}`)], ruleSet.default_unmatched);
  }
  for (const finding of normalised.opaque) findings.push(opaqueFindingOf(finding.detail));
  let budgetReported = false;
  for (const sub of normalised.subs) {
    for (const rule of ruleSet.rules) {
      let outcome: NodeOutcome;
      try {
        outcome = matchRule(rule.match, sub, context, budget);
      } catch (error: unknown) {
        findings.push(opaqueFindingOf(`evaluator error in rule "${rule.id}": ${errorMessage(error)}`));
        continue;
      }
      if (outcome === 'budget-exceeded') {
        if (!budgetReported) findings.push(opaqueFindingOf(`analysis exceeded ${budget.max} steps while matching`));
        budgetReported = true;
        continue;
      }
      if (outcome) {
        findings.push({ rule_id: rule.id, effect: rule.effect, reason: `${rule.intent} (${describeSubAction(sub)})` });
      }
    }
  }
  return decide(findings, ruleSet.default_unmatched);
}

/** guard(policy, action, context) for a schema-valid action (PLAN M3 AC5). */
export function guard(policy: Policy, action: Action, context: EvaluationContext): GuardResult {
  return evaluateRules(policy, action, context);
}

/**
 * Untrusted input entry point: an action that fails the schema is never evaluated and the structured errors are
 * returned instead (PLAN M1 AC2; gold rows labelled `invalid`).
 */
export function guardInput(policy: Policy, input: unknown, context: EvaluationContext): Result<GuardResult> {
  return evaluateValidated(input, (action) => guard(policy, action, context));
}

/**
 * Isolation pass (Claude §2.8): only `rule` plus the fixed opaque fallback, as used for `expected_local` and the
 * ≥2 prohibited / ≥2 permitted check.
 */
export function guardInIsolation(
  rule: Rule,
  action: Action,
  context: EvaluationContext,
  defaultUnmatched: DefaultUnmatched = 'allow',
): GuardResult {
  return evaluateRules({ rules: [rule], default_unmatched: defaultUnmatched }, action, context);
}

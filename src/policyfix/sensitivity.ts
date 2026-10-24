import { type Fixture, OPAQUE_RULE_ID, type Policy } from './action';
import { evaluateRules, guard, type GuardResult } from './guard';

export interface SensitivityRow {
  readonly rule_id: string;
  readonly changed_fixture_ids: readonly string[];
  readonly deciding_fixture_ids: readonly string[];
  readonly matched_fixture_ids: readonly string[];
  readonly untested: boolean;
  readonly shadowed: boolean;
}

/** Delete-one verdict sensitivity. A mere change of deciding id does not prove behavior coverage. */
export function ruleSensitivity(policy: Policy, fixtures: readonly Fixture[]): readonly SensitivityRow[] {
  const full: readonly GuardResult[] = fixtures.map((fixture) => guard(policy, fixture.action, policy.context));
  return policy.rules.filter((rule) => rule.id !== OPAQUE_RULE_ID).map((rule) => {
    const changed: string[] = [];
    const deciding: string[] = [];
    const matched: string[] = [];
    const reduced = { rules: policy.rules.filter((candidate) => candidate.id !== rule.id), default_unmatched: policy.default_unmatched };
    fixtures.forEach((fixture, index) => {
      const before = full[index];
      if (before === undefined) return;
      if (before.rule_id === rule.id) deciding.push(fixture.id);
      if (before.matched_rule_ids.includes(rule.id)) matched.push(fixture.id);
      const after = evaluateRules(reduced, fixture.action, policy.context);
      if (before.verdict !== after.verdict) changed.push(fixture.id);
    });
    return { rule_id: rule.id, changed_fixture_ids: changed, deciding_fixture_ids: deciding, matched_fixture_ids: matched, untested: changed.length === 0, shadowed: matched.length > 0 && deciding.length === 0 };
  });
}

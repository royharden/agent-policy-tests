import { type Fixture, OPAQUE_RULE_ID, type Policy, validateFixtures, validatePolicy } from './action';
import { fail, makeError, ok, type Result } from './errors';
import { createFakeState, type FakeEffect, invokeFake } from './faketools';
import { evaluateRules, guard, guardInIsolation, type GuardResult } from './guard';

export interface ReplayRow {
  readonly fixture_id: string;
  readonly local: GuardResult | null;
  readonly composed: GuardResult;
  readonly effects: readonly FakeEffect[];
}

/** Pure fake replay; each fixture gets a new state and exactly one allowed-action invocation. */
export function replay(policyInput: Policy, fixturesInput: readonly Fixture[]): Result<readonly ReplayRow[]> {
  const policyResult = validatePolicy(policyInput);
  if (!policyResult.ok) return policyResult;
  const policy = policyResult.value;
  const file = validateFixtures({ fixtures: fixturesInput }, policy);
  if (!file.ok) return file;
  const rows: ReplayRow[] = [];
  for (const fixture of file.value.fixtures) {
    const rule = policy.rules.find((candidate) => candidate.id === fixture.rule_id);
    let local: GuardResult | null = null;
    if (rule !== undefined) local = guardInIsolation(rule, fixture.action, policy.context);
    else if (fixture.rule_id === OPAQUE_RULE_ID) local = evaluateRules({ rules: [], default_unmatched: 'allow' }, fixture.action, policy.context);
    const composed = guard(policy, fixture.action, policy.context);
    const state = createFakeState();
    if (composed.verdict === 'allow') invokeFake(state, fixture.action, fixture.id);
    rows.push({ fixture_id: fixture.id, local, composed, effects: [...state.effects] });
  }
  return ok(rows);
}

/** Runner/UI helper: refuses incomplete cached replay rows instead of silently omitting fixtures. */
export function checkReplayRows(fixtures: readonly Fixture[], rows: readonly ReplayRow[]): Result<ReadonlyMap<string, ReplayRow>> {
  const index = new Map(rows.map((row) => [row.fixture_id, row]));
  if (index.size !== rows.length || rows.length !== fixtures.length || fixtures.some((fixture) => !index.has(fixture.id))) {
    return fail([makeError('inconsistent', '/rows', 'Replay rows must contain every fixture exactly once.')]);
  }
  return ok(index);
}

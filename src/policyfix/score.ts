// Reports are recomputed, not assertions read from an imported report. Generated fixture metrics describe template
// self-consistency. Gold observations have their own explicit evasion flag and can use the same metric aggregator.
import { type Fixture, OPAQUE_RULE_ID, type Policy, QUESTION_IDS, TRAP_NAMES, type TrapName, type Verdict, validateFixtures, validatePolicy } from './action';
import { contextSha, fixturesSha, policySha } from './digest';
import { fail, makeError, ok, type Result } from './errors';
import { type Finding, inspectFixtures, type ItemStatus, type RuleMinimum } from './fixtures';
import { replay, type ReplayRow } from './replay';
import { ruleSensitivity, type SensitivityRow } from './sensitivity';
import { ENGINE_VERSION, GRAMMAR_VERSION } from './version';

export interface Ratio {
  readonly k: number;
  readonly n: number;
}

export function formatRatio(ratio: Ratio): string {
  return ratio.n === 0 ? 'N/A' : `${ratio.k}/${ratio.n} (${(100 * ratio.k / ratio.n).toFixed(1)}%)`;
}

export interface MetricObservation {
  readonly id: string;
  readonly expected: Verdict | 'invalid';
  readonly actual: Verdict | 'invalid';
  readonly traps: readonly TrapName[];
  /** Gold callers must supply the frozen row's explicit flag; never infer it from observed behavior. */
  readonly evasion: boolean;
}

export interface TrapCounts {
  readonly total: number;
  readonly prohibited: number;
  readonly blocked: number;
  readonly permitted: number;
  readonly allowed: number;
}

export interface ObservationMetrics {
  readonly metrics: Readonly<Record<'exact_verdict_accuracy' | 'prohibited_block_rate' | 'evasion_block_rate' | 'permitted_allow_rate' | 'false_block_rate' | 'opaque_block_rate', Ratio>>;
  readonly per_trap: Readonly<Record<TrapName, TrapCounts>>;
}

function blocked(verdict: MetricObservation['actual']): boolean {
  return verdict !== 'allow';
}

export function summarizeMetrics(observations: readonly MetricObservation[]): ObservationMetrics {
  const prohibited = observations.filter((row) => row.expected !== 'allow');
  const permitted = observations.filter((row) => row.expected === 'allow');
  const evasions = prohibited.filter((row) => row.evasion);
  const opaque = prohibited.filter((row) => row.traps.includes('opaque'));
  const ratio = (rows: readonly MetricObservation[], predicate: (row: MetricObservation) => boolean): Ratio => ({ k: rows.filter(predicate).length, n: rows.length });
  const perTrap = Object.fromEntries(TRAP_NAMES.map((trap) => {
    const rows = observations.filter((row) => row.traps.includes(trap));
    return [trap, {
      total: rows.length,
      prohibited: rows.filter((row) => row.expected !== 'allow').length,
      blocked: rows.filter((row) => row.expected !== 'allow' && blocked(row.actual)).length,
      permitted: rows.filter((row) => row.expected === 'allow').length,
      allowed: rows.filter((row) => row.expected === 'allow' && row.actual === 'allow').length,
    }];
  })) as Record<TrapName, TrapCounts>;
  return {
    metrics: {
      exact_verdict_accuracy: ratio(observations, (row) => row.expected === row.actual),
      prohibited_block_rate: ratio(prohibited, (row) => blocked(row.actual)),
      evasion_block_rate: ratio(evasions, (row) => blocked(row.actual)),
      permitted_allow_rate: ratio(permitted, (row) => row.actual === 'allow'),
      false_block_rate: ratio(permitted, (row) => blocked(row.actual)),
      opaque_block_rate: ratio(opaque, (row) => blocked(row.actual)),
    },
    per_trap: perTrap,
  };
}

export interface ScoredRow extends ReplayRow {
  readonly expected_local: Verdict;
  readonly expected_policy: Verdict;
  readonly status: ItemStatus;
  readonly findings: readonly Finding[];
}

export interface ItemScore {
  readonly source_answer: string;
  readonly status: ItemStatus;
  readonly fixture_ids: readonly string[];
  readonly findings: readonly Finding[];
}

export interface ScoreReport {
  readonly policy_sha: string;
  readonly fixtures_sha: string;
  readonly context_sha: string;
  readonly engine_version: string;
  readonly status: ItemStatus;
  readonly rows: readonly ScoredRow[];
  readonly items: readonly ItemScore[];
  readonly findings: readonly Finding[];
  readonly metrics: ObservationMetrics['metrics'] & Readonly<Record<'rule_coverage' | 'answer_coverage' | 'executable_coverage', Ratio>>;
  readonly per_trap: ObservationMetrics['per_trap'];
  readonly silent_drops: number;
  readonly minima: readonly RuleMinimum[];
  readonly sensitivity: readonly SensitivityRow[];
  readonly untested_rule_ids: readonly string[];
  readonly shadowed_rule_ids: readonly string[];
  readonly manual_item_ids: readonly string[];
  readonly opaque_fixture_ids: readonly string[];
}

function statusOf(findings: readonly Finding[]): ItemStatus {
  return findings.some((entry) => entry.severity === 'Fail') ? 'Fail' : findings.some((entry) => entry.severity === 'Gap') ? 'Gap' : 'Pass';
}

function consumesContext(policy: Policy, ruleId: string): boolean {
  const rule = policy.rules.find((candidate) => candidate.id === ruleId);
  return rule?.match.some((node) => node.field === 'fs.inside_root' || node.field.startsWith('fs.root_relative') || node.field.startsWith('fs.path')) === true;
}

/** Report-only diagnostics: no compile sidecar, cached report, supplied replay row or approval is trusted. */
export function evaluatePolicy(policyInput: Policy, fixturesInput: readonly Fixture[]): Result<ScoreReport> {
  const checkedPolicy = validatePolicy(policyInput);
  if (!checkedPolicy.ok) return checkedPolicy;
  const policy = checkedPolicy.value;
  if (policy.engine_version !== ENGINE_VERSION || policy.grammar_version !== GRAMMAR_VERSION) return fail([makeError('inconsistent', '/policy', 'Policy engine/grammar version does not match this evaluator.')]);
  const checkedFixtures = validateFixtures({ fixtures: fixturesInput }, policy);
  if (!checkedFixtures.ok) return checkedFixtures;
  const fixtures = checkedFixtures.value.fixtures;
  const replayed = replay(policy, fixtures);
  if (!replayed.ok) return replayed;
  const inspected = inspectFixtures(policy, fixtures);
  const findings: Finding[] = [...inspected.findings];
  const fixtureById = new Map(fixtures.map((fixture) => [fixture.id, fixture]));
  const sourceOf = (fixture: Fixture): string => policy.rules.find((rule) => rule.id === fixture.rule_id)?.source_answer ?? fixture.source_answer ?? '';
  const rows: ScoredRow[] = replayed.value.map((row) => {
    const fixture = fixtureById.get(row.fixture_id);
    // replay validated ids and produced each row from precisely this fixture list.
    if (fixture === undefined) throw new Error('Internal replay/fixture invariant failed.');
    const source = sourceOf(fixture);
    const expected = fixture.expected_policy ?? fixture.expected_local;
    const rowFindings: Finding[] = findings.filter((entry) => entry.fixture_ids.includes(fixture.id));
    const mismatch = (code: string, reason: string): void => {
      const entry: Finding = { code, severity: 'Fail', source_answer: source, rule_id: fixture.rule_id, fixture_ids: [fixture.id], reason };
      findings.push(entry);
      rowFindings.push(entry);
    };
    if (row.local !== null && row.local.verdict !== fixture.expected_local) mismatch('local-verdict', `Expected isolated ${fixture.expected_local}, observed ${row.local.verdict}.`);
    if (row.composed.verdict !== expected) mismatch('policy-verdict', `Expected composed ${expected}, observed ${row.composed.verdict}.`);
    if (expected !== 'allow' && row.effects.length !== 0) mismatch('prohibited-effect', 'A prohibited fixture produced a fake-tool effect.');
    if (row.composed.verdict !== 'allow' && row.effects.length !== 0) mismatch('blocked-effect', 'A blocked action must never invoke a fake tool.');
    return { ...row, expected_local: fixture.expected_local, expected_policy: expected, status: statusOf(rowFindings), findings: rowFindings };
  });
  const allSources = [...new Set<string>([...QUESTION_IDS, ...policy.dispositions.map((entry) => entry.source_answer), ...policy.rules.map((rule) => rule.source_answer), ...policy.manual_items.map((item) => item.source_answer)])];
  let covered = 0;
  let executable = 0;
  const items: ItemScore[] = [];
  for (const source of allSources) {
    const disposition = policy.dispositions.find((entry) => entry.source_answer === source);
    const sourceFixtures = fixtures.filter((fixture) => sourceOf(fixture) === source);
    const ruleHasFixtures = (id: string): boolean => fixtures.some((fixture) => fixture.rule_id === id);
    let hasCoverage = false;
    let hasExecutable = false;
    const add = (code: string, severity: 'Fail' | 'Gap', reason: string, ruleId: string | null = null): void => {
      findings.push({ code, severity, source_answer: source, rule_id: ruleId, fixture_ids: sourceFixtures.map((fixture) => fixture.id), reason });
    };
    if (disposition === undefined) add('silent-drop', 'Fail', `Source ${source} has no explicit disposition.`);
    else {
      switch (disposition.disposition) {
        case 'restricted':
          hasExecutable = disposition.rule_ids.some(ruleHasFixtures);
          hasCoverage = disposition.rule_ids.length > 0 && disposition.rule_ids.every(ruleHasFixtures);
          if (!hasCoverage) add('missing-rule-fixtures', 'Gap', 'Restriction has no fixture for one or more owning rules.');
          break;
        case 'not-restricted': {
          // Strict unmatched asks do not turn an explicitly disabled restriction into a missing permitted witness.
          const witnesses = sourceFixtures.filter((fixture) => fixture.rule_id === null && fixture.expected_local === 'allow' && fixture.conflict === undefined);
          hasCoverage = witnesses.some((fixture) => rows.find((row) => row.fixture_id === fixture.id)?.status === 'Pass');
          if (!hasCoverage) add('missing-answer-witness', 'Gap', 'Not-restricted answer needs a successful permitted witness.');
          break;
        }
        case 'parameter': {
          const consumers = policy.rules.filter((rule) => consumesContext(policy, rule.id));
          hasCoverage = consumers.some((rule) => ruleHasFixtures(rule.id)) || sourceFixtures.some((fixture) => fixture.rule_id === null && rows.find((row) => row.fixture_id === fixture.id)?.status === 'Pass');
          hasExecutable = consumers.some((rule) => ruleHasFixtures(rule.id));
          if (!hasCoverage) add('unconsumed-parameter', 'Gap', 'No fixture exercises a rule consuming this context parameter.');
          break;
        }
        case 'manual':
          hasCoverage = disposition.manual_item_ids.length > 0 && disposition.manual_item_ids.every((id) => policy.manual_items.some((item) => item.id === id && item.reason.trim() !== ''));
          add('manual-item', 'Gap', hasCoverage ? 'Manual restriction remains unexecutable after acknowledgement.' : 'Manual disposition has no explained manual marker.');
          break;
      }
      for (const rule of policy.rules.filter((candidate) => candidate.source_answer === source)) {
        if (!disposition.rule_ids.includes(rule.id)) add('silent-drop', 'Fail', `Rule ${rule.id} is omitted from its source disposition.`, rule.id);
      }
      for (const item of policy.manual_items.filter((candidate) => candidate.source_answer === source)) {
        if (!disposition.manual_item_ids.includes(item.id)) add('silent-drop', 'Fail', `Manual item ${item.id} is omitted from its source disposition.`);
      }
    }
    if (hasCoverage) covered += 1;
    if (hasExecutable) executable += 1;
    const itemFindings = findings.filter((entry) => entry.source_answer === source);
    items.push({ source_answer: source, status: statusOf(itemFindings), fixture_ids: sourceFixtures.map((fixture) => fixture.id), findings: itemFindings });
  }
  const sensitivity = ruleSensitivity(policy, fixtures);
  const observations = fixtures.map((fixture): MetricObservation => {
    const row = rows.find((candidate) => candidate.fixture_id === fixture.id);
    const expected = fixture.expected_policy ?? fixture.expected_local;
    return { id: fixture.id, expected, actual: row?.composed.verdict ?? 'invalid', traps: fixture.trap === undefined ? [] : [fixture.trap], evasion: expected !== 'allow' && fixture.trap !== undefined && !['near-miss-permitted', 'opaque'].includes(fixture.trap) };
  });
  const summary = summarizeMetrics(observations);
  const policyHash = policySha(policy);
  if (!policyHash.ok) return policyHash;
  const fixtureHash = fixturesSha(fixtures);
  if (!fixtureHash.ok) return fixtureHash;
  const contextHash = contextSha(policy.context);
  if (!contextHash.ok) return contextHash;
  return ok({
    policy_sha: policyHash.value, fixtures_sha: fixtureHash.value, context_sha: contextHash.value, engine_version: ENGINE_VERSION,
    status: statusOf(findings), rows, items, findings,
    metrics: { ...summary.metrics, rule_coverage: { k: sensitivity.filter((entry) => entry.deciding_fixture_ids.length > 0).length, n: sensitivity.length }, answer_coverage: { k: covered, n: allSources.length }, executable_coverage: { k: executable, n: allSources.length } },
    per_trap: summary.per_trap, silent_drops: findings.filter((entry) => entry.code === 'silent-drop').length, minima: inspected.minima,
    sensitivity, untested_rule_ids: sensitivity.filter((entry) => entry.untested).map((entry) => entry.rule_id), shadowed_rule_ids: sensitivity.filter((entry) => entry.shadowed).map((entry) => entry.rule_id), manual_item_ids: policy.manual_items.map((item) => item.id), opaque_fixture_ids: rows.filter((row) => row.composed.matched_rule_ids.includes(OPAQUE_RULE_ID)).map((row) => row.fixture_id),
  });
}

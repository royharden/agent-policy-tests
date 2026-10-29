// Review bindings are separate from policy_sha. UI and the M8 bundle builder share this one gate.
import { type Fixture, isQuestionId, type Policy, validateFixtures, validatePolicy } from './action';
import type { CompileOutput, Provenance } from './compile';
import { contextSha, digestOf, fixturesSha, policySha } from './digest';
import { fail, makeError, ok, type Result } from './errors';
import type { Classification, ClassifierProvider } from './freetext/classify';
import type { ThresholdConfig } from './freetext/thresholds';
import { guard } from './guard';
import type { Answers } from './questionnaire';
import type { ScoreReport } from './score';
import { ENGINE_VERSION } from './version';

export interface ReviewLine {
  readonly id: string;
  readonly text: string;
  readonly provider: ClassifierProvider;
  readonly params_text: string;
  readonly classification: Classification | null;
}

/** Includes raw editor values: typing an equivalent parameter still stales the old report. */
export interface ReviewInputs {
  readonly answers: Answers;
  readonly default_unmatched: Policy['default_unmatched'];
  readonly lines: readonly ReviewLine[];
  readonly thresholds: ThresholdConfig;
  readonly thresholds_text: string;
  readonly raw_answers: Readonly<Record<string, string>>;
  readonly revision: number;
}

export interface ApprovalRequirement {
  readonly item_id: string;
  readonly source_answer: string;
  readonly kind: 'rule' | 'manual';
  readonly label: string;
  readonly content_sha256: string;
  readonly required: boolean;
}

/** Append-only whole-item rulings (no field_id); a changed digest never inherits an old decision. */
export interface ApprovalRecord {
  readonly item_id: string;
  readonly content_sha256: string;
  readonly decision: 'approve' | 'acknowledge';
  readonly decided_at: string;
}

export interface ReviewReport extends ScoreReport {
  readonly source_sha256: string;
  readonly approvals: readonly ApprovalRecord[];
}

export interface ReviewSnapshot {
  readonly policy: Policy;
  readonly fixtures: readonly Fixture[];
  readonly inputs: ReviewInputs;
  readonly provenance: Provenance;
  readonly compiled_source_sha256: string;
  readonly requirements: readonly ApprovalRequirement[];
  readonly report: ReviewReport | null;
  readonly approvals: readonly ApprovalRecord[];
}

export interface ExportReadiness {
  readonly ready: boolean;
  readonly report_current: boolean;
  readonly missing_item_ids: readonly string[];
  readonly reasons: readonly string[];
}

export function reviewInputsSha(inputs: ReviewInputs): Result<string> {
  return digestOf(inputs);
}

function lineBinding(source: string, inputs: ReviewInputs): unknown {
  const line = inputs.lines.find((candidate) => `freetext:${candidate.id}` === source);
  if (line === undefined) return null;
  const provider = line.provider;
  return {
    ...line,
    threshold: provider === 'jev' || provider === 'llm'
      ? { value: inputs.thresholds[provider], provenance: inputs.thresholds.provenance }
      : null,
  };
}

/** Hash only actual dependencies, never the whole policy/report or another item's approval. */
export function approvalRequirements(
  compiled: Pick<CompileOutput, 'policy' | 'provenance'>,
  fixtures: readonly Fixture[],
  inputs: ReviewInputs,
): Result<readonly ApprovalRequirement[]> {
  const requirements: ApprovalRequirement[] = [];
  const observations = new Map<string, ReturnType<typeof guard>>();
  const observe = (fixture: Fixture): ReturnType<typeof guard> => {
    const cached = observations.get(fixture.id);
    if (cached !== undefined) return cached;
    const result = guard(compiled.policy, fixture.action, compiled.policy.context);
    observations.set(fixture.id, result); return result;
  };
  for (const item of [...compiled.policy.rules, ...compiled.policy.manual_items]) {
    const rule = compiled.policy.rules.find((candidate) => candidate.id === item.id);
    const parameterIds = compiled.provenance.rules[item.id]?.parameters ?? [];
    const questionIds = new Set<string>(parameterIds);
    if (isQuestionId(item.source_answer)) questionIds.add(item.source_answer);
    const answers = Object.fromEntries([...questionIds].map((id) => [id, isQuestionId(id) ? inputs.answers[id] : null]));
    const raw = Object.fromEntries(Object.entries(inputs.raw_answers).filter(([key]) => questionIds.has(key.split(':')[0] ?? '')));
    const linked = fixtures.filter((fixture) => fixture.rule_id === item.id || fixture.conflict?.owner_rule === item.id || (rule === undefined && fixture.source_answer === item.source_answer));
    const hash = digestOf({
      item, answers, raw, source: lineBinding(item.source_answer, inputs),
      default_unmatched: rule === undefined ? null : compiled.policy.default_unmatched,
      engine_version: compiled.policy.engine_version,
      grammar_version: compiled.policy.grammar_version,
      // Composed outcomes include dependencies on other rules that actually affect these fixtures.
      fixtures: linked.map((fixture) => ({ fixture, observed: observe(fixture) })),
    });
    if (!hash.ok) return hash;
    requirements.push({
      item_id: item.id, source_answer: item.source_answer, kind: rule === undefined ? 'manual' : 'rule',
      label: rule?.intent ?? ('text' in item ? item.text : item.id), content_sha256: hash.value,
      required: rule === undefined || item.source_answer.startsWith('freetext:'),
    });
  }
  return ok(requirements);
}

export function isApproved(requirement: ApprovalRequirement, records: readonly ApprovalRecord[]): boolean {
  const latest = [...records].reverse().find((record) => record.item_id === requirement.item_id);
  return latest?.content_sha256 === requirement.content_sha256
    && latest.decision === (requirement.kind === 'manual' ? 'acknowledge' : 'approve');
}

export function recordApproval(requirement: ApprovalRequirement, decidedAt: string): ApprovalRecord {
  return { item_id: requirement.item_id, content_sha256: requirement.content_sha256, decision: requirement.kind === 'manual' ? 'acknowledge' : 'approve', decided_at: decidedAt };
}

export function bindReviewReport(report: ScoreReport, inputs: ReviewInputs, approvals: readonly ApprovalRecord[]): Result<ReviewReport> {
  const source = reviewInputsSha(inputs);
  return source.ok ? ok({ ...report, source_sha256: source.value, approvals }) : source;
}

/** Pure export preflight. M8 must invoke this again at download time, using the same current snapshot. */
export function exportReadiness(snapshot: ReviewSnapshot): Result<ExportReadiness> {
  const checked = validatePolicy(snapshot.policy);
  if (!checked.ok) return checked;
  const file = validateFixtures({ fixtures: snapshot.fixtures }, snapshot.policy);
  if (!file.ok) return file;
  const source = reviewInputsSha(snapshot.inputs);
  const policy = policySha(snapshot.policy);
  const fixtures = fixturesSha(snapshot.fixtures);
  const context = contextSha(snapshot.policy.context);
  if (!source.ok) return source;
  if (!policy.ok) return policy;
  if (!fixtures.ok) return fixtures;
  if (!context.ok) return context;
  const report = snapshot.report;
  const compiledCurrent = snapshot.compiled_source_sha256 === source.value;
  const reportCurrent = compiledCurrent && report !== null
    && report.policy_sha === policy.value && report.fixtures_sha === fixtures.value
    && report.context_sha === context.value && report.engine_version === ENGINE_VERSION
    && snapshot.policy.engine_version === ENGINE_VERSION && report.source_sha256 === source.value;
  // Recompute, so an empty/stale UI requirement list cannot weaken the M8 preflight.
  const requirements = approvalRequirements({ policy: snapshot.policy, provenance: snapshot.provenance }, snapshot.fixtures, snapshot.inputs);
  if (!requirements.ok) return requirements;
  const missing = requirements.value.filter((item) => item.required && !isApproved(item, snapshot.approvals)).map((item) => item.item_id);
  const reasons: string[] = [];
  if (!compiledCurrent) reasons.push('Compile the current answers and NOT lines.');
  if (report === null) reasons.push('Replay the fixtures to create a report.');
  else if (!reportCurrent) reasons.push('The report is stale. Compile, generate fixtures if needed, and replay.');
  if (missing.length > 0) reasons.push(`Review ${missing.length} pending approval${missing.length === 1 ? '' : 's'} or manual acknowledgement${missing.length === 1 ? '' : 's'}.`);
  // Export preserves the observed Pass/Fail/Gap status; readiness never relabels or hides a Fail.
  return ok({ ready: reasons.length === 0, report_current: reportCurrent, missing_item_ids: missing, reasons });
}

/** Reject rather than trust a report copied from a different draft. No imported report becomes current. */
export function checkReportBinding(snapshot: ReviewSnapshot): Result<ReviewReport> {
  const ready = exportReadiness(snapshot);
  if (!ready.ok) return ready;
  return ready.value.report_current && snapshot.report !== null
    ? ok({ ...snapshot.report, approvals: snapshot.approvals })
    : fail([makeError('inconsistent', '/report', 'Report does not match the current policy, fixtures, context, engine and source inputs.')]);
}

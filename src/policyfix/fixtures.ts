// Declarations -> deterministic fixtures. Observations identify conflicts, but only declared ownership can change
// expected_policy. The runner can reconstruct conflict/minimum findings from policy + fixtures alone.
import {
  type Fixture, type FixtureConflict, isQuestionId, OPAQUE_RULE_ID, type Policy, type Rule, type ShellDialect,
  type TemplateId, type Verdict, validateAction, validateFixtures, validatePolicy,
} from './action';
import type { CompileOutput } from './compile';
import { canonicalJson, digestOf } from './digest';
import { fail, makeError, ok, type PolicyError, type Result } from './errors';
import { guard, guardInIsolation, type GuardResult } from './guard';
import { checkFileBytes, MAX_FIXTURES } from './limits';
import { mutateAction } from './mutators';
import { type DeclaredExample, TEMPLATES, TEMPLATES_BY_ID } from './templates/index';

export type ItemStatus = 'Pass' | 'Fail' | 'Gap';

export interface Finding {
  readonly code: string;
  readonly severity: 'Fail' | 'Gap' | 'info';
  readonly source_answer: string;
  readonly rule_id: string | null;
  readonly fixture_ids: readonly string[];
  readonly owner_rule?: string;
  readonly reason: string;
}

export interface RuleMinimum {
  readonly rule_id: string;
  readonly prohibited_fixture_ids: readonly string[];
  readonly permitted_fixture_ids: readonly string[];
}

export interface FixtureInspection {
  readonly findings: readonly Finding[];
  readonly minima: readonly RuleMinimum[];
}

export interface GenerationOutput {
  readonly fixtures: readonly Fixture[];
  readonly gaps: readonly Finding[];
  readonly conflicts: readonly Finding[];
}

export interface GenerationOptions {
  readonly seed?: number;
  readonly mutate?: boolean;
  readonly dialects?: readonly ShellDialect[];
}

function rank(verdict: Verdict): number {
  return verdict === 'deny' ? 2 : verdict === 'ask' ? 1 : 0;
}

function sourceTemplate(policy: Policy, fixture: Fixture): TemplateId | null {
  const own = policy.rules.find((rule) => rule.id === fixture.rule_id);
  if (own !== undefined) return own.template;
  const source = fixture.source_answer;
  if (source !== undefined && isQuestionId(source)) {
    return TEMPLATES.find((template) => template.answers.includes(source))?.id ?? null;
  }
  return null;
}

export interface CompositionExpectation {
  readonly expected: Verdict;
  readonly conflict: FixtureConflict | null;
  readonly undeclared_owner: string | null;
}

/** Recomputed from pinned declarations. The guard's winning verdict is never copied into an expectation. */
export function compositionExpectation(policy: Policy, fixture: Fixture, observed: GuardResult): CompositionExpectation {
  const templateId = sourceTemplate(policy, fixture);
  const template = templateId === null ? undefined : TEMPLATES_BY_ID[templateId];
  const candidates: { rule: Rule; reason: string }[] = [];
  const undeclared: { id: string; effect: Verdict }[] = [];
  for (const id of observed.matched_rule_ids) {
    if (id === fixture.rule_id) continue;
    if (id === OPAQUE_RULE_ID) {
      if (rank('ask') > rank(fixture.expected_local)) undeclared.push({ id, effect: 'ask' });
      continue;
    }
    const rule = policy.rules.find((candidate) => candidate.id === id);
    if (rule === undefined || rank(rule.effect) <= rank(fixture.expected_local)) continue;
    const declaration = template?.conflicts.find((entry) => entry.owner_template === rule.template && entry.effect === rule.effect);
    if (declaration === undefined) undeclared.push({ id, effect: rule.effect });
    else candidates.push({ rule, reason: declaration.reason });
  }
  candidates.sort((a, b) => rank(b.rule.effect) - rank(a.rule.effect) || (a.rule.id < b.rule.id ? -1 : a.rule.id > b.rule.id ? 1 : 0));
  const winner = candidates[0];
  const expected = winner?.rule.effect ?? fixture.expected_local;
  // An undeclared weaker ask does not explain a stronger declared deny. Equal/stronger undeclared blockers do fail.
  const unknown = undeclared.filter((entry) => rank(entry.effect) >= rank(expected)).sort((a, b) => rank(b.effect) - rank(a.effect) || (a.id < b.id ? -1 : 1))[0];
  if (winner !== undefined) return { expected, conflict: { owner_rule: winner.rule.id, reason: winner.reason }, undeclared_owner: unknown?.id ?? null };
  if (fixture.expected_local === 'allow' && policy.default_unmatched === 'ask' && observed.matched_rule_ids.length === 0) {
    return { expected: 'ask', conflict: null, undeclared_owner: null };
  }
  return { expected, conflict: null, undeclared_owner: unknown?.id ?? null };
}

function finding(fixture: Fixture, code: string, severity: Finding['severity'], reason: string, owner?: string): Finding {
  const base = { code, severity, source_answer: fixture.source_answer ?? '', rule_id: fixture.rule_id, fixture_ids: [fixture.id], reason };
  return owner === undefined ? base : { ...base, owner_rule: owner };
}

/** Checks imported as well as generated fixtures; sidecar generation outcomes are never required or trusted. */
export function inspectFixtures(policy: Policy, fixtures: readonly Fixture[]): FixtureInspection {
  const findings: Finding[] = [];
  const seen = new Map<string, Verdict>();
  const minima = new Map(policy.rules.map((rule) => [rule.id, { prohibited: new Set<string>(), permitted: new Set<string>() }]));
  for (const fixture of fixtures) {
    const rule = policy.rules.find((candidate) => candidate.id === fixture.rule_id);
    const source = rule?.source_answer ?? fixture.source_answer ?? '';
    if (rule !== undefined && fixture.source_answer !== undefined && fixture.source_answer !== source) {
      findings.push(finding(fixture, 'source-mismatch', 'Fail', 'Fixture source_answer disagrees with its owning rule.'));
    }
    if (fixture.rule_id === null) {
      const disposition = policy.dispositions.find((entry) => entry.source_answer === fixture.source_answer);
      if (disposition === undefined || !['parameter', 'not-restricted'].includes(disposition.disposition) || fixture.expected_local !== 'allow') {
        findings.push(finding(fixture, 'invalid-witness', 'Fail', 'Null-rule fixtures must be permitted parameter/not-restricted witnesses.'));
      }
    }
    const actionKey = canonicalJson({ rule_id: fixture.rule_id, source_answer: source, action: fixture.action });
    if (!actionKey.ok) continue; // Input validation and digesting report errors before this helper is used by the scorer.
    const previous = seen.get(actionKey.value);
    if (previous !== undefined && previous !== fixture.expected_local) findings.push(finding(fixture, 'contradictory-expectation', 'Fail', 'The same owning rule and action have contradictory local expectations.'));
    seen.set(actionKey.value, fixture.expected_local);
    const composed = guard(policy, fixture.action, policy.context);
    const expected = compositionExpectation(policy, fixture, composed);
    if (expected.undeclared_owner !== null) {
      findings.push({ ...finding(fixture, 'undeclared-conflict', 'Fail', `Undeclared composed block of ${fixture.rule_id ?? source} by ${expected.undeclared_owner}.`, expected.undeclared_owner), source_answer: source });
    }
    if (expected.conflict !== null) findings.push({ ...finding(fixture, 'declared-conflict', 'info', expected.conflict.reason, expected.conflict.owner_rule), source_answer: source });
    const suppliedExpected = fixture.expected_policy ?? fixture.expected_local;
    if (suppliedExpected !== expected.expected) findings.push({ ...finding(fixture, 'composition-expectation', 'Fail', `Declared composition expects ${expected.expected}; fixture carries ${suppliedExpected}.`), source_answer: source });
    if ((fixture.conflict?.owner_rule ?? null) !== (expected.conflict?.owner_rule ?? null)) findings.push({ ...finding(fixture, 'conflict-owner', 'Fail', 'Stored conflict owner does not match the current declaration-backed owner.'), source_answer: source });
    if (rule === undefined || fixture.conflict !== undefined || expected.conflict !== null || expected.undeclared_owner !== null) continue;
    const local = guardInIsolation(rule, fixture.action, policy.context);
    const minimum = minima.get(rule.id);
    if (minimum === undefined || local.verdict !== fixture.expected_local) continue;
    if (fixture.expected_local === 'allow') minimum.permitted.add(actionKey.value);
    else if (local.rule_id === rule.id) minimum.prohibited.add(actionKey.value);
  }
  const counts: RuleMinimum[] = [];
  for (const rule of policy.rules) {
    const count = minima.get(rule.id);
    // Resolve distinct canonical actions back to representative ids; duplicate metadata never creates extra evidence.
    const idsFor = (keys: ReadonlySet<string>): string[] => {
      const result: string[] = [];
      const remaining = new Set(keys);
      for (const fixture of fixtures) {
        if (fixture.rule_id !== rule.id) continue;
        const key = canonicalJson({ rule_id: fixture.rule_id, source_answer: rule.source_answer, action: fixture.action });
        if (key.ok && remaining.delete(key.value)) result.push(fixture.id);
      }
      return result;
    };
    const prohibited = idsFor(count?.prohibited ?? new Set<string>());
    const permitted = idsFor(count?.permitted ?? new Set<string>());
    counts.push({ rule_id: rule.id, prohibited_fixture_ids: prohibited, permitted_fixture_ids: permitted });
    for (const [kind, ids] of [['prohibited', prohibited], ['permitted', permitted]] as const) {
      if (ids.length < 2) findings.push({ code: `missing-${kind}-witness`, severity: 'Gap', source_answer: rule.source_answer, rule_id: rule.id, fixture_ids: ids, reason: `${rule.id} has ${ids.length}/2 distinct successful isolated ${kind} witnesses after conflict exclusion.` });
    }
  }
  return { findings, minima: counts };
}

type FixtureBody = Omit<Fixture, 'id'>;

/** Stable ids cover final expectations/conflict ownership, not just the input action. */
export function fixtureId(body: FixtureBody): Result<string> {
  const hash = digestOf(body);
  return hash.ok ? ok(`fx-${hash.value}`) : hash;
}

export function generateFixtures(compiled: CompileOutput, options: GenerationOptions = {}): Result<GenerationOutput> {
  const policyResult = validatePolicy(compiled.policy);
  if (!policyResult.ok) return policyResult;
  const policy = policyResult.value;
  const bodies: FixtureBody[] = [];
  const identities = new Map<string, Verdict>();
  const errors: PolicyError[] = [];
  const append = (rule: Rule | null, source: string, example: DeclaredExample, origin: Fixture['origin']): void => {
    const action = validateAction(example.action);
    if (!action.ok) {
      if (origin !== 'mutator') errors.push(makeError('invalid_value', '/examples', `Invalid declared action for ${rule?.id ?? source}: ${action.errors.map((error) => error.message).join('; ')}`));
      return; // Out-of-cap mutations are omitted, never truncated into a different action.
    }
    const key = canonicalJson({ rule_id: rule?.id ?? null, source_answer: source, action: action.value });
    if (!key.ok) { errors.push(...key.errors); return; }
    const previous = identities.get(key.value);
    if (previous !== undefined) {
      if (previous !== example.expected_local) errors.push(makeError('inconsistent', '/examples', 'Duplicate action has contradictory declared expectations.'));
      return;
    }
    identities.set(key.value, example.expected_local);
    const base: FixtureBody = { rule_id: rule?.id ?? null, source_answer: source, action: action.value, expected_local: example.expected_local, origin };
    bodies.push(example.trap === undefined ? base : { ...base, trap: example.trap });
  };
  for (const rule of policy.rules) for (const example of compiled.examples[rule.id] ?? []) append(rule, rule.source_answer, example, rule.source_answer.startsWith('freetext:') ? 'freetext' : 'template');
  for (const entry of policy.dispositions) {
    if (entry.disposition === 'not-restricted' || entry.disposition === 'parameter') {
      for (const example of compiled.witnesses[entry.source_answer] ?? []) append(null, entry.source_answer, example, 'template');
    }
  }
  // Declarations win deduplication over their mutated spellings.
  if (options.mutate !== false) {
    const originals = [...bodies];
    for (const body of originals) {
      const rule = policy.rules.find((candidate) => candidate.id === body.rule_id) ?? null;
      for (const mutation of mutateAction(body.action, body.expected_local, policy.context, { ...options, ...(rule === null ? {} : { rule }) })) {
        // A null-rule witness must remain permitted. Opaque mutations belong only to actual rule fixtures.
        if (rule === null && mutation.expected_local !== 'allow') continue;
        append(rule, body.source_answer ?? '', { id: mutation.id, kind: mutation.expected_local === 'allow' ? 'permitted' : 'prohibited', action: mutation.action, expected_local: mutation.expected_local, trap: mutation.trap, note: `Mutator ${mutation.id}: ${mutation.transform}` }, 'mutator');
      }
    }
  }
  if (errors.length > 0) return fail(errors);
  if (bodies.length > MAX_FIXTURES) return fail([makeError('too_many', '/fixtures', `Generated ${bodies.length} fixtures; cap is ${MAX_FIXTURES}.`, MAX_FIXTURES)]);
  const fixtures: Fixture[] = [];
  for (const body of bodies) {
    const draft: Fixture = { ...body, id: 'draft' };
    const observed = guard(policy, body.action, policy.context);
    const expected = compositionExpectation(policy, draft, observed);
    let finalBody: FixtureBody = body;
    if (expected.conflict !== null) finalBody = { ...body, expected_policy: expected.expected, conflict: expected.conflict };
    else if (expected.expected !== body.expected_local) finalBody = { ...body, expected_policy: expected.expected };
    const id = fixtureId(finalBody);
    if (!id.ok) return id;
    fixtures.push({ ...finalBody, id: id.value });
  }
  const file = validateFixtures({ fixtures }, policy);
  if (!file.ok) return file;
  const byteError = checkFileBytes(JSON.stringify({ fixtures: file.value.fixtures }), undefined, 'export_too_large');
  if (byteError !== null) return fail([byteError]);
  const inspected = inspectFixtures(policy, file.value.fixtures);
  return ok({ fixtures: file.value.fixtures, gaps: inspected.findings.filter((entry) => entry.severity === 'Gap'), conflicts: inspected.findings.filter((entry) => entry.code.includes('conflict') || entry.code === 'composition-expectation') });
}

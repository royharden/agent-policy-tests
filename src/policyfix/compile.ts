// Questionnaire answers + accepted free-text lines → policy (PLAN M3 AC1, A8, A10, A11; Claude §2.6).
// compile(answers, acceptedFreeText, context) → {policy, rules, manual_items, dispositions, provenance, examples, witnesses}
//   - every answer and every accepted free-text line gets exactly one disposition:
//       restricted     — compiled to ≥1 rule (with declared examples that M4 turns into fixtures);
//       not-restricted — boolean false, deny-list empty, Q10 `none`, Q12 no limit, or an allow-list switched off
//                        (permitted witnesses only; neither a rule nor a Gap);
//       parameter      — Q01 (root + context): no rule of its own, linked to every consuming rule in provenance;
//       manual         — a restriction no template can express (free text labelled manual, or unextractable
//                        parameters) → manual marker with a reason (reported as Gap by M4);
//   - Q06/Q07 enabled with an empty list compile to deny-all rules (restricted), never to "no restriction";
//   - the fixed `opaque-construct` fallback is not a rule here: the guard always applies it (PLAN A10);
//   - the final policy is re-validated with the M1 schema (ids, references, caps) before it is returned.
// Framework-free.
import {
  type DefaultUnmatched,
  type DispositionEntry,
  isValidId,
  type ManualItem,
  type Policy,
  type QuestionId,
  QUESTION_IDS,
  type Rule,
  type TemplateId,
  validatePolicy,
} from './action';
import { type EvaluationContext, validateContext } from './context';
import { fail, makeError, ok, type PolicyError, type Result, toPointer } from './errors';
import { checkMatch } from './match';
import { type Answers, validateAnswers } from './questionnaire';
import {
  type AnswerOutcome,
  type CompiledRule,
  type DeclaredExample,
  type FreeTextParams,
  type PolicyTemplate,
  TEMPLATES,
  TEMPLATES_BY_ID,
} from './templates/index';
import { ENGINE_VERSION, GRAMMAR_VERSION } from './version';

/** An accepted free-text NOT line after classification and code extraction (M5 produces these). */
export interface FreeTextItem {
  readonly id: string;
  readonly text: string;
  readonly label: TemplateId | 'manual';
  readonly params?: FreeTextParams;
  /** Why the line is manual (classifier reason, injection, …). */
  readonly reason?: string;
}

export interface CompileOptions {
  readonly default_unmatched?: DefaultUnmatched;
}

export interface RuleProvenance {
  readonly source_answer: string;
  readonly template: TemplateId;
  /** Answers consumed as parameters (e.g. Q01 for path rules). */
  readonly parameters: readonly QuestionId[];
}

export interface Provenance {
  readonly rules: Readonly<Record<string, RuleProvenance>>;
  /** Parameter answer → ids of the rules that consume it. */
  readonly parameters: Readonly<Record<string, readonly string[]>>;
  /** Parameter answers no rule consumes (reported, never a silent drop). */
  readonly unconsumed_parameters: readonly QuestionId[];
}

export interface CompileOutput {
  readonly policy: Policy;
  readonly rules: readonly Rule[];
  readonly manual_items: readonly ManualItem[];
  readonly dispositions: readonly DispositionEntry[];
  readonly provenance: Provenance;
  /** Declared examples per rule id (Claude §2.8 expected_local). */
  readonly examples: Readonly<Record<string, readonly DeclaredExample[]>>;
  /** Permitted witnesses per not-restricted source answer. */
  readonly witnesses: Readonly<Record<string, readonly DeclaredExample[]>>;
}

const PARAMETER_ANSWERS: readonly QuestionId[] = ['Q01'];

function prefixErrors(errors: readonly PolicyError[], prefix: string): PolicyError[] {
  return errors.map((error) => makeError(error.code, `${prefix}${error.pointer}`, error.message, error.limit));
}

function questionOrder(id: string): number {
  const index = (QUESTION_IDS as readonly string[]).indexOf(id);
  return index < 0 ? QUESTION_IDS.length : index;
}

interface Collected {
  readonly rules: Rule[];
  readonly manual: ManualItem[];
  readonly dispositions: DispositionEntry[];
  readonly provenance: Record<string, RuleProvenance>;
  readonly examples: Record<string, readonly DeclaredExample[]>;
  readonly witnesses: Record<string, readonly DeclaredExample[]>;
  readonly errors: PolicyError[];
}

function addRule(collected: Collected, compiled: CompiledRule, template: PolicyTemplate): string | null {
  const problem = checkMatch(compiled.rule.match, template.fields);
  if (problem !== null) {
    collected.errors.push(
      makeError('invalid_value', toPointer(['rules', compiled.rule.id]), `Template ${template.id} produced an invalid rule: ${problem}`),
    );
    return null;
  }
  let id = compiled.rule.id;
  let suffix = 2;
  while (collected.provenance[id] !== undefined) {
    id = `${compiled.rule.id}-${suffix}`;
    suffix += 1;
  }
  const rule: Rule = id === compiled.rule.id ? compiled.rule : { ...compiled.rule, id };
  collected.rules.push(rule);
  collected.provenance[id] = { source_answer: rule.source_answer, template: rule.template, parameters: compiled.parameters };
  collected.examples[id] = compiled.examples;
  return id;
}

function addOutcome(collected: Collected, outcome: AnswerOutcome, template: PolicyTemplate): void {
  const ruleIds: string[] = [];
  for (const compiled of outcome.rules) {
    const id = addRule(collected, compiled, template);
    if (id !== null) ruleIds.push(id);
  }
  collected.dispositions.push({
    source_answer: outcome.source_answer,
    disposition: outcome.disposition,
    rule_ids: ruleIds,
    manual_item_ids: [],
    reason: outcome.reason,
  });
  if (outcome.disposition === 'not-restricted') collected.witnesses[outcome.source_answer] = outcome.witnesses;
}

function addManual(collected: Collected, item: FreeTextItem, reason: string): void {
  const id = `manual:${item.id}`;
  const source = `freetext:${item.id}`;
  collected.manual.push({ id, source_answer: source, text: item.text, reason });
  collected.dispositions.push({ source_answer: source, disposition: 'manual', rule_ids: [], manual_item_ids: [id], reason });
}

function addFreeText(collected: Collected, item: FreeTextItem, index: number, context: EvaluationContext, seen: Set<string>): void {
  if (!isValidId(item.id) || item.id.length > 100) {
    collected.errors.push(makeError('invalid_value', toPointer(['acceptedFreeText', index, 'id']), 'Free-text ids must be short [A-Za-z0-9._:-] ids.'));
    return;
  }
  if (seen.has(item.id)) {
    collected.errors.push(makeError('duplicate_id', toPointer(['acceptedFreeText', index, 'id']), `Duplicate free-text id "${item.id}".`));
    return;
  }
  seen.add(item.id);
  const text = item.text.trim();
  if (text.length === 0) {
    collected.errors.push(makeError('too_short', toPointer(['acceptedFreeText', index, 'text']), 'A free-text line cannot be empty.'));
    return;
  }
  if (item.label === 'manual') {
    addManual(collected, { ...item, text }, item.reason ?? 'No template can express this restriction.');
    return;
  }
  const template = TEMPLATES_BY_ID[item.label];
  const compiled = template.compileFreeText(item.id, text, item.params ?? {}, context);
  if (compiled === null) {
    addManual(collected, { ...item, text }, `Classified as ${item.label}, but the parameters it needs could not be extracted.`);
    return;
  }
  const id = addRule(collected, compiled, template);
  collected.dispositions.push({
    source_answer: `freetext:${item.id}`,
    disposition: id === null ? 'manual' : 'restricted',
    rule_ids: id === null ? [] : [id],
    manual_item_ids: [],
    reason: id === null ? 'The compiled rule was invalid.' : `Free text compiled by ${template.id}.`,
  });
}

/** Builds the policy. Invalid answers, context or free text return structured errors and no policy. */
export function compile(
  answersInput: unknown,
  acceptedFreeText: readonly FreeTextItem[],
  contextInput: unknown,
  options: CompileOptions = {},
): Result<CompileOutput> {
  const answersResult = validateAnswers(answersInput);
  const contextResult = validateContext(contextInput);
  const inputErrors: PolicyError[] = [];
  if (!answersResult.ok) inputErrors.push(...prefixErrors(answersResult.errors, '/answers'));
  if (!contextResult.ok) inputErrors.push(...prefixErrors(contextResult.errors, '/context'));
  if (!answersResult.ok || !contextResult.ok) return fail(inputErrors);
  const answers: Answers = answersResult.value;
  const context: EvaluationContext = contextResult.value;
  if (Object.entries(answers.Q01.context).some(([key, value]) => context[key as keyof EvaluationContext] !== value)) {
    return fail([makeError('inconsistent', '/answers/Q01/context', 'Q01 must describe the context used to compile this policy.')]);
  }
  if (context.grammar_version !== GRAMMAR_VERSION) {
    return fail([
      makeError('inconsistent', '/context/grammar_version', `Context grammar_version "${context.grammar_version}" is not the engine's "${GRAMMAR_VERSION}".`),
    ]);
  }

  const collected: Collected = { rules: [], manual: [], dispositions: [], provenance: {}, examples: {}, witnesses: {}, errors: [] };
  const outcomes: { outcome: AnswerOutcome; template: PolicyTemplate }[] = [];
  for (const template of TEMPLATES) {
    for (const outcome of template.compile(answers, context)) outcomes.push({ outcome, template });
  }
  outcomes.sort((a, b) => questionOrder(a.outcome.source_answer) - questionOrder(b.outcome.source_answer));

  for (const { outcome, template } of outcomes) addOutcome(collected, outcome, template);

  const seen = new Set<string>();
  acceptedFreeText.forEach((item, index) => {
    addFreeText(collected, item, index, context, seen);
  });

  // Q01: a parameter, linked to its consumers in provenance (dispositions may only list a rule under its own answer).
  const parameters: Record<string, string[]> = {};
  const unconsumed: QuestionId[] = [];
  for (const parameter of PARAMETER_ANSWERS) {
    const consumers = Object.entries(collected.provenance)
      .filter(([, provenance]) => provenance.parameters.includes(parameter))
      .map(([id]) => id);
    parameters[parameter] = consumers;
    if (consumers.length === 0) unconsumed.push(parameter);
  }
  collected.dispositions.unshift({
    source_answer: 'Q01',
    disposition: 'parameter',
    rule_ids: [],
    manual_item_ids: [],
    reason:
      (parameters['Q01'] ?? []).length > 0
        ? `Evaluation context for ${(parameters['Q01'] ?? []).length} path-dependent rule(s).`
        : 'No compiled rule consumes the project root (reported, not dropped).',
  });

  if (collected.errors.length > 0) return fail(collected.errors);

  const candidate = {
    engine_version: ENGINE_VERSION,
    grammar_version: GRAMMAR_VERSION,
    context,
    default_unmatched: options.default_unmatched ?? 'allow',
    rules: collected.rules,
    manual_items: collected.manual,
    dispositions: collected.dispositions,
  };
  const policy = validatePolicy(candidate);
  if (!policy.ok) return fail(prefixErrors(policy.errors, '/policy'));
  return ok({
    policy: policy.value,
    rules: policy.value.rules,
    manual_items: policy.value.manual_items,
    dispositions: policy.value.dispositions,
    provenance: { rules: collected.provenance, parameters, unconsumed_parameters: unconsumed },
    examples: collected.examples,
    witnesses: collected.witnesses,
  });
}

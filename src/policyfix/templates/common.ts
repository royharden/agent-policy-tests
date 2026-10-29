// Shared template contract (PLAN M3 AC1/AC6, A12; Claude §2.6, §2.8).
// A template turns the answers it owns into rules, and declares — next to each rule, execpolicy match/not_match style —
// at least two prohibited and two permitted example actions with the verdict the template author expects when that rule
// is evaluated **in isolation** (`expected_local`: only that rule + the fixed opaque fallback + the context, with
// unmatched → allow). M4's generator turns these into fixtures and checks them; the guard never writes an expectation.
// Each template also declares conflict ownership: which templates may legitimately block its permitted near-misses in
// the composed policy, and with which effect (an undeclared composed block is a Fail in M4).
// Framework-free.
import type {
  Action,
  FsOp,
  MatchOperator,
  MessageChannel,
  QuestionId,
  Rule,
  RuleEffect,
  TemplateId,
  TrapName,
  Verdict,
} from '../action';
import type { EvaluationContext } from '../context';
import type { Answers } from '../questionnaire';

export const EXAMPLE_KINDS = ['prohibited', 'permitted'] as const;
export type ExampleKind = (typeof EXAMPLE_KINDS)[number];

export interface DeclaredExample {
  /** Stable within its rule (`p1`, `n1`, …). */
  readonly id: string;
  readonly kind: ExampleKind;
  readonly action: Action;
  /** Verdict of the owning rule in isolation. Permitted examples declare `allow` (= unmatched; M4 maps strict mode). */
  readonly expected_local: Verdict;
  readonly trap?: TrapName;
  readonly note: string;
}

export interface CompiledRule {
  readonly rule: Rule;
  /** Answers this rule consumes as parameters besides its own source answer (e.g. Q01 for path rules). */
  readonly parameters: readonly QuestionId[];
  readonly examples: readonly DeclaredExample[];
}

/** What one answer compiled to. */
export interface AnswerOutcome {
  readonly source_answer: QuestionId;
  readonly disposition: 'restricted' | 'not-restricted';
  readonly rules: readonly CompiledRule[];
  /** Permitted witnesses for a not-restricted answer (Claude §2.6: emits permitted witness fixtures only). */
  readonly witnesses: readonly DeclaredExample[];
  readonly reason: string;
}

export interface ConflictOwnership {
  /** Template whose rule may block this template's permitted near-miss in the composed policy. */
  readonly owner_template: TemplateId;
  readonly effect: RuleEffect;
  readonly reason: string;
}

/** Parameters a free-text line may carry after code extraction (RUBRIC §9 keys). */
export interface FreeTextParams {
  /** Code-extracted destination semantics. Missing polarity must never be guessed. */
  readonly polarity?: 'allow-list' | 'block-list';
  readonly fs_ops?: readonly FsOp[];
  readonly git_operation?: 'push' | 'delete' | 'protect';
  readonly command?: string;
  readonly branch?: string;
  readonly host?: string;
  readonly hosts?: readonly string[];
  readonly domain?: string;
  readonly glob?: string;
  readonly path?: string;
  readonly except?: readonly string[];
  readonly limit_cents?: number;
  readonly currency?: string;
}

export interface PolicyTemplate {
  readonly id: TemplateId;
  readonly title: string;
  /** Questionnaire answers this template consumes. */
  readonly answers: readonly QuestionId[];
  /** Per-template field/operator compatibility table (a subset of match.ts FIELD_SPECS). */
  readonly fields: Readonly<Record<string, readonly MatchOperator[]>>;
  readonly conflicts: readonly ConflictOwnership[];
  compile(answers: Answers, context: EvaluationContext): readonly AnswerOutcome[];
  /**
   * Compiles one accepted free-text line (id = the free-text item id). Returns null when the parameters this template
   * needs are missing, so the caller routes the line to `manual`.
   */
  compileFreeText(id: string, text: string, params: FreeTextParams, context: EvaluationContext): CompiledRule | null;
}

// ---- action builders for declared examples ---------------------------------------------------------------

export function sh(command: string): Action {
  return { kind: 'shell', dialect: 'posix', command };
}

export function fsAction(op: FsOp, path: string, recursive?: boolean): Action {
  return recursive === undefined ? { kind: 'fs', op, path } : { kind: 'fs', op, path, recursive };
}

export function httpGet(url: string): Action {
  return { kind: 'http', method: 'GET', url };
}

export function gitAction(...args: readonly string[]): Action {
  return { kind: 'git', args: [...args] };
}

export function sqlAction(statement: string): Action {
  return { kind: 'sql', statement };
}

export function payment(amount_cents: number, currency: string): Action {
  return { kind: 'payment', amount_cents, currency };
}

export function message(channel: MessageChannel, to: string): Action {
  return { kind: 'message', channel, to };
}

export function prohibited(id: string, action: Action, expected: 'deny' | 'ask', note: string, trap?: TrapName): DeclaredExample {
  return trap === undefined
    ? { id, kind: 'prohibited', action, expected_local: expected, note }
    : { id, kind: 'prohibited', action, expected_local: expected, note, trap };
}

export function permitted(id: string, action: Action, note: string, trap?: TrapName): DeclaredExample {
  return trap === undefined
    ? { id, kind: 'permitted', action, expected_local: 'allow', note }
    : { id, kind: 'permitted', action, expected_local: 'allow', note, trap };
}

/** A stable, id-safe slug of free text (`[a-z0-9-]`, ≤ 40 chars). */
export function slug(text: string): string {
  let out = '';
  for (const ch of text.toLowerCase()) {
    const ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
    if (ok) out += ch;
    else if (!out.endsWith('-') && out.length > 0) out += '-';
    if (out.length >= 40) break;
  }
  while (out.endsWith('-')) out = out.slice(0, -1);
  return out.length === 0 ? 'x' : out;
}

/** Trimmed, de-duplicated, non-empty items in input order. */
export function cleanList(items: readonly string[], lower = false): string[] {
  const out: string[] = [];
  for (const raw of items) {
    const item = lower ? raw.trim().toLowerCase() : raw.trim();
    if (item.length > 0 && !out.includes(item)) out.push(item);
  }
  return out;
}

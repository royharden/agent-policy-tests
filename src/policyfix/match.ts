// Structured, regex-free match evaluation (PLAN M3 AC2, A23; spec item 3). A rule's `match` is a conjunction of nodes;
// every node names a field of one normalised sub-action kind. A rule applies to a sub-action only when every node's
// field belongs to that sub-action's kind; then every node must hold.
//
// Exactly eight operators: eq, in, glob, prefix, command_name, flags_include, sql_without_where, host_not_in.
// FIELD_SPECS below is the global field/operator compatibility table; each template narrows it further
// (templates/*.ts `fields`). Semantics worth knowing:
//   - `negate` inverts the node's result. A node on a null value (e.g. fs.root_relative outside the root) is false,
//     so its negation is true.
//   - folding: `always` fields compare case-insensitively everywhere (secret names, hosts, SQL verbs); `context` fields
//     follow context.case_insensitive_fs (paths); `dialect` fields fold for PowerShell/cmd only (command names, flags).
//   - `prefix` on a list field (command.words) is a token prefix: "npm publish" matches ["npm","publish","--tag",…],
//     never ["npm","publisher"].
//   - `arg` is a numeric argument for derived fields (payment.amount_exceeds: amount > arg).
//   - `host_not_in` with an empty list is true for every host ("deny all destinations", PLAN A8).
// Glob steps come from the per-action budget; an exhausted budget is an evaluation error → ask.
// No regex literals or RegExp in this file (ESLint).
import type { Match, MatchNode, MatchOperator } from './action';
import type { EvaluationContext } from './context';
import { globMatchAny } from './glob';
import type { StepBudget } from './normalise/opaque';
import type { SubAction, SubActionKind } from './normalise/types';
import { hostInList } from './normalise/url';

export const FIELD_TYPES = ['string', 'nullable_string', 'string_list', 'boolean', 'number', 'sql'] as const;
export type FieldType = (typeof FIELD_TYPES)[number];

export const FIELD_FOLDS = ['none', 'always', 'context', 'dialect'] as const;
export type FieldFold = (typeof FIELD_FOLDS)[number];

export interface FieldSpec {
  readonly kind: SubActionKind;
  readonly type: FieldType;
  readonly fold: FieldFold;
  /** Glob separator for this field (`/` for paths and branches). */
  readonly separator: '/' | null;
  readonly ops: readonly MatchOperator[];
  /** Whether the field requires a numeric `arg`. */
  readonly needsArg: boolean;
  readonly description: string;
}

function spec(
  kind: SubActionKind,
  type: FieldType,
  fold: FieldFold,
  ops: readonly MatchOperator[],
  description: string,
  extra: { separator?: '/' | null; needsArg?: boolean } = {},
): FieldSpec {
  return { kind, type, fold, ops, description, separator: extra.separator ?? null, needsArg: extra.needsArg ?? false };
}

const TEXT_OPS: readonly MatchOperator[] = ['eq', 'in', 'glob', 'prefix'];
const BOOL_OPS: readonly MatchOperator[] = ['eq'];

/** Global field/operator compatibility table. */
export const FIELD_SPECS: Readonly<Record<string, FieldSpec>> = {
  'command.name': spec('command', 'string', 'dialect', ['command_name', 'eq', 'in'], 'program name after wrapper unwrapping'),
  'command.words': spec('command', 'string_list', 'dialect', ['prefix'], 'program name followed by its non-flag operands'),
  'command.flags': spec('command', 'string_list', 'dialect', ['flags_include'], 'expanded flags'),
  'command.dialect': spec('command', 'string', 'none', ['eq', 'in'], 'shell dialect'),
  'fs.op': spec('fs', 'string', 'none', ['eq', 'in'], 'read | write | delete | list'),
  'fs.mode': spec('fs', 'string', 'none', ['eq', 'in'], 'delete mode: plain | recursive | force | recursive-force'),
  'fs.inside_root': spec('fs', 'boolean', 'none', BOOL_OPS, 'path is inside the project root (segment boundary)'),
  'fs.path': spec('fs', 'string', 'context', TEXT_OPS, 'canonical absolute path (`/`-separated)', { separator: '/' }),
  'fs.path_ci': spec('fs', 'string', 'always', TEXT_OPS, 'canonical absolute path compared case-insensitively', { separator: '/' }),
  'fs.root_relative': spec('fs', 'nullable_string', 'context', TEXT_OPS, 'path below the project root; null outside', { separator: '/' }),
  'fs.root_relative_ci': spec('fs', 'nullable_string', 'always', TEXT_OPS, 'root_relative compared case-insensitively', { separator: '/' }),
  'fs.name': spec('fs', 'string', 'context', TEXT_OPS, 'final path segment'),
  'fs.name_ci': spec('fs', 'string', 'always', TEXT_OPS, 'final path segment compared case-insensitively'),
  'http.host': spec('http', 'string', 'always', ['eq', 'in', 'glob', 'host_not_in'], 'WHATWG hostname'),
  'http.userinfo': spec('http', 'boolean', 'none', BOOL_OPS, 'URL carries userinfo'),
  'http.method': spec('http', 'string', 'always', ['eq', 'in'], 'HTTP method'),
  'sql.verb': spec('sql', 'string', 'always', ['eq', 'in'], 'statement verb'),
  'sql.statement': spec('sql', 'sql', 'none', ['sql_without_where'], 'the statement (for sql_without_where)'),
  'git.subcommand': spec('git', 'string', 'none', ['eq', 'in'], 'git subcommand'),
  'git.operation': spec('git', 'string', 'none', ['eq', 'in'], 'push | delete | none'),
  'git.branch': spec('git', 'nullable_string', 'none', TEXT_OPS, 'destination branch; null when it depends on repository state', { separator: '/' }),
  'git.branch_known': spec('git', 'boolean', 'none', BOOL_OPS, 'destination branch is known lexically'),
  'git.force': spec('git', 'boolean', 'none', BOOL_OPS, 'push forces the update'),
  'payment.currency': spec('payment', 'string', 'none', ['eq', 'in'], 'ISO currency code'),
  'payment.amount_cents': spec('payment', 'number', 'none', ['eq', 'in'], 'amount in integer cents'),
  'payment.amount_exceeds': spec('payment', 'boolean', 'none', BOOL_OPS, 'amount_cents > arg', { needsArg: true }),
  'message.channel': spec('message', 'string', 'none', ['eq', 'in'], 'email | slack | sms | webhook'),
  'message.domain': spec('message', 'nullable_string', 'always', ['eq', 'in', 'glob', 'host_not_in'], 'recipient domain (webhook: URL host)'),
  'message.domain_status': spec('message', 'string', 'none', ['eq', 'in'], 'domain | none | ambiguous'),
  'message.userinfo': spec('message', 'boolean', 'none', BOOL_OPS, 'webhook URL carries userinfo'),
};

type FieldValue = string | null | boolean | number | readonly string[] | SubAction;

/** Reads a field from a sub-action; undefined when the field does not belong to the sub-action's kind. */
function readField(sub: SubAction, field: string, arg: string | number | undefined): FieldValue | undefined {
  switch (sub.kind) {
    case 'command':
      if (field === 'command.name') return sub.name;
      if (field === 'command.words') return sub.words;
      if (field === 'command.flags') return sub.flags;
      if (field === 'command.dialect') return sub.dialect;
      return undefined;
    case 'fs':
      if (field === 'fs.op') return sub.op;
      if (field === 'fs.mode') return sub.mode;
      if (field === 'fs.inside_root') return sub.path.inside_root;
      if (field === 'fs.path' || field === 'fs.path_ci') return sub.path.key;
      if (field === 'fs.root_relative' || field === 'fs.root_relative_ci') return sub.path.root_relative;
      if (field === 'fs.name' || field === 'fs.name_ci') return sub.path.name;
      return undefined;
    case 'http':
      if (field === 'http.host') return sub.host;
      if (field === 'http.userinfo') return sub.userinfo;
      if (field === 'http.method') return sub.method;
      return undefined;
    case 'sql':
      if (field === 'sql.verb') return sub.verb;
      if (field === 'sql.statement') return sub;
      return undefined;
    case 'git':
      if (field === 'git.subcommand') return sub.subcommand;
      if (field === 'git.operation') return sub.operation;
      if (field === 'git.branch') return sub.branch;
      if (field === 'git.branch_known') return sub.branch !== null;
      if (field === 'git.force') return sub.force;
      return undefined;
    case 'payment':
      if (field === 'payment.currency') return sub.currency;
      if (field === 'payment.amount_cents') return sub.amount_cents;
      if (field === 'payment.amount_exceeds') return typeof arg === 'number' ? sub.amount_cents > arg : undefined;
      return undefined;
    case 'message':
      if (field === 'message.channel') return sub.channel;
      if (field === 'message.domain') return sub.domain;
      if (field === 'message.domain_status') return sub.domain_status;
      if (field === 'message.userinfo') return sub.userinfo;
      return undefined;
  }
}

function shouldFold(fieldSpec: FieldSpec, sub: SubAction, context: EvaluationContext): boolean {
  switch (fieldSpec.fold) {
    case 'none':
      return false;
    case 'always':
      return true;
    case 'context':
      return context.case_insensitive_fs;
    case 'dialect':
      return sub.kind === 'command' && sub.dialect !== 'posix';
  }
}

function foldText(value: string, fold: boolean): string {
  return fold ? value.toLowerCase() : value;
}

function scalarEquals(actual: FieldValue, expected: string | number | boolean, fold: boolean): boolean {
  if (typeof actual === 'string' && typeof expected === 'string') return foldText(actual, fold) === foldText(expected, fold);
  if (typeof actual === 'number' || typeof actual === 'boolean') return actual === expected;
  return false;
}

/** Validation of one rule's match against the field table; returns an error message or null. */
export function checkMatch(match: Match, allowed?: Readonly<Record<string, readonly MatchOperator[]>>): string | null {
  if (match.length === 0) return 'a rule must contain at least one match node';
  let kind: SubActionKind | null = null;
  for (const node of match) {
    const fieldSpec = FIELD_SPECS[node.field];
    if (fieldSpec === undefined) return `unknown field "${node.field}"`;
    if (!fieldSpec.ops.includes(node.op)) return `operator "${node.op}" is not allowed on field "${node.field}"`;
    if (allowed !== undefined && allowed[node.field]?.includes(node.op) !== true) {
      return `field "${node.field}" with operator "${node.op}" is not in the template's compatibility table`;
    }
    if (fieldSpec.needsArg && typeof node.arg !== 'number') return `field "${node.field}" needs a numeric arg`;
    if (!fieldSpec.needsArg && node.arg !== undefined) return `field "${node.field}" takes no arg`;
    if (kind !== null && kind !== fieldSpec.kind) return 'a rule may only reference fields of one sub-action kind';
    kind = fieldSpec.kind;
  }
  return null;
}

/** The sub-action kind a (valid) match applies to. */
export function matchKind(match: Match): SubActionKind | null {
  const first = match[0];
  if (first === undefined) return null;
  return FIELD_SPECS[first.field]?.kind ?? null;
}

export type NodeOutcome = boolean | 'budget-exceeded';

function evaluateNodeBase(
  node: MatchNode,
  fieldSpec: FieldSpec,
  value: FieldValue,
  sub: SubAction,
  context: EvaluationContext,
  budget: StepBudget,
): NodeOutcome {
  const fold = shouldFold(fieldSpec, sub, context);
  switch (node.op) {
    case 'eq':
      return value !== null && scalarEquals(value, node.value, fold);
    case 'in':
      return value !== null && node.values.some((expected) => scalarEquals(value, expected, fold));
    case 'glob': {
      if (typeof value !== 'string') return false;
      const outcome = globMatchAny(node.patterns, value, budget, { fold, separator: fieldSpec.separator });
      if (outcome === 'budget-exceeded') return outcome;
      return outcome === 'match';
    }
    case 'prefix': {
      if (typeof value === 'string') {
        const folded = foldText(value, fold);
        return node.prefixes.some((prefix) => folded.startsWith(foldText(prefix, fold)));
      }
      if (Array.isArray(value)) {
        const words = (value as readonly string[]).map((word) => foldText(word, fold));
        return node.prefixes.some((prefix) => {
          const tokens = prefix.split(' ').filter((token) => token.length > 0).map((token) => foldText(token, fold));
          return tokens.length > 0 && tokens.length <= words.length && tokens.every((token, index) => words[index] === token);
        });
      }
      return false;
    }
    case 'command_name':
      return typeof value === 'string' && node.names.some((name) => foldText(name, fold) === foldText(value, fold));
    case 'flags_include': {
      if (!Array.isArray(value)) return false;
      const flags = (value as readonly string[]).map((flag) => foldText(flag, fold));
      return node.flags.every((flag) => flags.includes(foldText(flag, fold)));
    }
    case 'sql_without_where':
      return typeof value === 'object' && value !== null && !Array.isArray(value) && 'kind' in value && value.kind === 'sql'
        ? (node.verbs as readonly string[]).includes(value.verb) && !value.bounded
        : false;
    case 'host_not_in':
      return typeof value === 'string' && !hostInList(value, node.hosts);
  }
}

/**
 * Evaluates one rule's match against one sub-action.
 * Returns false when the rule does not apply to this sub-action's kind; `budget-exceeded` when globbing ran out of steps.
 * Throws only on an invalid match (call `checkMatch` first).
 */
export function matchRule(
  match: Match,
  sub: SubAction,
  context: EvaluationContext,
  budget: StepBudget,
): NodeOutcome {
  for (const node of match) {
    const fieldSpec = FIELD_SPECS[node.field];
    if (fieldSpec === undefined) throw new Error(`unknown field "${node.field}"`);
    if (fieldSpec.kind !== sub.kind) return false;
    const value = readField(sub, node.field, node.arg);
    if (value === undefined) return false;
    const base = evaluateNodeBase(node, fieldSpec, value, sub, context, budget);
    if (base === 'budget-exceeded') return base;
    const result = node.negate === true ? !base : base;
    if (!result) return false;
  }
  return true;
}

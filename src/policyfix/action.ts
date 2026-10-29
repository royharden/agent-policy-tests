// Core document schemas (PLAN M1 AC1, A7, A11; CONTRACTS C1): the seven-variant Action union, the regex-free
// Match AST, Rule, ManualItem, Disposition, Policy and Fixture — plus the validation API that turns untrusted
// text into typed values or structured errors. Validation never evaluates anything.
// Framework-free: zod only (PLAN A23 import boundary).
import { z } from 'zod';
import { EvaluationContextSchema } from './context';
import {
  fail,
  fromZodIssues,
  makeError,
  ok,
  type PolicyError,
  type Result,
  toPointer,
  truncateErrors,
} from './errors';
import {
  checkFileBytes,
  checkJsonDepth,
  MAX_COMMAND_CHARS,
  MAX_DISPOSITIONS,
  MAX_FIELD_NAME_CHARS,
  MAX_FIXTURES,
  MAX_GIT_ARGS,
  MAX_ID_CHARS,
  MAX_LIST_ITEMS,
  MAX_MANUAL_ITEMS,
  MAX_MATCH_NODES,
  MAX_REPORTED_ERRORS,
  MAX_RULES,
  MAX_TEXT_CHARS,
  MAX_VERSION_CHARS,
} from './limits';

// =========================================================================================================
// Vocabularies
// =========================================================================================================

export const ACTION_KINDS = ['shell', 'fs', 'http', 'sql', 'git', 'payment', 'message'] as const;
export type ActionKind = (typeof ACTION_KINDS)[number];

export const SHELL_DIALECTS = ['posix', 'powershell', 'cmd'] as const;
export type ShellDialect = (typeof SHELL_DIALECTS)[number];

export const FS_OPS = ['read', 'write', 'delete', 'list'] as const;
export type FsOp = (typeof FS_OPS)[number];

export const HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

export const MESSAGE_CHANNELS = ['email', 'slack', 'sms', 'webhook'] as const;
export type MessageChannel = (typeof MESSAGE_CHANNELS)[number];

/** Guard verdicts; precedence deny > ask > allow. */
export const VERDICTS = ['deny', 'ask', 'allow'] as const;
export type Verdict = (typeof VERDICTS)[number];

/** Effects a rule can have (a rule never allows; allow is the unmatched default). */
export const RULE_EFFECTS = ['deny', 'ask'] as const;
export type RuleEffect = (typeof RULE_EFFECTS)[number];

/** policy.default_unmatched (PLAN A9): 'ask' = strict policy mode. Distinct from the runner's --strict flag. */
export const DEFAULT_UNMATCHED = ['allow', 'ask'] as const;
export type DefaultUnmatched = (typeof DEFAULT_UNMATCHED)[number];

export const TEMPLATE_IDS = [
  'destructive-shell-fs',
  'secrets-paths',
  'network-egress',
  'git-release',
  'data-money',
] as const;
export type TemplateId = (typeof TEMPLATE_IDS)[number];

/** Questionnaire answer ids (PLAN A8, Claude §2.6). */
export const QUESTION_IDS = ['Q01', 'Q02', 'Q03', 'Q04', 'Q05', 'Q06', 'Q07', 'Q08', 'Q09', 'Q10', 'Q11', 'Q12'] as const;
export type QuestionId = (typeof QUESTION_IDS)[number];

/** The 13 named traps (spec; both FINAL plans). */
export const TRAP_NAMES = [
  'flag-reorder',
  'path-traversal',
  'case-fold',
  'prefix-wrap',
  'shell-wrapper',
  'chained',
  'sql-comment-split',
  'url-lookalike',
  'refspec-trick',
  'amount-boundary',
  'dialect-swap',
  'opaque',
  'near-miss-permitted',
] as const;
export type TrapName = (typeof TRAP_NAMES)[number];

export const FIXTURE_ORIGINS = ['template', 'mutator', 'gold', 'freetext'] as const;
export type FixtureOrigin = (typeof FIXTURE_ORIGINS)[number];

/** Answer dispositions (PLAN A8, Claude §2.6). */
export const DISPOSITIONS = ['restricted', 'not-restricted', 'parameter', 'manual'] as const;
export type Disposition = (typeof DISPOSITIONS)[number];

/** The fixed built-in fallback rule (PLAN A10): effect ask, not disableable, never part of policy.rules. */
export const OPAQUE_RULE_ID = 'opaque-construct';
/** Ids a user/compiled rule may not take. */
export const RESERVED_RULE_IDS: readonly string[] = [OPAQUE_RULE_ID];

/** Prefix of a source_answer that came from an accepted free-text NOT line, e.g. `freetext:ft-1`. */
export const FREETEXT_SOURCE_PREFIX = 'freetext:';

// =========================================================================================================
// Character-class helpers (code-based, no regex: the same helpers are safe to reuse from match/glob)
// =========================================================================================================

function isAsciiDigit(ch: string): boolean {
  return ch >= '0' && ch <= '9';
}

function isAsciiLower(ch: string): boolean {
  return ch >= 'a' && ch <= 'z';
}

function isAsciiUpper(ch: string): boolean {
  return ch >= 'A' && ch <= 'Z';
}

function isAsciiAlnum(ch: string): boolean {
  return isAsciiDigit(ch) || isAsciiLower(ch) || isAsciiUpper(ch);
}

/** Id: 1..MAX_ID_CHARS of `[A-Za-z0-9._:-]`, starting with a letter or digit. */
export function isValidId(value: string): boolean {
  if (value.length === 0 || value.length > MAX_ID_CHARS) return false;
  if (!isAsciiAlnum(value.charAt(0))) return false;
  for (const ch of value) {
    if (!(isAsciiAlnum(ch) || ch === '.' || ch === '_' || ch === ':' || ch === '-')) return false;
  }
  return true;
}

/** Match field name: dot-separated segments of `[a-z][a-z0-9_]*`, e.g. `shell.command_name`, `fs.path`. */
export function isValidFieldName(value: string): boolean {
  if (value.length === 0 || value.length > MAX_FIELD_NAME_CHARS) return false;
  for (const segment of value.split('.')) {
    if (segment.length === 0 || !isAsciiLower(segment.charAt(0))) return false;
    for (const ch of segment) {
      if (!(isAsciiLower(ch) || isAsciiDigit(ch) || ch === '_')) return false;
    }
  }
  return true;
}

/** ISO-4217-shaped currency code: exactly three ASCII upper-case letters (checked by code, CONTRACTS C1). */
export function isCurrencyCode(value: string): boolean {
  return value.length === 3 && [...value].every(isAsciiUpper);
}

export function isQuestionId(value: string): value is QuestionId {
  return (QUESTION_IDS as readonly string[]).includes(value);
}

/** A source_answer is a question id (`Q01`..`Q12`) or `freetext:<id>`. */
export function isValidSourceAnswer(value: string): boolean {
  if (isQuestionId(value)) return true;
  return value.startsWith(FREETEXT_SOURCE_PREFIX) && isValidId(value.slice(FREETEXT_SOURCE_PREFIX.length));
}

/** Joined length of a git argv as it would be displayed (`args.join(' ')`). */
export function joinedArgvLength(args: readonly string[]): number {
  let total = 0;
  for (const arg of args) total += arg.length;
  return total + Math.max(0, args.length - 1);
}

// =========================================================================================================
// Action (CONTRACTS C1)
// =========================================================================================================

const boundedText = z.string().min(1).max(MAX_COMMAND_CHARS);

export const ShellActionSchema = z
  .object({ kind: z.literal('shell'), dialect: z.enum(SHELL_DIALECTS), command: boundedText })
  .strict();

export const FsActionSchema = z
  .object({ kind: z.literal('fs'), op: z.enum(FS_OPS), path: boundedText, recursive: z.boolean().optional() })
  .strict();

export const HttpActionSchema = z
  .object({ kind: z.literal('http'), method: z.enum(HTTP_METHODS), url: boundedText })
  .strict();

export const SqlActionSchema = z.object({ kind: z.literal('sql'), statement: boundedText }).strict();

const GitArgsSchema = z
  .array(z.string().max(MAX_COMMAND_CHARS))
  .max(MAX_GIT_ARGS)
  .superRefine((args, ctx) => {
    const joined = joinedArgvLength(args);
    if (joined > MAX_COMMAND_CHARS) {
      ctx.addIssue({
        code: 'custom',
        message: `Joined git argv is ${joined} characters; the cap is ${MAX_COMMAND_CHARS}.`,
        params: { code: 'too_long', limit: MAX_COMMAND_CHARS },
      });
    }
  });

export const GitActionSchema = z.object({ kind: z.literal('git'), args: GitArgsSchema }).strict();

const CurrencySchema = z
  .string()
  .length(3)
  .superRefine((value, ctx) => {
    if (!isCurrencyCode(value)) {
      ctx.addIssue({
        code: 'custom',
        message: 'Currency must be three upper-case ASCII letters (e.g. USD).',
        params: { code: 'invalid_value' },
      });
    }
  });

export const PaymentActionSchema = z
  .object({
    kind: z.literal('payment'),
    // Integer cents only: NaN/Infinity, fractional, negative and unsafe integers are rejected.
    amount_cents: z.number().finite().int().min(0).max(Number.MAX_SAFE_INTEGER),
    currency: CurrencySchema,
  })
  .strict();

export const MessageActionSchema = z
  .object({ kind: z.literal('message'), channel: z.enum(MESSAGE_CHANNELS), to: boundedText })
  .strict();

export const ActionSchema = z.discriminatedUnion('kind', [
  ShellActionSchema,
  FsActionSchema,
  HttpActionSchema,
  SqlActionSchema,
  GitActionSchema,
  PaymentActionSchema,
  MessageActionSchema,
]);

export type ShellAction = z.infer<typeof ShellActionSchema>;
export type FsAction = z.infer<typeof FsActionSchema>;
export type HttpAction = z.infer<typeof HttpActionSchema>;
export type SqlAction = z.infer<typeof SqlActionSchema>;
export type GitAction = z.infer<typeof GitActionSchema>;
export type PaymentAction = z.infer<typeof PaymentActionSchema>;
export type MessageAction = z.infer<typeof MessageActionSchema>;
export type Action = z.infer<typeof ActionSchema>;

// =========================================================================================================
// Match AST (regex-free structured match language, PLAN M3 AC2)
//
// A rule's `match` is a conjunction: every node must hold on the same normalised sub-action. Each node names
// a template-defined `field` (the per-template field/operator compatibility table lives in M3's templates);
// `arg` is an optional template-defined field argument (e.g. a limit for a derived field); `negate` inverts
// the node (used for exception lists such as Q03's excluded directories or Q05's `.env.example`).
// Exactly eight operators exist; there is deliberately no regex operator.
// =========================================================================================================

export const MATCH_OPERATORS = [
  'eq',
  'in',
  'glob',
  'prefix',
  'command_name',
  'flags_include',
  'sql_without_where',
  'host_not_in',
] as const;
export type MatchOperator = (typeof MATCH_OPERATORS)[number];

export const SQL_WHERE_VERBS = ['DELETE', 'UPDATE'] as const;
export type SqlWhereVerb = (typeof SQL_WHERE_VERBS)[number];

const FieldNameSchema = z
  .string()
  .min(1)
  .max(MAX_FIELD_NAME_CHARS)
  .superRefine((value, ctx) => {
    if (!isValidFieldName(value)) {
      ctx.addIssue({
        code: 'custom',
        message: 'Field names are dot-separated lower-case segments, e.g. "shell.command_name".',
        params: { code: 'invalid_value' },
      });
    }
  });

const MatchTextSchema = z.string().max(MAX_COMMAND_CHARS);
const MatchScalarSchema = z.union([MatchTextSchema, z.number().finite(), z.boolean()]);
const MatchArgSchema = z.union([MatchTextSchema, z.number().finite()]);
const NonEmptyTextList = z.array(z.string().min(1).max(MAX_COMMAND_CHARS)).min(1).max(MAX_LIST_ITEMS);

const nodeBase = {
  field: FieldNameSchema,
  arg: MatchArgSchema.optional(),
  negate: z.boolean().optional(),
};

/** field equals value. */
export const EqNodeSchema = z.object({ op: z.literal('eq'), ...nodeBase, value: MatchScalarSchema }).strict();
/** field equals one of values. */
export const InNodeSchema = z
  .object({ op: z.literal('in'), ...nodeBase, values: z.array(MatchScalarSchema).min(1).max(MAX_LIST_ITEMS) })
  .strict();
/** field matches any glob pattern (own step-budgeted matcher, M3). */
export const GlobNodeSchema = z.object({ op: z.literal('glob'), ...nodeBase, patterns: NonEmptyTextList }).strict();
/** field starts with any prefix. */
export const PrefixNodeSchema = z.object({ op: z.literal('prefix'), ...nodeBase, prefixes: NonEmptyTextList }).strict();
/** normalised command name (after wrapper unwrapping and alias resolution) is one of names. */
export const CommandNameNodeSchema = z
  .object({ op: z.literal('command_name'), ...nodeBase, names: NonEmptyTextList })
  .strict();
/** every listed flag is present after flag expansion (`-rf` → `-r`, `-f`; PowerShell prefix abbreviation). */
export const FlagsIncludeNodeSchema = z
  .object({ op: z.literal('flags_include'), ...nodeBase, flags: NonEmptyTextList })
  .strict();
/** a top-level SQL statement with one of verbs has no WHERE clause. */
export const SqlWithoutWhereNodeSchema = z
  .object({
    op: z.literal('sql_without_where'),
    ...nodeBase,
    verbs: z.array(z.enum(SQL_WHERE_VERBS)).min(1).max(SQL_WHERE_VERBS.length),
  })
  .strict();
/** host/domain is not in the allow-list. An empty list means "deny all destinations" (PLAN A8). */
export const HostNotInNodeSchema = z
  .object({
    op: z.literal('host_not_in'),
    ...nodeBase,
    hosts: z.array(z.string().min(1).max(MAX_COMMAND_CHARS)).max(MAX_LIST_ITEMS),
  })
  .strict();

export const MatchNodeSchema = z.discriminatedUnion('op', [
  EqNodeSchema,
  InNodeSchema,
  GlobNodeSchema,
  PrefixNodeSchema,
  CommandNameNodeSchema,
  FlagsIncludeNodeSchema,
  SqlWithoutWhereNodeSchema,
  HostNotInNodeSchema,
]);
export type MatchNode = z.infer<typeof MatchNodeSchema>;

export const MatchSchema = z.array(MatchNodeSchema).min(1).max(MAX_MATCH_NODES);
export type Match = z.infer<typeof MatchSchema>;

// =========================================================================================================
// Rule, manual item, disposition, policy
// =========================================================================================================

function idSchema(label: string): z.ZodEffects<z.ZodString, string, string> {
  return z
    .string()
    .min(1)
    .max(MAX_ID_CHARS)
    .superRefine((value, ctx) => {
      if (!isValidId(value)) {
        ctx.addIssue({
          code: 'custom',
          message: `${label} must be 1..${MAX_ID_CHARS} characters of [A-Za-z0-9._:-], starting with a letter or digit.`,
          params: { code: 'invalid_value' },
        });
      }
    });
}

const RuleIdSchema = idSchema('Rule id').superRefine((value, ctx) => {
  if (RESERVED_RULE_IDS.includes(value)) {
    ctx.addIssue({
      code: 'custom',
      message: `"${value}" is a built-in rule id and cannot be defined, replaced or disabled.`,
      params: { code: 'reserved_id' },
    });
  }
});

const SourceAnswerSchema = z
  .string()
  .min(1)
  .max(MAX_ID_CHARS)
  .superRefine((value, ctx) => {
    if (!isValidSourceAnswer(value)) {
      ctx.addIssue({
        code: 'custom',
        message: 'source_answer must be a question id (Q01..Q12) or "freetext:<id>".',
        params: { code: 'invalid_value' },
      });
    }
  });

const ProseSchema = z.string().min(1).max(MAX_TEXT_CHARS);
const VersionSchema = z.string().min(1).max(MAX_VERSION_CHARS);

export const RuleSchema = z
  .object({
    id: RuleIdSchema,
    source_answer: SourceAnswerSchema,
    template: z.enum(TEMPLATE_IDS),
    effect: z.enum(RULE_EFFECTS),
    match: MatchSchema,
    intent: ProseSchema,
  })
  .strict();
export type Rule = z.infer<typeof RuleSchema>;

export const ManualItemSchema = z
  .object({
    id: idSchema('Manual item id'),
    source_answer: SourceAnswerSchema,
    text: ProseSchema,
    reason: ProseSchema,
  })
  .strict();
export type ManualItem = z.infer<typeof ManualItemSchema>;

export const DispositionEntrySchema = z
  .object({
    source_answer: SourceAnswerSchema,
    disposition: z.enum(DISPOSITIONS),
    rule_ids: z.array(idSchema('Rule id')).max(MAX_RULES),
    manual_item_ids: z.array(idSchema('Manual item id')).max(MAX_MANUAL_ITEMS),
    reason: ProseSchema.optional(),
  })
  .strict();
export type DispositionEntry = z.infer<typeof DispositionEntrySchema>;

const PolicyObjectSchema = z
  .object({
    engine_version: VersionSchema,
    grammar_version: VersionSchema,
    context: EvaluationContextSchema,
    default_unmatched: z.enum(DEFAULT_UNMATCHED),
    rules: z.array(RuleSchema).max(MAX_RULES),
    manual_items: z.array(ManualItemSchema).max(MAX_MANUAL_ITEMS),
    dispositions: z.array(DispositionEntrySchema).max(MAX_DISPOSITIONS),
  })
  .strict();

type PolicyShape = z.infer<typeof PolicyObjectSchema>;

function addIssueAt(
  ctx: z.RefinementCtx,
  path: (string | number)[],
  code: 'duplicate_id' | 'dangling_reference' | 'inconsistent',
  message: string,
): void {
  ctx.addIssue({ code: 'custom', path, message, params: { code } });
}

/** Cross-field integrity: unique ids, no dangling references, consistent grammar version. */
function checkPolicyIntegrity(policy: PolicyShape, ctx: z.RefinementCtx): void {
  const ruleSource = new Map<string, string>();
  policy.rules.forEach((rule, index) => {
    if (ruleSource.has(rule.id)) {
      addIssueAt(ctx, ['rules', index, 'id'], 'duplicate_id', `Duplicate rule id "${rule.id}".`);
    } else {
      ruleSource.set(rule.id, rule.source_answer);
    }
  });

  const manualSource = new Map<string, string>();
  policy.manual_items.forEach((item, index) => {
    if (manualSource.has(item.id)) {
      addIssueAt(ctx, ['manual_items', index, 'id'], 'duplicate_id', `Duplicate manual item id "${item.id}".`);
    } else {
      manualSource.set(item.id, item.source_answer);
    }
  });

  const seenAnswers = new Set<string>();
  policy.dispositions.forEach((entry, index) => {
    if (seenAnswers.has(entry.source_answer)) {
      addIssueAt(
        ctx,
        ['dispositions', index, 'source_answer'],
        'duplicate_id',
        `Answer "${entry.source_answer}" has more than one disposition.`,
      );
    }
    seenAnswers.add(entry.source_answer);
    entry.rule_ids.forEach((ruleId, ruleIndex) => {
      const source = ruleSource.get(ruleId);
      if (source === undefined) {
        addIssueAt(ctx, ['dispositions', index, 'rule_ids', ruleIndex], 'dangling_reference', `Unknown rule id "${ruleId}".`);
      } else if (source !== entry.source_answer) {
        addIssueAt(
          ctx,
          ['dispositions', index, 'rule_ids', ruleIndex],
          'inconsistent',
          `Rule "${ruleId}" belongs to answer "${source}", not "${entry.source_answer}".`,
        );
      }
    });
    entry.manual_item_ids.forEach((itemId, itemIndex) => {
      const source = manualSource.get(itemId);
      if (source === undefined) {
        addIssueAt(
          ctx,
          ['dispositions', index, 'manual_item_ids', itemIndex],
          'dangling_reference',
          `Unknown manual item id "${itemId}".`,
        );
      } else if (source !== entry.source_answer) {
        addIssueAt(
          ctx,
          ['dispositions', index, 'manual_item_ids', itemIndex],
          'inconsistent',
          `Manual item "${itemId}" belongs to answer "${source}", not "${entry.source_answer}".`,
        );
      }
    });
  });

  if (policy.context.grammar_version !== policy.grammar_version) {
    addIssueAt(
      ctx,
      ['context', 'grammar_version'],
      'inconsistent',
      `context.grammar_version "${policy.context.grammar_version}" differs from policy grammar_version "${policy.grammar_version}".`,
    );
  }
}

export const PolicySchema = PolicyObjectSchema.superRefine(checkPolicyIntegrity);
export type Policy = z.infer<typeof PolicySchema>;

// =========================================================================================================
// Fixture (PLAN A11) and fixtures file
// =========================================================================================================

export const FixtureConflictSchema = z
  .object({ owner_rule: idSchema('Owner rule id'), reason: ProseSchema })
  .strict();
export type FixtureConflict = z.infer<typeof FixtureConflictSchema>;

const FixtureObjectSchema = z
  .object({
    id: idSchema('Fixture id'),
    // null only for source_answer-tagged parameter / not-restricted witnesses (A11, checked below).
    rule_id: idSchema('Rule id').nullable(),
    action: ActionSchema,
    expected_local: z.enum(VERDICTS),
    expected_policy: z.enum(VERDICTS).optional(),
    origin: z.enum(FIXTURE_ORIGINS),
    trap: z.enum(TRAP_NAMES).optional(),
    conflict: FixtureConflictSchema.optional(),
    source_answer: SourceAnswerSchema.optional(),
  })
  .strict();

export const FixtureSchema = FixtureObjectSchema.superRefine((fixture, ctx) => {
  if (fixture.rule_id === null && fixture.source_answer === undefined) {
    ctx.addIssue({
      code: 'custom',
      path: ['rule_id'],
      message: 'rule_id may be null only on a source_answer-tagged witness fixture.',
      params: { code: 'invalid_value' },
    });
  }
  if (fixture.conflict !== undefined && fixture.expected_policy === undefined) {
    ctx.addIssue({
      code: 'custom',
      path: ['expected_policy'],
      message: 'A fixture with a declared conflict must carry expected_policy.',
      params: { code: 'inconsistent' },
    });
  }
});
export type Fixture = z.infer<typeof FixtureSchema>;

export const FixturesFileSchema = z
  .object({ fixtures: z.array(FixtureSchema).max(MAX_FIXTURES) })
  .strict()
  .superRefine((file, ctx) => {
    const seen = new Set<string>();
    file.fixtures.forEach((fixture, index) => {
      if (seen.has(fixture.id)) {
        addIssueAt(ctx, ['fixtures', index, 'id'], 'duplicate_id', `Duplicate fixture id "${fixture.id}".`);
      }
      seen.add(fixture.id);
    });
  });
export type FixturesFile = z.infer<typeof FixturesFileSchema>;

// =========================================================================================================
// Validation API — every function returns a Result and never throws or evaluates.
// =========================================================================================================

function validateWith<T>(schema: z.ZodType<T, z.ZodTypeDef, unknown>, value: unknown): Result<T> {
  const parsed = schema.safeParse(value);
  if (parsed.success) return ok(parsed.data);
  return fail(truncateErrors(fromZodIssues(parsed.error.issues), MAX_REPORTED_ERRORS));
}

/**
 * Untrusted text → JSON value. Order matters: the UTF-8 byte cap and the nesting-depth cap are checked on the
 * raw text first, so an oversized or deeply nested document never reaches JSON.parse.
 */
export function parseImportText(text: string): Result<unknown> {
  const sizeError = checkFileBytes(text);
  if (sizeError !== null) return fail([sizeError]);
  const depthError = checkJsonDepth(text);
  if (depthError !== null) return fail([depthError]);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : 'unparsable JSON';
    return fail([makeError('invalid_json', '', `Invalid JSON: ${detail}`)]);
  }
  return ok(value);
}

export function validateAction(value: unknown): Result<Action> {
  return validateWith(ActionSchema, value);
}

export function validatePolicy(value: unknown): Result<Policy> {
  return validateWith(PolicySchema, value);
}

/** Cross-references fixtures against a validated policy: rule ids, conflict owners and source answers must exist. */
export function checkFixtureReferences(file: FixturesFile, policy: Policy): PolicyError[] {
  const ruleIds = new Set<string>([OPAQUE_RULE_ID, ...policy.rules.map((rule) => rule.id)]);
  const answers = new Set<string>(policy.dispositions.map((entry) => entry.source_answer));
  const errors: PolicyError[] = [];
  file.fixtures.forEach((fixture, index) => {
    if (fixture.rule_id !== null && !ruleIds.has(fixture.rule_id)) {
      errors.push(
        makeError(
          'dangling_reference',
          toPointer(['fixtures', index, 'rule_id']),
          `Fixture refers to unknown rule "${fixture.rule_id}".`,
        ),
      );
    }
    if (fixture.conflict !== undefined && !ruleIds.has(fixture.conflict.owner_rule)) {
      errors.push(
        makeError(
          'dangling_reference',
          toPointer(['fixtures', index, 'conflict', 'owner_rule']),
          `Conflict owner refers to unknown rule "${fixture.conflict.owner_rule}".`,
        ),
      );
    }
    if (fixture.source_answer !== undefined && !answers.has(fixture.source_answer)) {
      errors.push(
        makeError(
          'dangling_reference',
          toPointer(['fixtures', index, 'source_answer']),
          `Fixture refers to answer "${fixture.source_answer}", which has no disposition in the policy.`,
        ),
      );
    }
  });
  return errors;
}

/** Validates a fixtures file value; with a policy, also rejects dangling rule/answer references. */
export function validateFixtures(value: unknown, policy?: Policy): Result<FixturesFile> {
  const result = validateWith(FixturesFileSchema, value);
  if (!result.ok || policy === undefined) return result;
  const referenceErrors = checkFixtureReferences(result.value, policy);
  return referenceErrors.length === 0 ? result : fail(truncateErrors(referenceErrors, MAX_REPORTED_ERRORS));
}

export function parseAction(text: string): Result<Action> {
  const json = parseImportText(text);
  return json.ok ? validateAction(json.value) : json;
}

export function parsePolicy(text: string): Result<Policy> {
  const json = parseImportText(text);
  return json.ok ? validatePolicy(json.value) : json;
}

export function parseFixtures(text: string, policy?: Policy): Result<FixturesFile> {
  const json = parseImportText(text);
  return json.ok ? validateFixtures(json.value, policy) : json;
}

/**
 * The only bridge from untrusted input to evaluation: `evaluate` runs only on a schema-valid Action. Invalid
 * input returns the structured errors and the evaluator is never called (PLAN M1 AC2). M3's guard entry point
 * is built on this.
 */
export function evaluateValidated<T>(input: unknown, evaluate: (action: Action) => T): Result<T> {
  const action = validateAction(input);
  return action.ok ? ok(evaluate(action.value)) : action;
}

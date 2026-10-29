// The 12-question questionnaire (PLAN M3 AC1, A8; Claude §2.6; CONTRACTS C3): stable ids, typed answer schemas,
// defaults, and the reference-answer loader used by both the UI ("Load sample answers") and the eval.
// Dispositions (restricted / not-restricted / parameter / manual) are assigned by compile.ts.
// Framework-free.
import { z } from 'zod';
import {
  isCurrencyCode,
  type QuestionId,
  QUESTION_IDS,
  type TemplateId,
  DEFAULT_UNMATCHED,
  type DefaultUnmatched,
} from './action';
import { type EvaluationContext, EvaluationContextSchema } from './context';
import { fail, fromZodIssues, makeError, ok, type Result, truncateErrors } from './errors';
import { MAX_COMMAND_CHARS, MAX_LIST_ITEMS, MAX_REPORTED_ERRORS } from './limits';

export const ANSWER_TYPES = ['context', 'bool', 'bool+globs', 'globs', 'flag+hosts', 'mode', 'cents+currency'] as const;
export type AnswerType = (typeof ANSWER_TYPES)[number];

export interface QuestionDefinition {
  readonly id: QuestionId;
  readonly title: string;
  readonly prompt: string;
  readonly answer_type: AnswerType;
  /** Template the answer compiles into; null for Q01 (a parameter of every fs/shell rule). */
  readonly template: TemplateId | null;
  readonly help: string;
}

export const QUESTIONS: readonly QuestionDefinition[] = [
  {
    id: 'Q01',
    title: 'Project root and evaluation context',
    prompt: 'Project root (and evaluation context: cwd, home, path flavour)',
    answer_type: 'context',
    template: null,
    help: 'Paths are resolved lexically against this synthetic context; the real filesystem is never read.',
  },
  {
    id: 'Q02',
    title: 'Deletes and writes outside the root',
    prompt: 'Block deletes and writes outside the project root?',
    answer_type: 'bool',
    template: 'destructive-shell-fs',
    help: 'rm/rmdir/unlink, redirects (> >> 2> &>), tee, cp/mv destinations, touch, mkdir, fs delete/write actions.',
  },
  {
    id: 'Q03',
    title: 'Recursive or force deletes inside the root',
    prompt: 'Block recursive/force deletes inside the root, except these root-level directories',
    answer_type: 'bool+globs',
    template: 'destructive-shell-fs',
    help: 'Exceptions are directories directly under the root (and everything inside them), e.g. node_modules, dist, .cache.',
  },
  {
    id: 'Q04',
    title: 'Privilege elevation',
    prompt: 'Block privilege elevation (sudo, doas, runas, Start-Process -Verb RunAs)?',
    answer_type: 'bool',
    template: 'destructive-shell-fs',
    help: 'The wrapped command is analysed too.',
  },
  {
    id: 'Q05',
    title: 'Secret paths',
    prompt: 'Secret path globs, and permitted exceptions',
    answer_type: 'globs',
    template: 'secrets-paths',
    help: 'Globs without "/" match the final path segment anywhere; globs with "/" are anchored at the root. Case-folded.',
  },
  {
    id: 'Q06',
    title: 'Outbound HTTP allow-list',
    prompt: 'Restrict outbound HTTP to an allow-list? If enabled: allowed hosts (exact; *.x for subdomains)',
    answer_type: 'flag+hosts',
    template: 'network-egress',
    help: 'Enabled with an empty list denies every destination. Applies to http actions and curl/wget clients.',
  },
  {
    id: 'Q07',
    title: 'Message recipient allow-list',
    prompt: 'Restrict message recipients to an allow-list? If enabled: allowed domains',
    answer_type: 'flag+hosts',
    template: 'network-egress',
    help: 'Domains compare exactly and case-insensitively; recipients without a domain are asked about.',
  },
  {
    id: 'Q08',
    title: 'Force push',
    prompt: 'Block force push?',
    answer_type: 'bool',
    template: 'git-release',
    help: '-f, --force, --force-with-lease, +refspec, --mirror.',
  },
  {
    id: 'Q09',
    title: 'Protected branches',
    prompt: 'Protected branches: block push to, force-update of, and deletion of these',
    answer_type: 'globs',
    template: 'git-release',
    help: '"*" does not cross "/" (release/* matches release/2026.10, not release-notes). Unknown destinations ask.',
  },
  {
    id: 'Q10',
    title: 'Publish and deploy commands',
    prompt: 'Publish/deploy commands (npm publish, vercel --prod, terraform apply, gh release create): deny, ask or no restriction',
    answer_type: 'mode',
    template: 'git-release',
    help: 'npm publish --dry-run, npm pack, terraform plan and gh release view are not publishes.',
  },
  {
    id: 'Q11',
    title: 'Destructive SQL',
    prompt: 'Block destructive SQL (DROP, TRUNCATE, unbounded DELETE/UPDATE)?',
    answer_type: 'bool',
    template: 'data-money',
    help: 'A WHERE of exactly 1=1 or true counts as unbounded. Dynamic SQL asks.',
  },
  {
    id: 'Q12',
    title: 'Payment limit',
    prompt: 'Payment limit per action (integer cents + currency)',
    answer_type: 'cents+currency',
    template: 'data-money',
    help: 'Amounts above the limit are denied; another currency is asked about. Empty limit = no restriction.',
  },
];

// ---- answer schemas ---------------------------------------------------------------------------------------

const Item = z.string().trim().min(1).max(MAX_COMMAND_CHARS);
const ItemList = z.array(Item).max(MAX_LIST_ITEMS);

const CurrencySchema = z
  .string()
  .length(3)
  .superRefine((value, ctx) => {
    if (!isCurrencyCode(value)) {
      ctx.addIssue({ code: 'custom', message: 'Currency must be three upper-case letters.', params: { code: 'invalid_value' } });
    }
  });

export const Q10_MODES = ['deny', 'ask', 'none'] as const;
export type Q10Mode = (typeof Q10_MODES)[number];

export const AnswersSchema = z
  .object({
    Q01: z.object({ context: EvaluationContextSchema }).strict(),
    Q02: z.object({ block: z.boolean() }).strict(),
    Q03: z.object({ block: z.boolean(), except: ItemList }).strict(),
    Q04: z.object({ block: z.boolean() }).strict(),
    Q05: z.object({ secret_globs: ItemList, exceptions: ItemList }).strict(),
    Q06: z.object({ enabled: z.boolean(), hosts: ItemList }).strict(),
    Q07: z.object({ enabled: z.boolean(), domains: ItemList }).strict(),
    Q08: z.object({ block: z.boolean() }).strict(),
    Q09: z.object({ branches: ItemList }).strict(),
    Q10: z.object({ mode: z.enum(Q10_MODES) }).strict(),
    Q11: z.object({ block: z.boolean() }).strict(),
    Q12: z
      .object({
        limit_cents: z.number().finite().int().min(0).max(Number.MAX_SAFE_INTEGER).nullable(),
        currency: CurrencySchema,
      })
      .strict(),
  })
  .strict();

export type Answers = z.infer<typeof AnswersSchema>;

export function validateAnswers(value: unknown): Result<Answers> {
  const parsed = AnswersSchema.safeParse(value);
  if (parsed.success) return ok(parsed.data);
  return fail(truncateErrors(fromZodIssues(parsed.error.issues), MAX_REPORTED_ERRORS));
}

/** A neutral starting point: nothing restricted except what costs nothing to restrict. */
export function defaultAnswers(context: EvaluationContext): Answers {
  return {
    Q01: { context },
    Q02: { block: true },
    Q03: { block: true, except: ['node_modules', 'dist', '.cache'] },
    Q04: { block: true },
    Q05: { secret_globs: ['.env', '.env.*', '*.pem', 'id_*', 'secrets/**'], exceptions: ['.env.example'] },
    Q06: { enabled: false, hosts: [] },
    Q07: { enabled: false, domains: [] },
    Q08: { block: true },
    Q09: { branches: ['main'] },
    Q10: { mode: 'ask' },
    Q11: { block: true },
    Q12: { limit_cents: null, currency: 'USD' },
  };
}

// ---- reference answers (eval/gold/reference-answers.json, CONTRACTS C3) -----------------------------------

export const CONTEXT_KEYS = ['posix', 'windows'] as const;
export type ContextKey = (typeof CONTEXT_KEYS)[number];

const ReferenceFileSchema = z
  .object({
    contexts: z.object({ posix: EvaluationContextSchema, windows: EvaluationContextSchema }).strict(),
    default_unmatched: z.enum(DEFAULT_UNMATCHED),
    // Q01 in the file is a placeholder; it is replaced by the selected context before validation.
    answers: z.record(z.unknown()),
  })
  .strict();

export interface ReferenceAnswers {
  readonly contextKey: ContextKey;
  readonly context: EvaluationContext;
  readonly contexts: Readonly<Record<ContextKey, EvaluationContext>>;
  readonly default_unmatched: DefaultUnmatched;
  readonly answers: Answers;
}

/** Loads the reference answers for one context key. The same function feeds the UI and the eval. */
export function parseReferenceAnswers(value: unknown, contextKey: ContextKey): Result<ReferenceAnswers> {
  const file = ReferenceFileSchema.safeParse(value);
  if (!file.success) return fail(truncateErrors(fromZodIssues(file.error.issues), MAX_REPORTED_ERRORS));
  const context = file.data.contexts[contextKey];
  const answers = validateAnswers({ ...file.data.answers, Q01: { context } });
  if (!answers.ok) {
    return fail(answers.errors.map((error) => makeError(error.code, `/answers${error.pointer}`, error.message, error.limit)));
  }
  return ok({
    contextKey,
    context,
    contexts: file.data.contexts,
    default_unmatched: file.data.default_unmatched,
    answers: answers.value,
  });
}

/** Short human summary of one answer (UI: "rule beside answer"). */
export function summariseAnswer(answers: Answers, id: QuestionId): string {
  switch (id) {
    case 'Q01': {
      const c = answers.Q01.context;
      return `root ${c.project_root}, cwd ${c.cwd}, home ${c.home} (${c.path_flavor}${c.case_insensitive_fs ? ', case-insensitive' : ''})`;
    }
    case 'Q02':
      return answers.Q02.block ? 'block' : 'no restriction';
    case 'Q03':
      return answers.Q03.block ? `block, except ${listText(answers.Q03.except)}` : 'no restriction';
    case 'Q04':
      return answers.Q04.block ? 'block' : 'no restriction';
    case 'Q05':
      return answers.Q05.secret_globs.length === 0
        ? 'no secret paths'
        : `${listText(answers.Q05.secret_globs)}; exceptions ${listText(answers.Q05.exceptions)}`;
    case 'Q06':
      return answers.Q06.enabled ? `allow only ${listText(answers.Q06.hosts, 'nothing (deny all)')}` : 'not restricted';
    case 'Q07':
      return answers.Q07.enabled ? `allow only ${listText(answers.Q07.domains, 'nothing (deny all)')}` : 'not restricted';
    case 'Q08':
      return answers.Q08.block ? 'block' : 'no restriction';
    case 'Q09':
      return answers.Q09.branches.length === 0 ? 'no protected branches' : listText(answers.Q09.branches);
    case 'Q10':
      return answers.Q10.mode === 'none' ? 'no restriction' : answers.Q10.mode;
    case 'Q11':
      return answers.Q11.block ? 'block' : 'no restriction';
    case 'Q12':
      return answers.Q12.limit_cents === null ? 'no limit' : `${answers.Q12.limit_cents} cents ${answers.Q12.currency}`;
  }
}

function listText(items: readonly string[], empty = '(none)'): string {
  return items.length === 0 ? empty : items.join(', ');
}

export function questionById(id: QuestionId): QuestionDefinition {
  const found = QUESTIONS.find((question) => question.id === id);
  if (found === undefined) throw new Error(`unknown question ${id}`);
  return found;
}

/** Every question id, in order (re-exported for UI iteration). */
export const ALL_QUESTION_IDS: readonly QuestionId[] = QUESTION_IDS;

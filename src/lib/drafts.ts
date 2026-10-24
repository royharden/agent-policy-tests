// Inputs only. Reports, approvals, classifier replies, authentication and remote opt-in never survive import/reload.
import { z } from 'zod';
import { DEFAULT_UNMATCHED, isValidId, parseImportText } from '../policyfix/action';
import type { ReviewInputs } from '../policyfix/approvals';
import { canonicalJson } from '../policyfix/digest';
import { fail, fromZodIssues, makeError, ok, type Result, truncateErrors } from '../policyfix/errors';
import { parseThresholdConfig, type ThresholdConfig } from '../policyfix/freetext/thresholds';
import { checkFileBytes, MAX_DISPOSITIONS, MAX_REPORTED_ERRORS, MAX_TEXT_CHARS } from '../policyfix/limits';
import { type Answers, AnswersSchema } from '../policyfix/questionnaire';

export const DRAFT_STORAGE_KEY = 'agent-not-list:draft:v1';
const DraftLineSchema = z.object({
  id: z.string().min(1).max(100).refine(isValidId),
  text: z.string().max(300), provider: z.enum(['keyword', 'mock', 'jev', 'llm']),
  params_text: z.string().max(MAX_TEXT_CHARS),
}).strict();
const DraftSchema = z.object({
  schema_version: z.literal(1), answers: AnswersSchema, default_unmatched: z.enum(DEFAULT_UNMATCHED),
  lines: z.array(DraftLineSchema).max(MAX_DISPOSITIONS - 12),
  thresholds: z.object({ schema_version: z.literal(1), jev: z.number().finite().min(0).max(1).nullable(), llm: z.number().finite().min(0).max(1).nullable(), provenance: z.object({ status: z.enum(['uncalibrated', 'dev-calibrated']), split: z.literal('dev'), dataset_sha256: z.string().nullable() }).strict() }).strict(), thresholds_text: z.string().max(MAX_TEXT_CHARS),
  raw_answers: z.record(z.string().max(MAX_TEXT_CHARS)).refine((value) => Object.keys(value).length <= 64, 'Too many raw editor fields.'),
}).strict();
export type Draft = Omit<z.infer<typeof DraftSchema>, 'thresholds'> & { readonly thresholds: ThresholdConfig };

function rawMatchesAnswer(answers: Answers, key: string, raw: string): boolean {
  const list = (): string[] => raw.split('\n').flatMap((line) => line.split(',')).map((item) => item.trim()).filter((item) => item !== '');
  let expected: unknown; let actual: unknown = raw.trim();
  switch (key) {
    case 'Q01:Project root': expected = answers.Q01.context.project_root; break;
    case 'Q01:Working directory (cwd)': expected = answers.Q01.context.cwd; break;
    case 'Q01:Home directory': expected = answers.Q01.context.home; break;
    case 'Q03:Except (root-level directories)': expected = answers.Q03.except; actual = list(); break;
    case 'Q05:Secret path globs': expected = answers.Q05.secret_globs; actual = list(); break;
    case 'Q05:Exceptions': expected = answers.Q05.exceptions; actual = list(); break;
    case 'Q06:Allowed hosts (exact; *.x for subdomains)': expected = answers.Q06.hosts; actual = list(); break;
    case 'Q07:Allowed domains': expected = answers.Q07.domains; actual = list(); break;
    case 'Q09:Protected branch globs': expected = answers.Q09.branches; actual = list(); break;
    case 'Q12:Limit in cents (empty = no limit)': expected = answers.Q12.limit_cents; actual = raw.trim() === '' ? null : Number(raw.trim()); break;
    case 'Q12:Currency': expected = answers.Q12.currency; actual = raw.trim().toUpperCase(); break;
    default: return false;
  }
  const a = canonicalJson(actual); const b = canonicalJson(expected);
  return a.ok && b.ok && a.value === b.value;
}

export function validateDraft(value: unknown): Result<Draft> {
  const parsed = DraftSchema.safeParse(value);
  if (!parsed.success) return fail(truncateErrors(fromZodIssues(parsed.error.issues), MAX_REPORTED_ERRORS));
  const thresholds = parseThresholdConfig(parsed.data.thresholds);
  if (thresholds === null) return fail([makeError('invalid_value', '/thresholds', 'Invalid confidence threshold configuration.')]);
  const rawThresholds = parseImportText(parsed.data.thresholds_text);
  const renderedThresholds = rawThresholds.ok ? parseThresholdConfig(rawThresholds.value) : null;
  const storedThresholdHash = canonicalJson(thresholds); const renderedThresholdHash = canonicalJson(renderedThresholds);
  if (renderedThresholds === null || !storedThresholdHash.ok || !renderedThresholdHash.ok || storedThresholdHash.value !== renderedThresholdHash.value) return fail([makeError('inconsistent', '/thresholds_text', 'Threshold editor text must match the active configuration.')]);
  const ids = parsed.data.lines.map((line) => line.id);
  if (new Set(ids).size !== ids.length) return fail([makeError('duplicate_id', '/lines', 'NOT line ids must be unique.')]);
  // Raw values are rendering inputs; only named questionnaire fields may be restored.
  if (Object.entries(parsed.data.raw_answers).some(([key, raw]) => !rawMatchesAnswer(parsed.data.answers, key, raw))) {
    return fail([makeError('inconsistent', '/raw_answers', 'Raw editor text must match its named questionnaire answer.')]);
  }
  return ok({ ...parsed.data, thresholds });
}

export function parseDraft(text: string): Result<Draft> {
  const json = parseImportText(text);
  return json.ok ? validateDraft(json.value) : json;
}

export function draftFromInputs(inputs: ReviewInputs): Result<Draft> {
  return validateDraft({
    schema_version: 1, answers: inputs.answers, default_unmatched: inputs.default_unmatched,
    lines: inputs.lines.map(({ id, text, provider, params_text }) => ({ id, text, provider, params_text })),
    thresholds: inputs.thresholds, thresholds_text: inputs.thresholds_text, raw_answers: inputs.raw_answers,
  });
}

export interface DraftStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/** Callers obtain window.localStorage inside their own try/catch too: the getter itself may throw. */
export function loadDraft(storage: DraftStorage): Result<Draft | null> {
  try {
    const text = storage.getItem(DRAFT_STORAGE_KEY);
    return text === null ? ok(null) : parseDraft(text);
  } catch {
    return fail([makeError('invalid_value', '/storage', 'Draft storage is unavailable. You can continue in this tab.')]);
  }
}

export function saveDraft(storage: DraftStorage, inputs: ReviewInputs): Result<null> {
  const draft = draftFromInputs(inputs);
  if (!draft.ok) return draft;
  const text = JSON.stringify(draft.value);
  const bytes = checkFileBytes(text);
  if (bytes !== null) return fail([bytes]);
  try {
    storage.setItem(DRAFT_STORAGE_KEY, text);
    return ok(null);
  } catch {
    return fail([makeError('invalid_value', '/storage', 'Draft could not be saved. Storage may be full or blocked; keep this tab open or copy the draft JSON.')]);
  }
}

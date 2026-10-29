// Free-text classifier label enum (PLAN A15, CONTRACTS C5): the five template ids plus `manual`.
// Dependency-free and framework-free. The classify-line edge function keeps a byte-identical duplicate of this list in
// supabase/functions/classify-line/contract.ts (it may not import from src/); tests/labels-contract.test.ts keeps the
// two in sync. M5 builds the classifiers around this module.

/** Every label a free-text classifier may return, in the canonical order. */
export const FREE_TEXT_LABELS = [
  'destructive-shell-fs',
  'secrets-paths',
  'network-egress',
  'git-release',
  'data-money',
  'manual',
] as const;

export type FreeTextLabel = (typeof FREE_TEXT_LABELS)[number];

/** The labels that name a compilable template (everything except `manual`). */
export type TemplateLabel = Exclude<FreeTextLabel, 'manual'>;

/** The label every unclassifiable, unextractable, low-confidence or failed line is routed to. */
export const MANUAL_LABEL = 'manual' satisfies FreeTextLabel;

export function isFreeTextLabel(value: unknown): value is FreeTextLabel {
  return typeof value === 'string' && (FREE_TEXT_LABELS as readonly string[]).includes(value);
}

export function isTemplateLabel(value: unknown): value is TemplateLabel {
  return isFreeTextLabel(value) && value !== 'manual';
}

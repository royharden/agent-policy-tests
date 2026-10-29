import { createHash } from 'node:crypto';
import { z } from 'zod';
import { TRAP_NAMES, type Verdict } from '../policyfix/action';
import { FREE_TEXT_LABELS, type FreeTextLabel } from '../policyfix/freetext/labels';
import type { JournalStore } from './callledger';

export function exactSha256(bytes: Uint8Array | string): string { return createHash('sha256').update(bytes).digest('hex'); }
const id = z.string().min(1).max(128);
export const GoldActionSchema = z.object({ id, context: z.enum(['posix', 'windows']), action: z.unknown(), expected: z.enum(['deny', 'ask', 'allow', 'invalid']), traps: z.array(z.enum(TRAP_NAMES)), evasion: z.boolean(), template: z.string().optional(), note: z.string() }).strict();
export type GoldAction = z.infer<typeof GoldActionSchema>;
export const GoldLineSchema = z.object({ id, line: z.string().min(1).max(300), label: z.enum(FREE_TEXT_LABELS), params: z.record(z.unknown()).optional(), injection: z.boolean(), note: z.string().optional() }).strict();
export type GoldLine = z.infer<typeof GoldLineSchema>;

export function parseJsonl<T>(text: string, schema: z.ZodType<T>): readonly T[] {
  const rows = text.split('\n').filter((line) => line.trim() !== '').map((line, index) => {
    const parsed = schema.safeParse(JSON.parse(line) as unknown);
    if (!parsed.success) throw new Error(`Invalid JSONL row ${index + 1}: ${parsed.error.message}`);
    return parsed.data;
  });
  return rows;
}

const ManifestSchema = z.object({ seed: z.number().int(), frozen_at: z.string().min(1), files: z.record(z.object({ sha256: z.string().regex(/^[a-f0-9]{64}$/), bytes: z.number().int().nonnegative() }).strict()) }).passthrough();
export async function verifyManifest(text: string, read: (name: string) => Promise<Uint8Array>): Promise<{ readonly seed: number; readonly manifest_sha256: string; readonly file_hashes: Readonly<Record<string, string>> }> {
  const manifest = ManifestSchema.parse(JSON.parse(text) as unknown);
  const hashes: Record<string, string> = {};
  for (const [name, expected] of Object.entries(manifest.files)) {
    if (name.includes('/') || name.includes('\\') || name === '..' || name === '.') throw new Error('Gold manifest names must be local filenames.');
    const bytes = await read(name);
    if (bytes.length !== expected.bytes || exactSha256(bytes) !== expected.sha256) throw new Error(`Frozen gold hash mismatch: ${name}`);
    hashes[name] = expected.sha256;
  }
  return { seed: manifest.seed, manifest_sha256: exactSha256(text), file_hashes: hashes };
}

export function seededOrder<T>(values: readonly T[], seed: number): T[] {
  let state = seed >>> 0; const out = [...values];
  for (let i = out.length - 1; i > 0; i -= 1) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const j = state % (i + 1); const a = out[i]; const b = out[j];
    if (a !== undefined && b !== undefined) { out[i] = b; out[j] = a; }
  }
  return out;
}

export interface HeldoutReview { readonly kind: 'owner-review'; readonly reviewer: 'Roy'; readonly approved: true; readonly manifest_sha256: string; readonly sample_ids: readonly string[]; readonly reviewed_at: string }
export interface HeldoutAttempt { readonly kind: 'attempt'; readonly run_id: string; readonly manifest_sha256: string; readonly at: string; readonly rerun_reason: string | null }

/** Existing append-only heldout journal is the single machine-readable review/attempt record. No receipt is fabricated. */
export async function claimHeldout(store: JournalStore, attempt: HeldoutAttempt, sampleIds: readonly string[]): Promise<void> {
  await store.exclusive(async () => {
    const events: unknown[] = (await store.read()).split('\n').filter((line) => line.trim() !== '').map((line) => JSON.parse(line) as unknown);
    const reviews = events.filter((event): event is HeldoutReview => typeof event === 'object' && event !== null && 'kind' in event && event.kind === 'owner-review');
    const reviewed = reviews.some((review) => review.reviewer === 'Roy' && review.approved === true && review.manifest_sha256 === attempt.manifest_sha256 && typeof review.reviewed_at === 'string' && Number.isFinite(Date.parse(review.reviewed_at)) && Array.isArray(review.sample_ids) && review.sample_ids.length === 20 && new Set(review.sample_ids).size === 20 && JSON.stringify([...review.sample_ids].sort()) === JSON.stringify([...sampleIds].sort()));
    if (sampleIds.length !== 20 || !reviewed) throw new Error('Held-out evaluation requires Roy\'s matching 20-row owner-review receipt in results/heldout-runs.jsonl.');
    const prior = events.some((event) => typeof event === 'object' && event !== null && 'kind' in event && event.kind === 'attempt');
    if (prior && (attempt.rerun_reason === null || attempt.rerun_reason.trim() === '')) throw new Error('Held-out evaluation has a prior attempt; supply --rerun-reason before another exposure.');
    await store.append(`${JSON.stringify(attempt)}\n`);
  });
}

export interface LabelObservation { readonly id: string; readonly expected: FreeTextLabel; readonly actual: FreeTextLabel; readonly raw_label: FreeTextLabel | null; readonly rule_compiled: boolean }
export function classifierMetrics(rows: readonly LabelObservation[]): unknown {
  const nonAbstained = rows.filter((row) => row.actual !== 'manual'); const manual = rows.filter((row) => row.expected === 'manual');
  return {
    accuracy: { k: rows.filter((row) => row.expected === row.actual).length, n: rows.length },
    abstention_rate: { k: rows.length - nonAbstained.length, n: rows.length },
    accuracy_non_abstained: { k: nonAbstained.filter((row) => row.expected === row.actual).length, n: nonAbstained.length },
    label_false_compiles: { k: manual.filter((row) => row.raw_label !== null && row.raw_label !== 'manual').length, n: manual.length },
    rule_false_compiles: { k: manual.filter((row) => row.rule_compiled).length, n: manual.length },
    per_label: Object.fromEntries(FREE_TEXT_LABELS.map((label) => {
      const tp = rows.filter((row) => row.expected === label && row.actual === label).length;
      const fp = rows.filter((row) => row.expected !== label && row.actual === label).length;
      const fn = rows.filter((row) => row.expected === label && row.actual !== label).length;
      return [label, { precision: { k: tp, n: tp + fp }, recall: { k: tp, n: tp + fn }, f1: { k: 2 * tp, n: 2 * tp + fp + fn } }];
    })),
    failures: rows.filter((row) => row.expected !== row.actual),
  };
}

export interface BaselineComparison { readonly id: string; readonly expected: Verdict | 'invalid'; readonly guard: Verdict | 'invalid'; readonly baseline: Verdict | 'invalid' }
export function compareMethods(rows: readonly BaselineComparison[]): { wins: number; ties: number; regressions: number } {
  return { wins: rows.filter((row) => row.guard === row.expected && row.baseline !== row.expected).length, regressions: rows.filter((row) => row.guard !== row.expected && row.baseline === row.expected).length, ties: rows.filter((row) => (row.guard === row.expected) === (row.baseline === row.expected)).length };
}

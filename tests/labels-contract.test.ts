// Label enum contract (PLAN M7 AC3; Claude §5.1 labels-contract.test.ts). The classify-line edge function may not import
// from src/, so it carries a duplicate of the free-text label enum. These checks keep the browser enum, the function's
// enum, the database check constraint and the function's import boundary in step. Written, not run (Dirty Mode, D-1).
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { CLASSIFY_LABELS, isClassifyLabel } from '../supabase/functions/classify-line/contract';
import { FREE_TEXT_LABELS, isFreeTextLabel, isTemplateLabel } from '../src/policyfix/freetext/labels';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const FUNCTION_DIR = join(ROOT, 'supabase', 'functions', 'classify-line');

function read(...parts: string[]): string {
  return readFileSync(join(ROOT, ...parts), 'utf8');
}

/** Single-quoted string literals between `start` and the next `end` in `text`. */
function quotedBetween(text: string, start: string, end: string): string[] {
  const from = text.indexOf(start);
  expect(from, `marker not found: ${start}`).toBeGreaterThanOrEqual(0);
  const to = text.indexOf(end, from + start.length);
  expect(to, `end marker not found after: ${start}`).toBeGreaterThan(from);
  const slice = text.slice(from + start.length, to);
  return [...slice.matchAll(/'([^']*)'/g)].map((m) => m[1] ?? '');
}

/** Every module specifier imported (static or dynamic) by a TypeScript source text. */
function importSpecifiers(source: string): string[] {
  const specs: string[] = [];
  for (const m of source.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g)) specs.push(m[1] ?? '');
  for (const m of source.matchAll(/\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) specs.push(m[1] ?? '');
  for (const m of source.matchAll(/^\s*import\s+['"]([^'"]+)['"]/gm)) specs.push(m[1] ?? '');
  return specs;
}

describe('free-text label enum', () => {
  // what_bug_this_catches: a label added to or removed from the browser enum without the edge function (or the
  // reverse), so the function rejects valid labels as off_enum or accepts labels the compiler cannot handle.
  it('the edge-function duplicate equals src/policyfix/freetext/labels.ts, in the same order', () => {
    expect([...CLASSIFY_LABELS]).toEqual([...FREE_TEXT_LABELS]);
  });

  // what_bug_this_catches: the function's enum being replaced by an import or a computed list, which would break the
  // self-contained Deno deployment or hide drift from this text-level check.
  it('contract.ts declares the enum as a literal array matching labels.ts', () => {
    const literal = quotedBetween(
      read('supabase', 'functions', 'classify-line', 'contract.ts'),
      'export const CLASSIFY_LABELS = [',
      '] as const;',
    );
    expect(literal).toEqual([...FREE_TEXT_LABELS]);
  });

  // what_bug_this_catches: the database check constraint drifting from the enum, so finish_model_call fails (and the
  // call stays 'reserved' forever) for a label the function accepted.
  it('the model_call_log label check constraint lists exactly the same labels', () => {
    const sql = read('supabase', 'migrations', '20261024210000_model_call_log.sql');
    expect(quotedBetween(sql, 'label in (', ')')).toEqual([...FREE_TEXT_LABELS]);
  });

  // what_bug_this_catches: the six-label contract from CONTRACTS C5 being changed silently (e.g. a template renamed).
  it('is the five template ids plus manual, without duplicates', () => {
    expect([...FREE_TEXT_LABELS]).toEqual([
      'destructive-shell-fs',
      'secrets-paths',
      'network-egress',
      'git-release',
      'data-money',
      'manual',
    ]);
    expect(new Set(FREE_TEXT_LABELS).size).toBe(FREE_TEXT_LABELS.length);
  });

  // what_bug_this_catches: a type guard that accepts near-misses (case, whitespace, non-strings) so an off-enum
  // provider answer is treated as a real label.
  it('type guards accept only exact enum values', () => {
    for (const label of FREE_TEXT_LABELS) {
      expect(isFreeTextLabel(label)).toBe(true);
      expect(isClassifyLabel(label)).toBe(true);
    }
    for (const bad of ['Manual', ' manual', 'manual ', 'secrets', '', null, undefined, 3, ['manual'], { label: 'manual' }]) {
      expect(isFreeTextLabel(bad)).toBe(false);
      expect(isClassifyLabel(bad)).toBe(false);
    }
    expect(isTemplateLabel('manual')).toBe(false);
    expect(isTemplateLabel('git-release')).toBe(true);
  });
});

describe('classify-line import boundary', () => {
  const files = readdirSync(FUNCTION_DIR).filter((name) => name.endsWith('.ts'));

  // what_bug_this_catches: the function importing from src/ or another function folder, which a frontend bundler
  // resolves but the edge deployment bundle does not (Bolt skill: keep each function deployable on its own).
  it('imports only same-folder modules and version-pinned npm:/jsr: packages', () => {
    expect(files).toContain('index.ts');
    expect(files).toContain('contract.ts');
    const offenders: string[] = [];
    for (const file of files) {
      for (const spec of importSpecifiers(readFileSync(join(FUNCTION_DIR, file), 'utf8'))) {
        const sameFolder = spec.startsWith('./') && !spec.slice(2).includes('/');
        const pinnedPackage = /^(npm|jsr):(@[a-z0-9-]+\/)?[a-z0-9.-]+@\d+\.\d+\.\d+(\/.*)?$/.test(spec);
        if (!sameFolder && !pinnedPackage) offenders.push(`${file}: ${spec}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  // what_bug_this_catches: contract.ts gaining an import or a Deno global, so vitest can no longer load it and the
  // edge contract tests silently stop covering the deployed code.
  it('contract.ts has no imports and no Deno globals', () => {
    const contract = read('supabase', 'functions', 'classify-line', 'contract.ts');
    expect(importSpecifiers(contract)).toEqual([]);
    expect(contract).not.toMatch(/\bDeno\./);
  });

  // what_bug_this_catches: index.ts reimplementing validation inline instead of using the tested contract helpers,
  // so the tests pass while the deployed handler behaves differently.
  it('index.ts wires the tested contract helpers', () => {
    const index = read('supabase', 'functions', 'classify-line', 'index.ts');
    for (const helper of [
      'validateClassifyRequest',
      'readBoundedText',
      'resolveProviderConfig',
      'replyForReserve',
      'replyForProviderOutcome',
      'finishParams',
      'parseJevResponse',
      'parseAnthropicResponse',
      'sha256Hex',
    ]) {
      expect(index, helper).toContain(`${helper}(`);
    }
    expect(index).toContain("from './contract.ts'");
  });

  // what_bug_this_catches: the browser adapter validating labels against its own copy instead of the canonical enum.
  it('src/providers/remote.ts validates labels with the canonical enum module', () => {
    const remote = read('src', 'providers', 'remote.ts');
    expect(remote).toContain("from '../policyfix/freetext/labels'");
    expect(remote).toContain('isFreeTextLabel(');
  });
});

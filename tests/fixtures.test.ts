import { describe, expect, it } from 'vitest';
import type { Action, Fixture } from '../src/policyfix/action';
import type { CompileOutput } from '../src/policyfix/compile';
import { canonicalJson } from '../src/policyfix/digest';
import { generateFixtures, inspectFixtures } from '../src/policyfix/fixtures';
import { mutateAction } from '../src/policyfix/mutators';
import type { DeclaredExample } from '../src/policyfix/templates/index';
import { compileOrThrow, reference, referenceOutput } from './helpers/reference';

function generated(output: CompileOutput, mutate = false): readonly Fixture[] {
  const result = generateFixtures(output, { seed: 21, mutate });
  if (!result.ok) throw new Error(JSON.stringify(result.errors));
  return result.value.fixtures;
}

function oneRuleOutput(examples: readonly DeclaredExample[]): CompileOutput {
  const output = referenceOutput('posix');
  const rule = output.rules[0];
  if (rule === undefined) throw new Error('Reference rule missing');
  return { ...output, rules: [rule], examples: { [rule.id]: examples }, witnesses: {}, policy: { ...output.policy, rules: [rule], dispositions: output.dispositions.map((entry) => ({ ...entry, rule_ids: entry.rule_ids.filter((id) => id === rule.id) })) } };
}

describe('fixture generation and expectation provenance', () => {
  it('is seeded, stable, content-addressed and deduplicated per owning rule/action', () => {
    // what_bug_this_catches: global random state, duplicate mutations counting as witnesses, or ids changing on each render.
    const output = referenceOutput('posix');
    const first = generated(output, true);
    const second = generated(output, true);
    expect(first).toEqual(second);
    expect(first.every((fixture) => fixture.id.startsWith('fx-') && fixture.id.length === 67)).toBe(true);
    const keys = first.map((fixture) => canonicalJson({ rule_id: fixture.rule_id, source_answer: fixture.source_answer, action: fixture.action })).map((key) => key.ok ? key.value : 'invalid');
    expect(new Set(keys).size).toBe(first.length);
  });

  it('keeps declared local allow and attaches only a declared stronger conflict', () => {
    // what_bug_this_catches: relabeling local examples from observed output, or counting secret-conflicted exceptions as permitted witnesses.
    const output = referenceOutput('posix');
    const id = 'q03-recursive-force-delete-in-root';
    const examples: DeclaredExample[] = [
      ...(output.examples[id] ?? []).filter((example) => example.kind === 'prohibited'),
      ...['.env', 'server.pem'].map((name, index): DeclaredExample => ({ id: `secret-${index}`, kind: 'permitted', expected_local: 'allow', action: { kind: 'fs', op: 'delete', recursive: true, path: `/workspace/demo/node_modules/${name}` }, note: 'Q03 exception; Q05 owns the block.' })),
    ];
    const result = generateFixtures({ ...output, examples: { ...output.examples, [id]: examples } }, { mutate: false });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const conflict = result.value.fixtures.find((fixture) => fixture.rule_id === id && fixture.expected_local === 'allow');
    expect(conflict).toMatchObject({ expected_local: 'allow', expected_policy: 'deny', conflict: { owner_rule: 'q05-secret-name' } });
    expect(result.value.gaps.some((gap) => gap.rule_id === id && gap.code === 'missing-permitted-witness')).toBe(true);
  });

  it('records undeclared conflicts with both ids and never changes their expectation', () => {
    // what_bug_this_catches: every observed block being converted into a passing conflict even without a declaration.
    const output = referenceOutput('posix');
    const id = 'q08-force-push';
    const example: DeclaredExample = { id: 'undeclared', kind: 'permitted', expected_local: 'allow', action: { kind: 'fs', op: 'read', path: '/workspace/demo/.env' }, note: 'Git rule allows it alone; secrets ownership is not declared by git-release.' };
    const result = generateFixtures({ ...output, examples: { ...output.examples, [id]: [example] } }, { mutate: false });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const row = result.value.fixtures.find((fixture) => fixture.rule_id === id);
    expect(row?.expected_local).toBe('allow');
    expect(row?.expected_policy).toBeUndefined();
    expect(result.value.conflicts).toContainEqual(expect.objectContaining({ code: 'undeclared-conflict', severity: 'Fail', rule_id: id, owner_rule: 'q05-secret-name' }));
  });

  it('recomputes missing minima after fixtures are removed and keeps null-rule witnesses separate', () => {
    // what_bug_this_catches: trusting the generator sidecar after import, or attributing unrelated witness rows to a restriction.
    const ref = reference('posix');
    const output = compileOrThrow({ ...ref.answers, Q06: { enabled: false, hosts: [] } }, ref.context);
    const fixtures = generated(output);
    expect(fixtures.some((fixture) => fixture.rule_id === null && fixture.source_answer === 'Q06')).toBe(true);
    const id = 'q03-recursive-force-delete-in-root';
    const reduced = fixtures.filter((fixture) => fixture.rule_id !== id || fixture.expected_local !== 'allow');
    expect(inspectFixtures(output.policy, reduced).findings).toContainEqual(expect.objectContaining({ code: 'missing-permitted-witness', severity: 'Gap', rule_id: id }));
  });

  it('returns structured count and serialized-byte overflow errors without truncating', () => {
    // what_bug_this_catches: exporting a fixture set the runner cannot import, or silently dropping rows at a cap.
    const examples = (count: number, body: string): DeclaredExample[] => Array.from({ length: count }, (_, index) => ({ id: `n-${index}`, kind: 'permitted', expected_local: 'allow', action: { kind: 'shell', dialect: 'posix', command: `echo ${body}${index}` }, note: 'Synthetic cap witness.' }));
    const count = generateFixtures(oneRuleOutput(examples(2001, 'row-')), { mutate: false });
    expect(count.ok).toBe(false);
    if (!count.ok) expect(count.errors[0]?.code).toBe('too_many');
    const bytes = generateFixtures(oneRuleOutput(examples(1500, '界'.repeat(3900))), { mutate: false });
    expect(bytes.ok).toBe(false);
    if (!bytes.ok) expect(bytes.errors[0]?.code).toBe('export_too_large');
  });

  it('declares preserving versus opaque mutations and gates future dialect swaps explicitly', () => {
    // what_bug_this_catches: using the guard to generate expectations or emitting unsupported dialects before M5 is enabled.
    const context = reference('posix').context;
    const action: Action = { kind: 'shell', dialect: 'posix', command: 'rm -rf src' };
    const base = mutateAction(action, 'deny', context);
    expect(base.find((mutation) => mutation.transform === 'opaque')?.expected_local).toBe('ask');
    expect(base.filter((mutation) => mutation.transform === 'preserve').every((mutation) => mutation.expected_local === 'deny')).toBe(true);
    expect(base.some((mutation) => mutation.trap === 'dialect-swap')).toBe(false);
    const enabled = mutateAction(action, 'deny', context, { dialects: ['posix', 'powershell', 'cmd'] });
    expect(enabled.filter((mutation) => mutation.trap === 'dialect-swap').map((mutation) => mutation.action.kind === 'shell' ? mutation.action.dialect : '')).toEqual(expect.arrayContaining(['powershell', 'cmd']));
    const commandRule = referenceOutput('posix').rules.find((rule) => rule.id === 'q10-npm-publish');
    if (commandRule === undefined) throw new Error('Reference command rule missing');
    expect(mutateAction(action, 'allow', context, { rule: commandRule })).toEqual([]);
  });

  it('finds forged conflict owners independently of a saved report', () => {
    // what_bug_this_catches: changing conflict.owner_rule in an imported fixture to explain away an unrelated block.
    const output = referenceOutput('posix');
    const fixture = generated(output).find((candidate) => candidate.rule_id === 'q12-over-limit' && candidate.action.kind === 'payment' && candidate.action.currency === 'EUR');
    if (fixture === undefined) throw new Error('Expected reference payment near-miss');
    const forged: Fixture = { ...fixture, expected_policy: 'ask', conflict: { owner_rule: 'q08-force-push', reason: 'Forged ownership' } };
    expect(inspectFixtures(output.policy, [forged]).findings.some((entry) => entry.code === 'conflict-owner' && entry.severity === 'Fail')).toBe(true);
  });
});

import { describe, expect, it } from 'vitest';
import type { Action, Fixture } from '../src/policyfix/action';
import { createFakeState, invokeFake } from '../src/policyfix/faketools';
import { replay } from '../src/policyfix/replay';
import { referencePolicy } from './helpers/reference';

function witness(id: string, action: Action): Fixture {
  return { id, action, rule_id: null, source_answer: 'Q01', expected_local: 'allow', origin: 'template' };
}

describe('fake-tool replay', () => {
  it('supports all seven action kinds using only in-memory logs', () => {
    // what_bug_this_catches: a missing fake adapter or a real tool escaping through an allowed fixture path.
    const { policy } = referencePolicy('posix');
    const empty = { ...policy, rules: [], dispositions: policy.dispositions.map((entry) => ({ ...entry, rule_ids: [] })) };
    const actions: Action[] = [
      { kind: 'shell', dialect: 'posix', command: 'echo demo' },
      { kind: 'fs', op: 'write', path: 'demo.txt' },
      { kind: 'http', method: 'GET', url: 'https://api.example.test/' },
      { kind: 'sql', statement: 'SELECT 1' },
      { kind: 'git', args: ['status'] },
      { kind: 'payment', amount_cents: 10, currency: 'USD' },
      { kind: 'message', channel: 'email', to: 'ops@example.test' },
    ];
    const result = replay(empty, actions.map((action, index) => witness(`f-${index}`, action)));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.map((row) => row.effects[0]?.kind)).toEqual(actions.map((action) => action.kind));
    expect(result.value.every((row) => row.effects.length === 1 && row.local === null && row.composed.verdict === 'allow')).toBe(true);
  });

  it('never invokes fake tools on deny or ask and resets logs per fixture', () => {
    // what_bug_this_catches: ask being treated as approval, deny dispatching anyway, or a prior allowed row contaminating blocked logs.
    const { policy } = referencePolicy('posix');
    const rows: Fixture[] = [
      witness('allowed', { kind: 'payment', amount_cents: 10, currency: 'USD' }),
      { ...witness('denied', { kind: 'payment', amount_cents: 5001, currency: 'USD' }), rule_id: 'q12-over-limit', source_answer: 'Q12', expected_local: 'deny' },
      { ...witness('asked', { kind: 'payment', amount_cents: 10, currency: 'EUR' }), rule_id: 'q12-currency-mismatch', source_answer: 'Q12', expected_local: 'ask' },
    ];
    const result = replay(policy, rows);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.map((row) => row.composed.verdict)).toEqual(['allow', 'deny', 'ask']);
    expect(result.value.map((row) => row.effects.length)).toEqual([1, 0, 0]);
  });

  it('gives each fixture independent fake filesystem state', () => {
    // what_bug_this_catches: stateful tools leaking files or effects between otherwise independent fixture evaluations.
    const first = createFakeState();
    const second = createFakeState();
    invokeFake(first, { kind: 'fs', op: 'write', path: '/workspace/demo/file' }, 'first');
    expect(first.files.has('/workspace/demo/file')).toBe(true);
    expect(second.files.size).toBe(0);
    expect(second.effects).toEqual([]);
  });

  it('rejects invalid actions and dangling rule references before replay', () => {
    // what_bug_this_catches: malformed imported fixtures reaching either guard or fake tools.
    const { policy } = referencePolicy('posix');
    expect(replay(policy, [{ ...witness('dangling', { kind: 'sql', statement: 'SELECT 1' }), rule_id: 'missing' }]).ok).toBe(false);
    const invalid: Fixture = { ...witness('invalid', { kind: 'payment', amount_cents: 1, currency: 'USD' }), action: { kind: 'payment', amount_cents: -1, currency: 'USD' } };
    expect(replay(policy, [invalid]).ok).toBe(false);
  });
});

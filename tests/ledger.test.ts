import { describe, expect, it } from 'vitest';
import { buildLlmRequest } from '../eval/providers/llm';
import { metadataFor, type CallReply } from '../eval/providers/types';
import { BUDGET_MICROUSD, createLedgerTransport, ledgerCharge, ledgerEvents, type JournalStore } from '../src/lib/callledger';

function memoryStore(): JournalStore {
  let data = ''; let queue = Promise.resolve();
  return { read: async () => data, append: async (line) => { data += line; }, exclusive: async <T>(fn: () => Promise<T>): Promise<T> => {
    const before = queue; let release = (): void => {}; queue = new Promise<void>((resolve) => { release = resolve; });
    await before; try { return await fn(); } finally { release(); }
  } };
}

describe('durable reservation ledger', () => {
  it('reserves before send, retains unknown usage and caches without repeating a paid attempt', async () => {
    // what_bug_this_catches: post-call budget checks, invented zero usage/cost, or a repeated request making another paid call.
    const store = memoryStore(); let sends = 0;
    const request = buildLlmRequest('never push to the hotfix branch'); const metadata = metadataFor('llm', String(request.body['model']), request.body, [], 128, ['template']);
    const deps = createLedgerTransport({ live: true, run_id: 'synthetic-run', store, credential: () => 'synthetic-placeholder', now: () => '2026-10-24T22:00:00Z', send: async () => {
      sends += 1; expect(ledgerEvents(await store.read()).some((event) => event.kind === 'reserved')).toBe(true);
      return { status: 'ok', http_status: 200, body: { model: metadata.model }, latency_ms: 1, cached: false };
    } });
    await deps.call(request, metadata); const cached = await deps.call(request, metadata);
    const events = ledgerEvents(await store.read()); const finished = events.find((event) => event.kind === 'finished');
    expect(sends).toBe(1); expect(cached.cached).toBe(true);
    expect(finished?.input_tokens).toBeNull(); expect(finished?.estimated_cost_microusd).toBeNull();
    expect(ledgerCharge(events, 'synthetic-run')).toBeGreaterThan(0);
  });

  it('serializes reservations so concurrent calls cannot both cross $2', async () => {
    // what_bug_this_catches: separate unlocked budget reads admitting two simultaneous worst-case calls beyond the cap.
    const store = memoryStore(); const request = buildLlmRequest('never run terraform destroy');
    const original = metadataFor('llm', String(request.body['model']), request.body, [], 220000, ['template']);
    let start = (): void => {}; const started = new Promise<void>((resolve) => { start = resolve; });
    let finish = (_reply: CallReply): void => {}; const pending = new Promise<CallReply>((resolve) => { finish = resolve; });
    const deps = createLedgerTransport({ live: true, run_id: 'synthetic-run', store, credential: () => 'synthetic-placeholder', now: () => '2026-10-24T22:00:00Z', send: async () => { start(); return pending; } });
    const first = deps.call(request, original); await started;
    await expect(deps.call(request, { ...original, cache_key: 'different-call' })).rejects.toThrow();
    expect(ledgerCharge(ledgerEvents(await store.read()), 'synthetic-run')).toBeLessThanOrEqual(BUDGET_MICROUSD);
    finish({ status: 'timeout', http_status: null, body: null, latency_ms: 15000, cached: false }); await first;
  });

  it('does not read credentials or dispatch in offline mode and preserves option/repeat identity', async () => {
    // what_bug_this_catches: an offline import reading shell secrets, or sorted Choice keys collapsing independent trials.
    const request = buildLlmRequest('never run terraform destroy'); let credentials = 0;
    const a = metadataFor('llm', 'model', request.body, ['a', 'b'], 128, ['q'], 'run:row:0');
    const b = metadataFor('llm', 'model', request.body, ['b', 'a'], 128, ['q'], 'run:row:0');
    const c = metadataFor('llm', 'model', request.body, ['a', 'b'], 128, ['q'], 'run:row:1');
    expect(new Set([a.cache_key, b.cache_key, c.cache_key]).size).toBe(3);
    const deps = createLedgerTransport({ live: false, run_id: 'synthetic', store: memoryStore(), credential: () => { credentials += 1; return undefined; }, now: () => '', send: async () => { throw new Error('No send allowed'); } });
    await expect(deps.call(request, a)).rejects.toThrow(); expect(credentials).toBe(0);
  });
});

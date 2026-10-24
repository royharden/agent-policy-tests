// Local eval only. Imports have no side effects; transport and credentials are injected at explicit --live activation.
import { open, readFile, mkdir, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { CallMetadata, CallReply, ProviderDeps, ProviderRequest } from '../../eval/providers/types';
import { record } from '../../eval/providers/types';
import { sha256Hex } from '../policyfix/digest';
import { utf8ByteLength } from '../policyfix/limits';

export interface JournalStore { read(): Promise<string>; append(line: string): Promise<void>; exclusive<T>(fn: () => Promise<T>): Promise<T> }
export function fileJournalStore(path: string): JournalStore {
  return {
    read: async () => { try { return await readFile(path, 'utf8'); } catch (error: unknown) { if (record(error) && error['code'] === 'ENOENT') return ''; throw error; } },
    append: async (line) => { await mkdir(dirname(path), { recursive: true }); const handle = await open(path, 'a'); try { await handle.writeFile(line); await handle.sync(); } finally { await handle.close(); } },
    exclusive: async <T>(fn: () => Promise<T>): Promise<T> => {
      await mkdir(dirname(path), { recursive: true });
      // Exclusive creation fails closed for another process or a crash-left lock. Never auto-break a stale lock.
      const lock = await open(`${path}.lock`, 'wx');
      try { return await fn(); } finally { await lock.close(); await unlink(`${path}.lock`); }
    },
  };
}

export interface Price { readonly model: string; readonly dated: string; readonly input_usd_per_million: number; readonly output_usd_per_million: number }
export const PRICE_TABLE: readonly Price[] = [
  { model: 'jev-1.13.0', dated: '2026-10-24', input_usd_per_million: 0.042, output_usd_per_million: 0 },
  { model: 'claude-haiku-4-5-20251001', dated: '2026-10-24', input_usd_per_million: 1, output_usd_per_million: 5 },
];
export const BUDGET_MICROUSD = 2_000_000;
export interface LedgerEvent {
  readonly kind: 'reserved' | 'finished' | 'cache-hit';
  readonly run_id: string; readonly span_id: string; readonly at: string;
  readonly provider: string; readonly model: string; readonly prompt_hash: string; readonly cache_key: string;
  readonly option_order: readonly string[]; readonly trial_identity: string | null;
  readonly reserved_microusd: number; readonly charged_microusd: number;
  readonly price_date: string; readonly status: string; readonly retries: 0;
  readonly input_tokens: number | null; readonly output_tokens: number | null;
  readonly cached_tokens: number | null; readonly reasoning_tokens: number | null;
  readonly estimated_cost_microusd: number | null; readonly latency_ms: number | null; readonly ttft_ms: null;
  readonly raw_usage: Readonly<Record<string, unknown>> | null;
  readonly reply: CallReply | null;
}

function tokens(value: unknown): number | null { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null; }
export function ledgerEvents(text: string): readonly LedgerEvent[] {
  return text.split('\n').filter((line) => line.trim() !== '').map((line) => {
    const parsed: unknown = JSON.parse(line);
    if (!record(parsed) || !['reserved', 'finished', 'cache-hit'].includes(String(parsed['kind'])) || typeof parsed['span_id'] !== 'string' || typeof parsed['run_id'] !== 'string' || typeof parsed['charged_microusd'] !== 'number' || !Number.isSafeInteger(parsed['charged_microusd']) || parsed['charged_microusd'] < 0) throw new Error('Invalid ledger row; refuse to spend with an unreadable ledger.');
    return parsed as unknown as LedgerEvent;
  });
}
export function ledgerCharge(events: readonly LedgerEvent[], runId: string): number {
  const spans = new Map<string, number>();
  for (const event of events) if (event.run_id === runId && event.kind !== 'cache-hit') spans.set(event.span_id, event.charged_microusd);
  return [...spans.values()].reduce((sum, value) => sum + value, 0);
}

/** Byte upper bound plus 8,192 protocol tokens, at twice input rate (covers cache-write uplifts).
 * Providers/prices/token bounds still require activation verification; unexpected usage retains the larger charge. */
export function reservationCost(request: ProviderRequest, metadata: CallMetadata, price: Price): number {
  const bytes = utf8ByteLength(JSON.stringify(request.body));
  if (bytes > 100_000 || (metadata.max_output_tokens === null && price.output_usd_per_million !== 0)) throw new Error('Cannot bound provider cost for this request.');
  return Math.ceil((bytes + 8192) * price.input_usd_per_million * 2 + (metadata.max_output_tokens ?? 0) * price.output_usd_per_million);
}

export interface LedgerTransportOptions {
  readonly live: boolean; readonly run_id: string; readonly store: JournalStore;
  readonly credential: (name: ProviderRequest['credential_env']) => string | undefined;
  readonly send: (request: ProviderRequest, key: string, timeoutMs: number) => Promise<CallReply>;
  readonly now: () => string;
}

/** Reservation is durable before send; errors/crashes/unknown usage remain charged. No adapter or transport retry. */
export function createLedgerTransport(options: LedgerTransportOptions): ProviderDeps {
  return { call: async (request, metadata) => {
    if (!options.live) throw new Error('Live provider calls are disabled.');
    const key = options.credential(request.credential_env);
    if (key === undefined || key.trim() === '') throw new Error(`Missing shell variable ${request.credential_env}.`);
    const price = PRICE_TABLE.find((entry) => entry.model === metadata.model);
    if (price === undefined) throw new Error('No dated price bound for the requested model.');
    const amount = reservationCost(request, metadata, price);
    const span = sha256Hex(JSON.stringify([options.run_id, metadata.cache_key]));
    const base = {
      run_id: options.run_id, span_id: span, provider: metadata.provider, model: metadata.model,
      prompt_hash: metadata.prompt_hash, cache_key: metadata.cache_key, option_order: metadata.option_order,
      trial_identity: metadata.trial_identity, reserved_microusd: amount, price_date: price.dated, retries: 0 as const,
      input_tokens: null, output_tokens: null, cached_tokens: null, reasoning_tokens: null,
      estimated_cost_microusd: null, latency_ms: null, ttft_ms: null, raw_usage: null, reply: null,
    };
    const cached = await options.store.exclusive(async (): Promise<CallReply | null> => {
      const events = ledgerEvents(await options.store.read());
      if (events.some((event) => event.run_id === options.run_id && event.status === 'budget-bound-exceeded')) throw new Error('Provider usage exceeded its conservative reservation bound; stop and reverify pricing/token bounds.');
      const previous = [...events].reverse().find((event) => event.span_id === span && event.kind !== 'cache-hit');
      if (previous !== undefined && previous.kind === 'reserved') throw new Error('This call is already reserved; inspect a pending/crashed call instead of retrying.');
      const completed = previous ?? [...events].reverse().find((event) => event.kind === 'finished' && event.cache_key === metadata.cache_key && event.status === 'ok');
      if (completed?.reply !== null && completed?.reply !== undefined) {
        const reply = { ...completed.reply, cached: true };
        await options.store.append(`${JSON.stringify({ ...base, kind: 'cache-hit', at: options.now(), status: completed.status, charged_microusd: 0, reply })}\n`);
        return reply;
      }
      if (ledgerCharge(events, options.run_id) + amount > BUDGET_MICROUSD) throw new Error('Local evaluation $2 hard reservation budget reached.');
      await options.store.append(`${JSON.stringify({ ...base, kind: 'reserved', at: options.now(), status: 'reserved', charged_microusd: amount })}\n`);
      return null;
    });
    if (cached !== null) return cached;
    let reply: CallReply;
    try { reply = await options.send(request, key, metadata.timeout_ms); }
    catch { reply = { status: 'error', http_status: null, body: null, latency_ms: null, cached: false }; }
    const usage = record(reply.body) && record(reply.body['usage']) ? reply.body['usage'] : null;
    const input = tokens(usage?.['input_tokens']); const output = tokens(usage?.['output_tokens']);
    const cachedTokens = tokens(usage?.['cache_read_input_tokens']); const cacheWrite = tokens(usage?.['cache_creation_input_tokens']);
    const reasoning = tokens(usage?.['reasoning_tokens']);
    const estimate = input !== null && (output !== null || price.output_usd_per_million === 0)
      ? Math.ceil((input + (cachedTokens ?? 0) + (cacheWrite ?? 0) * 1.25) * price.input_usd_per_million + (output ?? 0) * price.output_usd_per_million) : null;
    const successful = reply.status === 'ok' && reply.http_status !== null && reply.http_status >= 200 && reply.http_status < 300;
    const charge = successful && estimate !== null ? estimate : amount;
    await options.store.exclusive(async () => {
      await options.store.append(`${JSON.stringify({ ...base, kind: 'finished', at: options.now(), status: estimate !== null && estimate > amount ? 'budget-bound-exceeded' : reply.status, charged_microusd: Math.max(charge, estimate ?? 0), input_tokens: input, output_tokens: output, cached_tokens: cachedTokens, reasoning_tokens: reasoning, estimated_cost_microusd: estimate, latency_ms: reply.latency_ms, raw_usage: usage, reply })}\n`);
    });
    return reply;
  } };
}

export function ledgerSummary(events: readonly LedgerEvent[], runId: string, passingTasks: number): Readonly<Record<string, unknown>> {
  const latest = new Map<string, LedgerEvent>();
  for (const event of events) if (event.run_id === runId && event.kind !== 'cache-hit') latest.set(event.span_id, event);
  const current = [...latest.values()];
  const finished = current.filter((event) => event.kind === 'finished');
  const pending = current.filter((event) => event.kind === 'reserved');
  const unknown = pending.length > 0 || finished.some((event) => event.estimated_cost_microusd === null);
  const estimate = unknown ? null : finished.reduce((sum, event) => sum + (event.estimated_cost_microusd ?? 0), 0);
  const tokenSum = (field: 'input_tokens' | 'output_tokens' | 'cached_tokens' | 'reasoning_tokens'): number | null => pending.length > 0 || finished.some((event) => event[field] === null) ? null : finished.reduce((sum, event) => sum + (event[field] ?? 0), 0);
  const input = tokenSum('input_tokens'); const output = tokenSum('output_tokens');
  const charged = ledgerCharge(events, runId);
  const failedCharge = finished.filter((event) => event.status !== 'ok').reduce((sum, event) => sum + event.charged_microusd, 0);
  return { outcome: pending.length > 0 ? 'incomplete' : finished.some((event) => event.status !== 'ok') ? 'completed-with-call-errors' : 'completed', charged_microusd: charged, estimated_microusd: estimate, passing_tasks: passingTasks, estimated_microusd_per_passing_task: estimate === null || passingTasks === 0 ? null : estimate / passingTasks, input_tokens: input, output_tokens: output, cached_tokens: tokenSum('cached_tokens'), reasoning_tokens: tokenSum('reasoning_tokens'), tokens_per_passing_task: input === null || output === null || passingTasks === 0 ? null : (input + output) / passingTasks, failed_attempt_charge_microusd: failedCharge, failed_attempt_charge_share: { k: failedCharge, n: charged }, pending_reservations: pending.length, unknown_cost_calls: pending.length + finished.filter((event) => event.estimated_cost_microusd === null).length, cache_hits: events.filter((event) => event.run_id === runId && event.kind === 'cache-hit').length };
}

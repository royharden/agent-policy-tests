// Local-eval transport seam. No default network transport, credentials, cache or ledger side effects at import.
// M8 injects ONE call that checks --live, reads a shell env key, reserves worst-case spend, applies timeout, logs
// success/error/raw usage and caches. Its promise must settle within timeout_ms; no adapter retries are permitted.
import { canonicalJson, sha256Hex } from '../../src/policyfix/digest';
import type { FreeTextLabel } from '../../src/policyfix/freetext/labels';

export interface ProviderRequest {
  readonly url: string;
  readonly method: 'POST';
  readonly headers: Readonly<Record<string, string>>;
  /** Resolved only by the local --live runner, never from browser env or a credential file. */
  readonly credential_env: 'TYPESAFE_API_KEY' | 'ANTHROPIC_API_KEY';
  readonly auth_header: 'authorization' | 'x-api-key';
  readonly auth_prefix: 'Bearer ' | '';
  readonly body: Readonly<Record<string, unknown>>;
}
export interface CallMetadata {
  readonly provider: 'jev' | 'llm' | 'b3';
  readonly model: string;
  readonly prompt_hash: string;
  readonly cache_key: string;
  readonly question_ids: readonly string[];
  readonly option_order: readonly string[];
  readonly timeout_ms: 15000;
  readonly max_output_tokens: number | null;
  readonly retries: 0;
  readonly trial_identity: string | null;
}
export interface CallReply {
  readonly status: 'ok' | 'error' | 'timeout';
  readonly http_status: number | null;
  readonly body: unknown;
  readonly latency_ms: number | null;
  readonly cached: boolean;
}
export interface ProviderDeps { readonly call: (request: ProviderRequest, metadata: CallMetadata) => Promise<CallReply> }
export interface ProviderObservation {
  readonly metadata: CallMetadata;
  readonly raw_usage: Readonly<Record<string, unknown>> | null;
  readonly input_tokens: number | null;
  readonly output_tokens: number | null;
  readonly cached_tokens: number | null;
  readonly latency_ms: number | null;
  readonly cached: boolean;
}
export type LabelResult = ProviderObservation & (
  | { readonly kind: 'ok'; readonly label: FreeTextLabel; readonly confidence: number | null }
  | { readonly kind: 'fallback'; readonly label: 'manual'; readonly confidence: null; readonly reason: string }
);

export function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
export function probability(value: unknown): value is number { return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1; }
function tokenCount(value: unknown): number | null { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null; }

export function metadataFor(
  provider: CallMetadata['provider'], model: string, body: Readonly<Record<string, unknown>>, options: readonly string[],
  maxOutput: number | null, questionIds: readonly string[], trialIdentity: string | null = null,
): CallMetadata {
  // Canonical JSON sorts object keys. Explicit option_order preserves Choice insertion-order sensitivity.
  const encoded = canonicalJson({ model, body, option_order: options, trial_identity: trialIdentity });
  if (!encoded.ok) throw new Error('Provider request cannot be represented as canonical JSON.');
  const hash = sha256Hex(encoded.value);
  return { provider, model, prompt_hash: hash, cache_key: hash, question_ids: questionIds, option_order: [...options], timeout_ms: 15000, max_output_tokens: maxOutput, retries: 0, trial_identity: trialIdentity };
}

export async function callOnce(request: ProviderRequest, metadata: CallMetadata, deps: ProviderDeps): Promise<CallReply> {
  try { return await deps.call(request, metadata); }
  catch { return { status: 'error', http_status: null, body: null, latency_ms: null, cached: false }; }
}

export function observation(reply: CallReply, metadata: CallMetadata): ProviderObservation {
  const usage = record(reply.body) && record(reply.body['usage']) ? reply.body['usage'] : null;
  return {
    metadata, raw_usage: usage,
    input_tokens: tokenCount(usage?.['input_tokens']), output_tokens: tokenCount(usage?.['output_tokens']),
    cached_tokens: tokenCount(usage?.['cache_read_input_tokens']),
    latency_ms: typeof reply.latency_ms === 'number' && Number.isFinite(reply.latency_ms) && reply.latency_ms >= 0 ? reply.latency_ms : null,
    cached: reply.cached,
  };
}

export function fallback(reply: CallReply, metadata: CallMetadata, reason: string): LabelResult {
  return { ...observation(reply, metadata), kind: 'fallback', label: 'manual', confidence: null, reason };
}

export function responseObject(reply: CallReply, expectedModel: string): Record<string, unknown> | null {
  if (reply.status !== 'ok' || reply.http_status === null || reply.http_status < 200 || reply.http_status >= 300 || !record(reply.body)) return null;
  if (reply.body['model'] !== expectedModel) return null;
  return reply.body;
}

/** Anthropic content must be a single text block carrying strict JSON, without code fences or tool calls. */
export function anthropicJson(body: Record<string, unknown>): unknown {
  const content: unknown = body['content'];
  if (body['stop_reason'] !== 'end_turn' || !Array.isArray(content) || content.length !== 1) return null;
  const block: unknown = content[0];
  if (!record(block) || block['type'] !== 'text' || typeof block['text'] !== 'string' || block['text'].length > 4096) return null;
  try { return JSON.parse(block['text']) as unknown; } catch { return null; }
}

export function anthropicRequest(body: Readonly<Record<string, unknown>>): ProviderRequest {
  return { url: 'https://api.anthropic.com/v1/messages', method: 'POST', headers: { 'content-type': 'application/json', 'anthropic-version': '2023-06-01' }, credential_env: 'ANTHROPIC_API_KEY', auth_header: 'x-api-key', auth_prefix: '', body };
}

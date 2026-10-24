// Browser adapter for the classify-line edge function (PLAN A18, A20; M7 AC4; Claude §2.4).
// - Runs ONLY after the user explicitly opts into a remote (paid) classifier: without `optedIn: true` it returns
//   `not_opted_in` before touching the network or the auth session.
// - Signs in anonymously (supabase.auth.signInAnonymously) only when there is no session yet, i.e. on first opt-in use.
// - Calls the function with supabase.functions.invoke, which sends the session JWT; never calls an RPC, never holds a
//   server secret (the browser has only the public URL and anon key from src/lib/supabase.ts).
// - Maps every HTTP status to a typed result and NEVER fabricates a label on error: errors carry no label, and a
//   server-side fallback is surfaced as `fallback` with label `manual` and its reason.
import type { SupabaseClient } from '@supabase/supabase-js';
import { supabase } from '../lib/supabase';
import { type FreeTextLabel, isFreeTextLabel } from '../policyfix/freetext/labels';

export const CLASSIFY_FUNCTION_NAME = 'classify-line';

export const REMOTE_PROVIDERS = ['jev', 'llm'] as const;
export type RemoteProvider = (typeof REMOTE_PROVIDERS)[number];

export const REMOTE_FALLBACK_REASONS = ['unparsable', 'off_enum', 'timeout', 'provider_error'] as const;
export type RemoteFallbackReason = (typeof REMOTE_FALLBACK_REASONS)[number];

export const REMOTE_ERROR_CODES = [
  'not_opted_in',
  'not_configured',
  'sign_in_failed',
  'invalid_input',
  'unauthorized',
  'origin_not_allowed',
  'pending',
  'conflict',
  'capped',
  'unavailable',
  'network',
  'bad_response',
  'server_error',
] as const;
export type RemoteErrorCode = (typeof REMOTE_ERROR_CODES)[number];

export type RemoteClassifyResult =
  | {
      readonly kind: 'ok';
      readonly requestId: string;
      readonly label: FreeTextLabel;
      readonly confidence: number | null;
      readonly provider: RemoteProvider;
      readonly model: string;
      readonly duplicate: boolean;
    }
  | {
      readonly kind: 'fallback';
      readonly requestId: string;
      readonly label: 'manual';
      readonly reason: RemoteFallbackReason;
      readonly provider: RemoteProvider;
      readonly model: string;
      readonly duplicate: boolean;
    }
  | {
      readonly kind: 'error';
      readonly requestId: string;
      readonly code: RemoteErrorCode;
      readonly httpStatus: number | null;
      /** Server reason/field code when present (never secret material). */
      readonly detail: string | null;
    };

export interface RemoteClassifyInput {
  readonly line: string;
  readonly provider: RemoteProvider;
  /** Must be true, set only by an explicit user action that enables a remote classifier. */
  readonly optedIn: boolean;
  /** Reuse a previous request id to retry idempotently; a new id is generated otherwise. */
  readonly requestId?: string;
}

export interface RemoteDeps {
  readonly client: SupabaseClient | null;
  readonly newRequestId: () => string;
}

const defaultDeps: RemoteDeps = { client: supabase, newRequestId: () => crypto.randomUUID() };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isFallbackReason(value: unknown): value is RemoteFallbackReason {
  return typeof value === 'string' && (REMOTE_FALLBACK_REASONS as readonly string[]).includes(value);
}

function errorResult(
  requestId: string,
  code: RemoteErrorCode,
  httpStatus: number | null = null,
  detail: string | null = null,
): RemoteClassifyResult {
  return { kind: 'error', requestId, code, httpStatus, detail };
}

function stringField(body: unknown, key: string): string | null {
  if (!isRecord(body)) return null;
  const value = body[key];
  return typeof value === 'string' ? value : null;
}

/**
 * Pure mapping of an edge-function reply to a typed result (PLAN A18). A 200 body must echo the request id and
 * provider and carry a valid enum label; anything else is `bad_response`, never a guessed label.
 */
export function parseClassifyResponse(
  httpStatus: number,
  body: unknown,
  expected: { readonly requestId: string; readonly provider: RemoteProvider },
): RemoteClassifyResult {
  const { requestId } = expected;
  const reason = stringField(body, 'reason');
  if (httpStatus === 200) {
    if (!isRecord(body)) return errorResult(requestId, 'bad_response', httpStatus);
    const label: unknown = body['label'];
    const model: unknown = body['model'];
    const rawConfidence: unknown = body['confidence'];
    const rawDuplicate: unknown = body['duplicate'];
    const echoedId: unknown = body['request_id'];
    const fallbackReason: unknown = body['reason'];
    let confidence: number | null;
    if (rawConfidence === null) {
      confidence = null;
    } else if (typeof rawConfidence === 'number' && Number.isFinite(rawConfidence) && rawConfidence >= 0 && rawConfidence <= 1) {
      confidence = rawConfidence;
    } else {
      return errorResult(requestId, 'bad_response', httpStatus);
    }
    if (typeof echoedId !== 'string' || echoedId.toLowerCase() !== requestId.toLowerCase()) {
      return errorResult(requestId, 'bad_response', httpStatus);
    }
    if (body['provider'] !== expected.provider || typeof model !== 'string' || model.length === 0) {
      return errorResult(requestId, 'bad_response', httpStatus);
    }
    if (!isFreeTextLabel(label)) return errorResult(requestId, 'bad_response', httpStatus);
    if (rawDuplicate !== undefined && typeof rawDuplicate !== 'boolean') {
      return errorResult(requestId, 'bad_response', httpStatus);
    }
    const duplicate = rawDuplicate === true;
    if (body['status'] === 'ok') {
      return { kind: 'ok', requestId, label, confidence, provider: expected.provider, model, duplicate };
    }
    if (body['status'] === 'fallback' && label === 'manual' && confidence === null && isFallbackReason(fallbackReason)) {
      return { kind: 'fallback', requestId, label: 'manual', reason: fallbackReason, provider: expected.provider, model, duplicate };
    }
    return errorResult(requestId, 'bad_response', httpStatus);
  }
  switch (httpStatus) {
    case 400:
    case 413:
      return errorResult(requestId, 'invalid_input', httpStatus, stringField(body, 'field') ?? reason);
    case 401:
      return errorResult(requestId, 'unauthorized', httpStatus, reason);
    case 403:
      return errorResult(requestId, 'origin_not_allowed', httpStatus, reason);
    case 409:
      return errorResult(requestId, reason === 'conflict' ? 'conflict' : 'pending', httpStatus, reason);
    case 429:
      return errorResult(requestId, 'capped', httpStatus, reason);
    case 503:
      return errorResult(requestId, 'unavailable', httpStatus, reason);
    default:
      return errorResult(requestId, 'server_error', httpStatus, reason);
  }
}

/** Existing session, or a new anonymous one. Only reached after opt-in. */
async function ensureSession(client: SupabaseClient): Promise<boolean> {
  try {
    const current = await client.auth.getSession();
    if (current.error === null && current.data.session !== null) return true;
    const signedIn = await client.auth.signInAnonymously();
    return signedIn.error === null && signedIn.data.session !== null;
  } catch {
    return false;
  }
}

/** The HTTP Response attached to a supabase-js FunctionsHttpError/FunctionsRelayError, if any. */
function errorResponse(error: unknown): Response | null {
  if (!isRecord(error) && !(error instanceof Error)) return null;
  const context: unknown = (error as { context?: unknown }).context;
  return context instanceof Response ? context : null;
}

async function readJsonSafely(response: Response): Promise<unknown> {
  try {
    return (await response.json()) as unknown;
  } catch {
    return null;
  }
}

/** Classify one free-text NOT line with a remote provider. Never throws; never retries automatically. */
export async function classifyLineRemote(
  input: RemoteClassifyInput,
  deps: RemoteDeps = defaultDeps,
): Promise<RemoteClassifyResult> {
  const requestId = input.requestId ?? deps.newRequestId();
  if (input.optedIn !== true) return errorResult(requestId, 'not_opted_in');
  const client = deps.client;
  if (client === null) return errorResult(requestId, 'not_configured');
  if (input.line.trim().length === 0) return errorResult(requestId, 'invalid_input', null, 'line');

  if (!(await ensureSession(client))) return errorResult(requestId, 'sign_in_failed');

  const expected = { requestId, provider: input.provider };
  try {
    const { data, error } = await client.functions.invoke<unknown>(CLASSIFY_FUNCTION_NAME, {
      body: { request_id: requestId, provider: input.provider, line: input.line },
    });
    if (error === null) return parseClassifyResponse(200, data, expected);
    const response = errorResponse(error);
    if (response === null) return errorResult(requestId, 'network');
    return parseClassifyResponse(response.status, await readJsonSafely(response), expected);
  } catch {
    return errorResult(requestId, 'network');
  }
}

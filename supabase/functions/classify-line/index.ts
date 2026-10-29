// classify-line: live free-text classification for the Agent NOT-List Builder (PLAN A16-A20, M7 AC3; Claude §2.4).
//
// Caller: a signed-in user (Supabase anonymous sign-in, requested by the browser only after the user explicitly opts
// into a remote classifier). Gateway verify_jwt = true (supabase/config.toml) AND the handler verifies the bearer token
// with auth.getUser(token), so the project anon key sent as Bearer is rejected (401).
//
// Pipeline (every early exit charges nothing unless a reservation was made):
//   CORS preflight / origin allow-list → POST only → platform config → body ≤ 4 KiB (bytes, before parsing) → JWT →
//   JSON + strict body validation → provider secret/model config (503 BEFORE any reservation) → line length vs
//   app_limits.max_input_chars → SHA-256 of the line → reserve_model_call (single global lock, count caps,
//   idempotency) → ONE bounded provider call (15 s, small max_tokens, no retry) → finish_model_call → A18 response.
//
// Self-contained: imports only ./contract.ts (same function folder) and a pinned supabase-js; never anything from src/.
// Secrets are read with Deno.env.get only; their values are never logged or returned. The line text is never stored
// or logged.
import { createClient, type SupabaseClient } from 'npm:@supabase/supabase-js@2.45.4';
import {
  ANTHROPIC_ENDPOINT,
  ANTHROPIC_VERSION,
  type HttpReply,
  JEV_ENDPOINT,
  MAX_BODY_BYTES,
  PROVIDER_TIMEOUT_MS,
  type ProviderConfig,
  type ProviderOutcome,
  buildAnthropicRequest,
  buildJevRequest,
  bearerToken,
  checkLineLength,
  checkOrigin,
  corsHeaders,
  declaredLengthTooLarge,
  errorReply,
  finishParams,
  parseAllowedOrigins,
  parseAnthropicResponse,
  parseJevResponse,
  parseJsonText,
  parseMaxInputChars,
  parseReserveResult,
  providerFailure,
  readBoundedText,
  replyForProviderOutcome,
  replyForReserve,
  resolveProviderConfig,
  sha256Hex,
  shuffleLabels,
  unavailableReply,
  validateClassifyRequest,
} from './contract.ts';

type ReadyProviderConfig = Extract<ProviderConfig, { ok: true }>;

/** Trimmed, non-empty env value or undefined. */
function env(name: string): string | undefined {
  const value = Deno.env.get(name);
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function jsonResponse(reply: HttpReply, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(reply.body), {
    status: reply.status,
    headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

/** Uniform integer in [0, n) from the platform CSPRNG (used only to shuffle Jev options). */
function randomIndex(exclusiveMax: number): number {
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  return (buffer[0] ?? 0) % exclusiveMax;
}

/** Service-role client from the platform-injected credentials. Bypasses RLS, so it is used only after auth. */
function serviceClient(url: string, serviceRoleKey: string): SupabaseClient {
  return createClient(url, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

/** The verified user id for a bearer token, or null (anon key, service key, expired or forged token). */
async function verifyUser(admin: SupabaseClient, token: string): Promise<string | null> {
  try {
    const { data, error } = await admin.auth.getUser(token);
    if (error !== null) return null;
    const id = data.user?.id;
    return typeof id === 'string' && id.length > 0 ? id : null;
  } catch {
    return null;
  }
}

async function readMaxInputChars(admin: SupabaseClient): Promise<number | null> {
  const { data, error } = await admin.from('app_limits').select('max_input_chars').eq('id', true).maybeSingle();
  if (error !== null) return null;
  return parseMaxInputChars(data);
}

/** Exactly one provider request: AbortController timeout, no retry. The line is a single data field. */
async function callProvider(config: ReadyProviderConfig, line: string): Promise<ProviderOutcome> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROVIDER_TIMEOUT_MS);
  const started = Date.now();
  try {
    const response =
      config.provider === 'jev'
        ? await fetch(JEV_ENDPOINT, {
            method: 'POST',
            headers: { Authorization: `Bearer ${config.apiKey}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(buildJevRequest(line, config.model, shuffleLabels(randomIndex))),
            signal: controller.signal,
          })
        : await fetch(ANTHROPIC_ENDPOINT, {
            method: 'POST',
            headers: {
              'x-api-key': config.apiKey,
              'anthropic-version': ANTHROPIC_VERSION,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(buildAnthropicRequest(line, config.model)),
            signal: controller.signal,
          });
    const detail: Record<string, unknown> = { http_status: response.status };
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      return providerFailure('provider_error', { ...detail, latency_ms: Date.now() - started });
    }
    const parsed = parseJsonText(await response.text());
    detail['latency_ms'] = Date.now() - started;
    if (!parsed.ok) return providerFailure('unparsable', detail);
    const outcome = config.provider === 'jev' ? parseJevResponse(parsed.value) : parseAnthropicResponse(parsed.value);
    return { ...outcome, detail: { ...outcome.detail, ...detail } };
  } catch {
    const latency = { latency_ms: Date.now() - started };
    return controller.signal.aborted ? providerFailure('timeout', latency) : providerFailure('provider_error', latency);
  } finally {
    clearTimeout(timer);
  }
}

async function handle(req: Request): Promise<Response> {
  const origin = req.headers.get('Origin');
  const originCheck = checkOrigin(origin, parseAllowedOrigins(Deno.env.get('ALLOWED_ORIGINS')));
  const cors: Record<string, string> = originCheck === 'allowed' && origin !== null ? corsHeaders(origin) : {};
  const send = (reply: HttpReply, extra: Record<string, string> = {}): Response =>
    jsonResponse(reply, { ...cors, ...extra });

  // CORS is additional to the JWT check, never a substitute.
  if (req.method === 'OPTIONS') {
    if (originCheck !== 'allowed') return send(errorReply(403, 'origin_not_allowed'));
    return new Response(null, { status: 204, headers: cors });
  }
  if (originCheck === 'denied') return send(errorReply(403, 'origin_not_allowed'));
  if (req.method !== 'POST') return send(errorReply(405, 'method_not_allowed'), { Allow: 'POST, OPTIONS' });

  // Platform-injected credentials (never copied from another project).
  const supabaseUrl = env('SUPABASE_URL');
  const serviceRoleKey = env('SUPABASE_SERVICE_ROLE_KEY');
  if (supabaseUrl === undefined || serviceRoleKey === undefined) return send(unavailableReply('server_not_configured'));

  // Byte cap before any parsing: the declared length first, then the bytes actually read.
  if (declaredLengthTooLarge(req.headers.get('Content-Length'), MAX_BODY_BYTES)) {
    return send(errorReply(413, 'body_too_large'));
  }
  const body = await readBoundedText(req.body, MAX_BODY_BYTES);
  if (!body.ok) return send(errorReply(body.reason === 'body_too_large' ? 413 : 400, body.reason));

  const token = bearerToken(req.headers.get('Authorization'));
  if (token === null) return send(errorReply(401, 'unauthorized'));
  const admin = serviceClient(supabaseUrl, serviceRoleKey);
  const userId = await verifyUser(admin, token);
  if (userId === null) return send(errorReply(401, 'unauthorized'));

  const json = parseJsonText(body.text);
  if (!json.ok) return send(errorReply(400, 'invalid_json'));
  const validation = validateClassifyRequest(json.value);
  if (!validation.ok) return send(errorReply(400, 'invalid_request', { field: validation.field }));
  const request = validation.value;

  // Secret/model configuration BEFORE any reservation: a missing secret charges nothing.
  const config = resolveProviderConfig(request.provider, env);
  if (!config.ok) return send(unavailableReply(config.reason));

  const maxInputChars = await readMaxInputChars(admin);
  if (maxInputChars === null) {
    console.error('[classify-line] app_limits unreadable');
    return send(errorReply(500, 'internal'));
  }
  if (!checkLineLength(request.line_chars, maxInputChars)) {
    return send(errorReply(400, 'line_too_long', { max_input_chars: maxInputChars }));
  }

  const inputSha256 = await sha256Hex(request.line);
  const reserved = await admin.rpc('reserve_model_call', {
    p_user: userId,
    p_request: request.request_id,
    p_provider: request.provider,
    p_model: config.model,
    p_input_chars: request.line_chars,
    p_input_sha256: inputSha256,
  });
  if (reserved.error !== null) {
    console.error('[classify-line] reserve_model_call failed', reserved.error.code);
    return send(errorReply(500, 'internal'));
  }
  const row = parseReserveResult(reserved.data);
  if (row === null) {
    console.error('[classify-line] reserve_model_call returned an unexpected shape');
    return send(errorReply(500, 'internal'));
  }
  const early = replyForReserve(row, request, config.model);
  if (early !== null) return send(early);
  if (row.reservation_id === null) return send(errorReply(500, 'internal'));

  // Exactly one paid call for this reservation; the row stays charged whatever happens next.
  const outcome = await callProvider(config, request.line);
  const finished = await admin.rpc('finish_model_call', finishParams(row.reservation_id, userId, request.provider, outcome));
  if (finished.error !== null) {
    // The row stays 'reserved' (charged; a retry with the same request_id gets 409 pending). The answer is still real.
    console.error('[classify-line] finish_model_call failed', finished.error.code);
  } else if (finished.data !== true) {
    console.error('[classify-line] finish_model_call matched no reserved row');
  }
  if (outcome.kind === 'fallback') console.warn('[classify-line] provider fallback', request.provider, outcome.reason);
  return send(replyForProviderOutcome(outcome, request, config.model));
}

Deno.serve(async (req: Request): Promise<Response> => {
  try {
    return await handle(req);
  } catch (error) {
    console.error('[classify-line] unhandled error', error instanceof Error ? error.name : 'unknown');
    const origin = req.headers.get('Origin');
    const allowed = checkOrigin(origin, parseAllowedOrigins(Deno.env.get('ALLOWED_ORIGINS'))) === 'allowed';
    return jsonResponse(errorReply(500, 'internal'), allowed && origin !== null ? corsHeaders(origin) : {});
  }
});

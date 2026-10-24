// Nullable Supabase client (Bolt skill: centralised connection config, no crash at import without env).
// Only public configuration is read here: VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY. The anon key identifies the
// project, not a user; server secrets (provider API keys, service role) never have a VITE_ prefix and never reach
// the browser. The client is used only after the user explicitly opts into a remote classifier (M7).
import { createClient, type SupabaseClient } from '@supabase/supabase-js';

export const CLASSIFIER_MODES = ['keyword', 'mock', 'jev', 'llm'] as const;
export type ClassifierMode = (typeof CLASSIFIER_MODES)[number];

/** Classifier modes that need the classify-line edge function (and therefore Supabase + explicit opt-in). */
export const REMOTE_CLASSIFIER_MODES: readonly ClassifierMode[] = ['jev', 'llm'];

/** PLAN A15: keyword is the default classifier. */
export const DEFAULT_CLASSIFIER_MODE: ClassifierMode = 'keyword';

export interface SupabaseConfig {
  readonly url: string;
  readonly anonKey: string;
}

export type EnvSource = Readonly<Record<string, unknown>>;

function nonEmptyString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/** Public Supabase config from env, or null when absent/blank/not an http(s) URL (→ mock mode, no crash). */
export function readSupabaseConfig(env: EnvSource): SupabaseConfig | null {
  const url = nonEmptyString(env['VITE_SUPABASE_URL']);
  const anonKey = nonEmptyString(env['VITE_SUPABASE_ANON_KEY']);
  if (url === null || anonKey === null) return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
  return { url, anonKey };
}

export function isClassifierMode(value: unknown): value is ClassifierMode {
  return typeof value === 'string' && (CLASSIFIER_MODES as readonly string[]).includes(value);
}

/** Requested classifier from VITE_CLASSIFIER_MODE; unknown or missing → keyword. */
export function readClassifierMode(env: EnvSource): ClassifierMode {
  const raw = nonEmptyString(env['VITE_CLASSIFIER_MODE']);
  return isClassifierMode(raw) ? raw : DEFAULT_CLASSIFIER_MODE;
}

/**
 * The classifier active when the app starts. Remote modes are never active at startup: they need Supabase config
 * and an explicit opt-in in the UI (anonymous sign-in, M7), so a requested remote mode starts as keyword.
 */
export function startupClassifierMode(requested: ClassifierMode): ClassifierMode {
  return REMOTE_CLASSIFIER_MODES.includes(requested) ? DEFAULT_CLASSIFIER_MODE : requested;
}

function createNullableClient(config: SupabaseConfig | null): SupabaseClient | null {
  if (config === null) return null;
  try {
    return createClient(config.url, config.anonKey, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: false },
    });
  } catch {
    return null;
  }
}

const env: EnvSource = import.meta.env;

export const supabaseConfig: SupabaseConfig | null = readSupabaseConfig(env);
/** null in mock mode; the app must branch on this rather than assume a backend. */
export const supabase: SupabaseClient | null = createNullableClient(supabaseConfig);
export const isSupabaseConfigured: boolean = supabase !== null;
export const requestedClassifierMode: ClassifierMode = readClassifierMode(env);

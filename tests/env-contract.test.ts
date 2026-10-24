// Environment/secret contract (PLAN M1 AC4-AC6; Claude §5.1 env-contract.test.ts; Bolt skill "Configuration and
// secrets"). Static source checks run under vitest; they read files, never the real .env.
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  readClassifierMode,
  readSupabaseConfig,
  startupClassifierMode,
} from '../src/lib/supabase';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/** Server-side secret names (BOLT-HANDOFF.md). None may ever appear with a public VITE_ prefix. */
const SERVER_SECRET_NAMES = [
  'TYPESAFE_API_KEY',
  'ANTHROPIC_API_KEY',
  'LLM_MODEL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SERVICE_ROLE_KEY',
  'SUPABASE_DB_URL',
];

const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', 'coverage', 'live']);
const SCANNED_EXTENSIONS = ['.ts', '.tsx', '.js', '.mjs', '.json', '.html', '.md', '.toml', '.sql', '.example'];

function listFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) out.push(...listFiles(full));
    } else if (SCANNED_EXTENSIONS.some((ext) => entry.name.endsWith(ext))) {
      out.push(full);
    }
  }
  return out;
}

function scannedFiles(): string[] {
  const roots = ['src', 'supabase', 'cli', 'scripts', 'eval', 'public', 'docs'].map((d) => join(ROOT, d));
  const topLevel = ['.env.example', 'index.html', 'vite.config.ts', 'package.json', 'README.md', 'BOLT-HANDOFF.md'].map(
    (f) => join(ROOT, f),
  );
  return [...roots.flatMap(listFiles), ...topLevel.filter((f) => existsSync(f))];
}

describe('.env.example', () => {
  const lines = readFileSync(join(ROOT, '.env.example'), 'utf8')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));

  // what_bug_this_catches: a real project URL/key (or any new variable) committed to the placeholder file.
  it('contains exactly the three public placeholders', () => {
    expect(lines).toEqual(['VITE_SUPABASE_URL=', 'VITE_SUPABASE_ANON_KEY=', 'VITE_CLASSIFIER_MODE=mock']);
  });
});

describe('.gitignore', () => {
  const entries = new Set(
    readFileSync(join(ROOT, '.gitignore'), 'utf8')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'))
      .map((line) => (line.endsWith('/') ? line.slice(0, -1) : line)),
  );

  // what_bug_this_catches: .env files, build output, the generated runner or unreviewed live results being committed.
  it('ignores env files (except the example), build output, the generated runner and live results', () => {
    for (const required of ['.env', '.env.*', '!.env.example', 'node_modules', 'dist', 'public/policy-runner.mjs', 'results/live']) {
      expect(entries.has(required), required).toBe(true);
    }
  });
});

describe('no server secret is public', () => {
  // what_bug_this_catches: a provider or service-role key exposed to the browser bundle through a VITE_ name.
  it('uses no VITE_* name containing KEY/SECRET/TOKEN/PASSWORD except VITE_SUPABASE_ANON_KEY', () => {
    const offenders: string[] = [];
    for (const file of scannedFiles()) {
      const text = readFileSync(file, 'utf8');
      for (const match of text.matchAll(/\bVITE_[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*\b/g)) {
        if (match[0] !== 'VITE_SUPABASE_ANON_KEY') offenders.push(`${relative(ROOT, file)}: ${match[0]}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  // what_bug_this_catches: a server secret renamed with a public prefix (e.g. VITE_ANTHROPIC_API_KEY, VITE_LLM_MODEL).
  it('never prefixes a server secret name with VITE_', () => {
    const offenders: string[] = [];
    for (const file of scannedFiles()) {
      const text = readFileSync(file, 'utf8');
      for (const name of SERVER_SECRET_NAMES) {
        if (text.includes(`VITE_${name}`)) offenders.push(`${relative(ROOT, file)}: VITE_${name}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe('nullable Supabase config (mock mode without env)', () => {
  // what_bug_this_catches: the app crashing at import (createClient with an empty URL) on a fresh clone with no .env.
  it('returns null when env is absent, blank or malformed', () => {
    expect(readSupabaseConfig({})).toBeNull();
    expect(readSupabaseConfig({ VITE_SUPABASE_URL: '', VITE_SUPABASE_ANON_KEY: '' })).toBeNull();
    expect(readSupabaseConfig({ VITE_SUPABASE_URL: '   ', VITE_SUPABASE_ANON_KEY: 'k' })).toBeNull();
    expect(readSupabaseConfig({ VITE_SUPABASE_URL: 'not a url', VITE_SUPABASE_ANON_KEY: 'k' })).toBeNull();
    expect(readSupabaseConfig({ VITE_SUPABASE_URL: 'ftp://db.example.test', VITE_SUPABASE_ANON_KEY: 'k' })).toBeNull();
    expect(readSupabaseConfig({ VITE_SUPABASE_URL: 'https://db.example.test' })).toBeNull();
  });

  // what_bug_this_catches: a valid config being ignored, leaving the app stuck in mock mode after setup.
  it('returns the trimmed config when both values are present', () => {
    expect(
      readSupabaseConfig({ VITE_SUPABASE_URL: ' https://db.example.test ', VITE_SUPABASE_ANON_KEY: 'public-anon' }),
    ).toEqual({ url: 'https://db.example.test', anonKey: 'public-anon' });
  });

  // what_bug_this_catches: an unknown VITE_CLASSIFIER_MODE value selecting a remote provider, or the default not being
  // the keyword classifier (PLAN A15).
  it('defaults the classifier to keyword and accepts only known modes', () => {
    expect(readClassifierMode({})).toBe('keyword');
    expect(readClassifierMode({ VITE_CLASSIFIER_MODE: 'gpt' })).toBe('keyword');
    expect(readClassifierMode({ VITE_CLASSIFIER_MODE: 'mock' })).toBe('mock');
    expect(readClassifierMode({ VITE_CLASSIFIER_MODE: 'jev' })).toBe('jev');
  });

  // what_bug_this_catches: a remote (paid) classifier becoming active at startup without the user's explicit opt-in.
  it('never starts in a remote classifier mode', () => {
    expect(startupClassifierMode('jev')).toBe('keyword');
    expect(startupClassifierMode('llm')).toBe('keyword');
    expect(startupClassifierMode('mock')).toBe('mock');
    expect(startupClassifierMode('keyword')).toBe('keyword');
  });
});

describe('mock banner wiring (source-traceable, PLAN M1 AC6)', () => {
  const app = readFileSync(join(ROOT, 'src', 'ui', 'App.tsx'), 'utf8');
  const banner = readFileSync(join(ROOT, 'src', 'ui', 'ModeBanner.tsx'), 'utf8');

  // what_bug_this_catches: the banner being dropped from the shell, so a user cannot tell live classifiers are off.
  it('App renders ModeBanner from the nullable client state', () => {
    expect(app).toContain('<ModeBanner');
    expect(app).toContain('isSupabaseConfigured');
    expect(banner).toContain('Mock mode');
    expect(banner).toContain('no Supabase config');
  });
});

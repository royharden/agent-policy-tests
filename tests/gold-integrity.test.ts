// Gold integrity (PLAN M2 / A13 / A21, CONTRACTS C1/C3/C4/C5). The published held-out claim rests only on these frozen,
// hand-written files, so this suite checks that they are byte-identical to MANIFEST.json and internally consistent with
// eval/gold/RUBRIC.md. It deliberately re-implements the C1 action shape locally instead of importing src/policyfix: the
// gold must be checkable independently of the code under evaluation.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const GOLD_URL = new URL('../eval/gold/', import.meta.url);

const TRAPS = [
  'flag-reorder',
  'path-traversal',
  'case-fold',
  'prefix-wrap',
  'shell-wrapper',
  'chained',
  'sql-comment-split',
  'url-lookalike',
  'refspec-trick',
  'amount-boundary',
  'dialect-swap',
  'opaque',
  'near-miss-permitted',
] as const;
const NEUTRAL_TRAPS: readonly string[] = ['near-miss-permitted', 'opaque'];
const TEMPLATES = ['destructive-shell-fs', 'secrets-paths', 'network-egress', 'git-release', 'data-money'] as const;
const LABELS = [...TEMPLATES, 'manual'] as const;
const EXPECTED = ['deny', 'ask', 'allow', 'invalid'] as const;
const CONTEXTS = ['posix', 'windows'] as const;
const KINDS = ['shell', 'fs', 'http', 'sql', 'git', 'payment', 'message'] as const;
const DIALECTS = ['posix', 'powershell', 'cmd'] as const;
const FS_OPS = ['read', 'write', 'delete', 'list'] as const;
const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
const CHANNELS = ['email', 'slack', 'sms', 'webhook'] as const;
const PARAM_KEYS = ['command', 'branch', 'host', 'hosts', 'domain', 'glob', 'path', 'except', 'limit_cents', 'currency'] as const;
const MAX_CHARS = 4096;
const MAX_GIT_ARGS = 128;
const SPLITS = ['dev', 'heldout'] as const;
type Split = (typeof SPLITS)[number];
const ACTION_ROWS: Record<Split, number> = { dev: 80, heldout: 120 };
const CLASSIFIER_ROWS: Record<Split, number> = { dev: 60, heldout: 60 };
const MOCK_DEMO_LINES = ['never run terraform destroy', 'never push to the hotfix branch', 'never be rude to customers'];

interface ActionRow {
  id: string;
  context: string;
  action: unknown;
  expected: string;
  traps: string[];
  evasion: boolean;
  template: string | undefined;
  note: string;
}

interface ClassifierRow {
  id: string;
  line: string;
  label: string;
  params: Record<string, unknown> | undefined;
  injection: boolean;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function oneOf(v: unknown, list: readonly string[]): boolean {
  return typeof v === 'string' && list.includes(v);
}

function boundedString(v: unknown): boolean {
  return typeof v === 'string' && v.length >= 1 && v.length <= MAX_CHARS;
}

function exactKeys(o: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  return required.every((k) => k in o) && Object.keys(o).every((k) => required.includes(k) || optional.includes(k));
}

function isCurrencyCode(v: unknown): boolean {
  if (typeof v !== 'string' || v.length !== 3) return false;
  for (let i = 0; i < v.length; i += 1) {
    const c = v.charCodeAt(i);
    if (c < 65 || c > 90) return false;
  }
  return true;
}

/** CONTRACTS C1, strict: unknown keys, wrong enums, empty/oversized strings and non-integer cents are rejected. */
function isC1Action(a: unknown): boolean {
  if (!isRecord(a)) return false;
  switch (a.kind) {
    case 'shell':
      return exactKeys(a, ['kind', 'dialect', 'command']) && oneOf(a.dialect, DIALECTS) && boundedString(a.command);
    case 'fs': {
      const recursive = a.recursive;
      return (
        exactKeys(a, ['kind', 'op', 'path'], ['recursive']) &&
        oneOf(a.op, FS_OPS) &&
        boundedString(a.path) &&
        (recursive === undefined || typeof recursive === 'boolean')
      );
    }
    case 'http':
      return exactKeys(a, ['kind', 'method', 'url']) && oneOf(a.method, METHODS) && boundedString(a.url);
    case 'sql':
      return exactKeys(a, ['kind', 'statement']) && boundedString(a.statement);
    case 'git': {
      const args = a.args;
      return (
        exactKeys(a, ['kind', 'args']) &&
        Array.isArray(args) &&
        args.length <= MAX_GIT_ARGS &&
        args.every((x: unknown) => typeof x === 'string' && x.length <= MAX_CHARS) &&
        args.join(' ').length <= MAX_CHARS
      );
    }
    case 'payment': {
      const amount = a.amount_cents;
      return (
        exactKeys(a, ['kind', 'amount_cents', 'currency']) &&
        typeof amount === 'number' &&
        Number.isSafeInteger(amount) &&
        amount >= 0 &&
        isCurrencyCode(a.currency)
      );
    }
    case 'message':
      return exactKeys(a, ['kind', 'channel', 'to']) && oneOf(a.channel, CHANNELS) && boundedString(a.to);
    default:
      return false;
  }
}

function goldBytes(name: string): Buffer {
  return readFileSync(new URL(name, GOLD_URL));
}

function goldText(name: string): string {
  return goldBytes(name).toString('utf8');
}

function readJsonl(name: string): unknown[] {
  const text = goldText(name);
  const lines = text.split('\n');
  const last = lines.pop();
  if (last !== '') throw new Error(`${name}: must end with exactly one LF`);
  return lines.map((line, i) => {
    if (line.trim() === '') throw new Error(`${name}:${i + 1}: blank line`);
    return JSON.parse(line) as unknown;
  });
}

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map((x: unknown) => canonical(x)).join(',')}]`;
  if (isRecord(v)) {
    const keys = Object.keys(v).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

function actionRowProblems(raw: unknown, where: string): string[] {
  const p: string[] = [];
  if (!isRecord(raw)) return [`${where}: not an object`];
  if (!exactKeys(raw, ['id', 'context', 'action', 'expected', 'traps', 'evasion', 'note'], ['template'])) {
    p.push(`${where}: keys ${Object.keys(raw).join(',')} do not match C4`);
  }
  if (!boundedString(raw.id)) p.push(`${where}: id`);
  if (!oneOf(raw.context, CONTEXTS)) p.push(`${where}: context`);
  if (!oneOf(raw.expected, EXPECTED)) p.push(`${where}: expected`);
  if (typeof raw.evasion !== 'boolean') p.push(`${where}: evasion`);
  if (!boundedString(raw.note)) p.push(`${where}: note`);
  const template = raw.template;
  if (template !== undefined && !oneOf(template, TEMPLATES)) p.push(`${where}: template`);
  const traps = raw.traps;
  if (!Array.isArray(traps) || !traps.every((t: unknown) => oneOf(t, TRAPS))) p.push(`${where}: traps`);
  else if (new Set(traps).size !== traps.length) p.push(`${where}: duplicate trap`);
  return p;
}

function toActionRow(raw: unknown): ActionRow {
  if (!isRecord(raw) || actionRowProblems(raw, 'row').length > 0) throw new Error(`malformed action row: ${canonical(raw)}`);
  const traps = raw.traps;
  const template = raw.template;
  return {
    id: String(raw.id),
    context: String(raw.context),
    action: raw.action,
    expected: String(raw.expected),
    traps: Array.isArray(traps) ? traps.map((t: unknown) => String(t)) : [],
    evasion: raw.evasion === true,
    template: typeof template === 'string' ? template : undefined,
    note: String(raw.note),
  };
}

function classifierRowProblems(raw: unknown, where: string): string[] {
  const p: string[] = [];
  if (!isRecord(raw)) return [`${where}: not an object`];
  if (!exactKeys(raw, ['id', 'line', 'label', 'injection'], ['params', 'note'])) p.push(`${where}: keys do not match C5`);
  if (!boundedString(raw.id)) p.push(`${where}: id`);
  const line = raw.line;
  if (typeof line !== 'string' || line.trim() === '' || line.includes('\n')) p.push(`${where}: line`);
  if (!oneOf(raw.label, LABELS)) p.push(`${where}: label`);
  if (typeof raw.injection !== 'boolean') p.push(`${where}: injection`);
  const note = raw.note;
  if (note !== undefined && typeof note !== 'string') p.push(`${where}: note`);
  const params = raw.params;
  if (params !== undefined) {
    if (!isRecord(params) || Object.keys(params).length === 0) p.push(`${where}: params must be a non-empty object`);
    else {
      for (const [k, v] of Object.entries(params)) {
        if (!oneOf(k, PARAM_KEYS)) p.push(`${where}: unknown param ${k}`);
        else if (k === 'limit_cents') {
          if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) p.push(`${where}: limit_cents`);
        } else if (k === 'currency') {
          if (!isCurrencyCode(v)) p.push(`${where}: currency`);
        } else if (k === 'hosts' || k === 'except') {
          if (!Array.isArray(v) || v.length === 0 || !v.every((x: unknown) => boundedString(x))) p.push(`${where}: ${k}`);
        } else if (!boundedString(v)) p.push(`${where}: ${k}`);
      }
      if (('limit_cents' in params) !== ('currency' in params)) p.push(`${where}: limit_cents and currency go together`);
    }
  }
  return p;
}

function toClassifierRow(raw: unknown): ClassifierRow {
  if (!isRecord(raw) || classifierRowProblems(raw, 'row').length > 0) throw new Error(`malformed classifier row: ${canonical(raw)}`);
  const params = raw.params;
  return {
    id: String(raw.id),
    line: String(raw.line),
    label: String(raw.label),
    params: isRecord(params) ? params : undefined,
    injection: raw.injection === true,
  };
}

function isProhibited(r: ActionRow): boolean {
  return r.expected !== 'allow';
}

function hasEvasionTrap(r: ActionRow): boolean {
  return r.traps.some((t) => !NEUTRAL_TRAPS.includes(t));
}

function shellDialect(r: ActionRow): string | undefined {
  const a = r.action;
  if (!isRecord(a) || a.kind !== 'shell') return undefined;
  const dialect = a.dialect;
  return typeof dialect === 'string' ? dialect : undefined;
}

function actionKind(r: ActionRow): string | undefined {
  const a = r.action;
  if (!isRecord(a)) return undefined;
  const kind = a.kind;
  return typeof kind === 'string' ? kind : undefined;
}

function normaliseLine(s: string): string {
  return s.trim().toLowerCase().split(/\s+/).join(' ');
}

const rawActions: Record<Split, unknown[]> = {
  dev: readJsonl('actions.dev.jsonl'),
  heldout: readJsonl('actions.heldout.jsonl'),
};
const rawClassifier: Record<Split, unknown[]> = {
  dev: readJsonl('classifier.dev.jsonl'),
  heldout: readJsonl('classifier.heldout.jsonl'),
};

function actions(split: Split): ActionRow[] {
  return rawActions[split].map((r) => toActionRow(r));
}

function classifier(split: Split): ClassifierRow[] {
  return rawClassifier[split].map((r) => toClassifierRow(r));
}

function actionSummary(rows: ActionRow[]): Record<string, unknown> {
  const byExpected: Record<string, number> = {};
  for (const e of EXPECTED) byExpected[e] = rows.filter((r) => r.expected === e).length;
  const traps: Record<string, number> = {};
  for (const t of TRAPS) traps[t] = rows.filter((r) => r.traps.includes(t)).length;
  const prohibited = rows.filter(isProhibited).length;
  return {
    rows: rows.length,
    prohibited,
    permitted: rows.length - prohibited,
    evasion: rows.filter((r) => r.evasion).length,
    opaque: rows.filter((r) => r.traps.includes('opaque')).length,
    by_expected: byExpected,
    traps,
  };
}

function classifierSummary(rows: ClassifierRow[]): Record<string, unknown> {
  const byLabel: Record<string, number> = {};
  for (const l of LABELS) byLabel[l] = rows.filter((r) => r.label === l).length;
  return {
    rows: rows.length,
    manual: rows.filter((r) => r.label === 'manual').length,
    injection: rows.filter((r) => r.injection).length,
    by_label: byLabel,
  };
}

const manifest: unknown = JSON.parse(goldText('MANIFEST.json'));

function manifestField(key: string): unknown {
  return isRecord(manifest) ? manifest[key] : undefined;
}

describe('gold MANIFEST.json', () => {
  it('records a sha256 for every gold file that matches its exact bytes', () => {
    // what_bug_this_catches: a gold file edited after freezing (or its line endings rewritten by git core.autocrlf)
    // without a new manifest, silently changing the data the published held-out number rests on.
    const files = manifestField('files');
    expect(isRecord(files)).toBe(true);
    if (!isRecord(files)) return;
    for (const [name, entry] of Object.entries(files)) {
      expect(isRecord(entry), name).toBe(true);
      if (!isRecord(entry)) continue;
      const bytes = goldBytes(name);
      expect(createHash('sha256').update(bytes).digest('hex'), name).toBe(entry.sha256);
      expect(bytes.length, name).toBe(entry.bytes);
    }
  });

  it('covers exactly the files present in eval/gold, excluding itself', () => {
    // what_bug_this_catches: a new gold file (e.g. a third split) added without being hashed, or a manifest entry
    // pointing at a deleted file, so the integrity check would pass while not covering the data actually used.
    const entries = manifestField('files');
    const files = isRecord(entries) ? Object.keys(entries).sort() : [];
    const present = readdirSync(GOLD_URL)
      .filter((n) => n !== 'MANIFEST.json')
      .sort();
    expect(files).toEqual(present);
    expect(files).toEqual(
      expect.arrayContaining([
        'reference-answers.json',
        'RUBRIC.md',
        'actions.dev.jsonl',
        'actions.heldout.jsonl',
        'classifier.dev.jsonl',
        'classifier.heldout.jsonl',
      ]),
    );
  });

  it('discloses builder authorship and records seed and freeze dates', () => {
    // what_bug_this_catches: an unfrozen manifest (the M3 gate requires frozen_at) or a gold set presented as
    // independently labelled when the builder wrote it.
    expect(manifestField('author')).toBe('S21-INT coder-high subagent (builder-authored, not independent)');
    expect(Number.isSafeInteger(manifestField('seed'))).toBe(true);
    for (const k of ['authored_at', 'frozen_at']) {
      const v = manifestField(k);
      expect(typeof v, k).toBe('string');
      expect(Number.isNaN(Date.parse(String(v))), k).toBe(false);
    }
    expect(Date.parse(String(manifestField('frozen_at')))).toBeGreaterThanOrEqual(
      Date.parse(String(manifestField('authored_at'))),
    );
  });

  it('records counts that match the data', () => {
    // what_bug_this_catches: rows added, removed or relabelled while the manifest still reports the old per-split,
    // per-trap and evasion counts that the README and results quote.
    const recorded = manifestField('counts');
    expect(isRecord(recorded)).toBe(true);
    const counts = isRecord(recorded) ? recorded : {};
    expect(counts.actions).toEqual({ dev: actionSummary(actions('dev')), heldout: actionSummary(actions('heldout')) });
    expect(counts.classifier).toEqual({
      dev: classifierSummary(classifier('dev')),
      heldout: classifierSummary(classifier('heldout')),
    });
  });
});

describe('gold reference-answers.json', () => {
  it('equals the frozen CONTRACTS C3 reference values', () => {
    // what_bug_this_catches: the answers or evaluation contexts drifting from the values the gold labels were written
    // against (e.g. a widened host list or a changed payment limit), which would make every expected verdict suspect.
    const reference: unknown = JSON.parse(goldText('reference-answers.json'));
    expect(reference).toEqual({
      contexts: {
        posix: {
          project_root: '/workspace/demo',
          cwd: '/workspace/demo',
          home: '/home/dev',
          path_flavor: 'posix',
          case_insensitive_fs: false,
          grammar_version: '1',
        },
        windows: {
          project_root: 'C:\\workspace\\demo',
          cwd: 'C:\\workspace\\demo',
          home: 'C:\\Users\\dev',
          path_flavor: 'windows',
          case_insensitive_fs: true,
          grammar_version: '1',
        },
      },
      default_unmatched: 'allow',
      answers: {
        Q01: { context: "<one of contexts; the eval substitutes each row's context>" },
        Q02: { block: true },
        Q03: { block: true, except: ['node_modules', 'dist', '.cache'] },
        Q04: { block: true },
        Q05: { secret_globs: ['.env', '.env.*', '*.pem', 'id_*', 'secrets/**'], exceptions: ['.env.example'] },
        Q06: { enabled: true, hosts: ['api.example.test', '*.cdn.example.test'] },
        Q07: { enabled: true, domains: ['example.test'] },
        Q08: { block: true },
        Q09: { branches: ['main', 'release/*'] },
        Q10: { mode: 'deny' },
        Q11: { block: true },
        Q12: { limit_cents: 5000, currency: 'USD' },
      },
    });
  });
});

describe.each(SPLITS)('gold actions.%s.jsonl', (split) => {
  it('has the planned row count and every row matches the C4 shape', () => {
    // what_bug_this_catches: a truncated or hand-edited split, a typo in a trap or verdict name, or a missing note,
    // any of which would make the scorer silently skip or misclassify rows.
    expect(rawActions[split]).toHaveLength(ACTION_ROWS[split]);
    const problems = rawActions[split].flatMap((r, i) => actionRowProblems(r, `${split}:${i + 1}`));
    expect(problems).toEqual([]);
  });

  it('labels a row invalid exactly when its action violates the C1 schema', () => {
    // what_bug_this_catches: a row expected to be evaluated whose action the strict schema would reject (it could
    // never reach the guard), or an `invalid` row whose action is actually valid (the label would be wrong).
    const wrong = actions(split)
      .filter((r) => isC1Action(r.action) === (r.expected === 'invalid'))
      .map((r) => r.id);
    expect(wrong).toEqual([]);
  });

  it('contains every one of the 13 traps, with dialect-swap in both PowerShell and cmd', () => {
    // what_bug_this_catches: a split that no longer exercises a named trap, so acceptance item 4 ("every named trap
    // has a dev and a held-out fixture") would be claimed without evidence.
    const rows = actions(split);
    const missing = TRAPS.filter((t) => !rows.some((r) => r.traps.includes(t)));
    expect(missing).toEqual([]);
    const swapDialects = new Set(rows.filter((r) => r.traps.includes('dialect-swap')).map((r) => shellDialect(r)));
    expect(swapDialects.has('powershell')).toBe(true);
    expect(swapDialects.has('cmd')).toBe(true);
  });

  it('sets evasion exactly when a prohibited row carries a trap other than near-miss-permitted or opaque', () => {
    // what_bug_this_catches: evasion flags that disagree with the trap tags (PLAN A13), which would inflate or
    // deflate the evasion block rate's denominator, or an evasion flag on a permitted row.
    const wrong = actions(split)
      .filter((r) => r.evasion !== (isProhibited(r) && hasEvasionTrap(r)))
      .map((r) => r.id);
    expect(wrong).toEqual([]);
  });

  it('keeps near-miss rows permitted and opaque rows at ask unless a visible deny decides', () => {
    // what_bug_this_catches: a near-miss labelled as blocked (it would count against the permitted allow rate) or an
    // opaque construct labelled allow/deny, contradicting the fail-closed `ask` rule.
    const rows = actions(split);
    expect(rows.filter((r) => r.traps.includes('near-miss-permitted') && r.expected !== 'allow').map((r) => r.id)).toEqual([]);
    const badOpaque = rows.filter((r) => {
      if (!r.traps.includes('opaque')) return false;
      if (r.expected === 'ask') return false;
      return !(r.expected === 'deny' && hasEvasionTrap(r));
    });
    expect(badOpaque.map((r) => r.id)).toEqual([]);
  });

  it('covers all seven action kinds, all five templates and both contexts', () => {
    // what_bug_this_catches: a split that never exercises one action kind or template, so a guard that ignores
    // e.g. message recipients or payments would score as if it handled them.
    const rows = actions(split);
    expect(KINDS.filter((k) => !rows.some((r) => actionKind(r) === k))).toEqual([]);
    expect(TEMPLATES.filter((t) => !rows.some((r) => r.template === t))).toEqual([]);
    expect(CONTEXTS.filter((c) => !rows.some((r) => r.context === c))).toEqual([]);
    expect(rows.filter((r) => r.template === undefined).map((r) => r.id)).toEqual([]);
  });

  it('evaluates PowerShell and cmd rows under the windows context and posix shell rows under posix', () => {
    // what_bug_this_catches: a Windows-syntax command labelled against the posix root (C:\ paths would always look
    // "outside the root"), producing verdicts that no correct guard could match.
    const wrong = actions(split).filter((r) => {
      const d = shellDialect(r);
      if (d === 'posix') return r.context !== 'posix';
      if (d === 'powershell' || d === 'cmd') return r.context !== 'windows';
      return false; // not a shell row, or a deliberately invalid dialect (expected `invalid`, never evaluated)
    });
    expect(wrong.map((r) => r.id)).toEqual([]);
  });

  it('is roughly half prohibited, with roughly a third of the prohibited rows being evasions', () => {
    // what_bug_this_catches: a lopsided split (e.g. almost all prohibited) that would make the permitted allow rate
    // or the evasion block rate rest on a handful of rows.
    const rows = actions(split);
    const prohibited = rows.filter(isProhibited);
    const evasion = prohibited.filter((r) => r.evasion);
    expect(prohibited.length / rows.length).toBeGreaterThanOrEqual(0.4);
    expect(prohibited.length / rows.length).toBeLessThanOrEqual(0.6);
    expect(evasion.length / prohibited.length).toBeGreaterThanOrEqual(0.25);
    expect(evasion.length / prohibited.length).toBeLessThanOrEqual(0.45);
  });
});

describe('gold actions across splits', () => {
  it('uses unique ids across all gold files', () => {
    // what_bug_this_catches: two rows sharing an id, so named failures and Roy's review sample could point at the
    // wrong row.
    const ids = [
      ...SPLITS.flatMap((s) => actions(s).map((r) => r.id)),
      ...SPLITS.flatMap((s) => classifier(s).map((r) => r.id)),
    ];
    expect(ids.filter((id, i) => ids.indexOf(id) !== i)).toEqual([]);
  });

  it('never repeats a (context, action) pair within or across splits', () => {
    // what_bug_this_catches: held-out rows copied from dev (leaking tuning data into the published number) or
    // duplicated rows that double-count one behaviour.
    const keys = SPLITS.flatMap((s) => actions(s).map((r) => canonical({ context: r.context, action: r.action })));
    expect(keys.filter((k, i) => keys.indexOf(k) !== i)).toEqual([]);
  });
});

describe.each(SPLITS)('gold classifier.%s.jsonl', (split) => {
  it('has the planned row count and every row matches the C5 shape', () => {
    // what_bug_this_catches: an off-enum label, a malformed params object (e.g. dollars instead of integer cents),
    // or a multi-line "line" that the classifier would never receive.
    expect(rawClassifier[split]).toHaveLength(CLASSIFIER_ROWS[split]);
    const problems = rawClassifier[split].flatMap((r, i) => classifierRowProblems(r, `${split}:${i + 1}`));
    expect(problems).toEqual([]);
  });

  it('includes every label, at least 8 manual lines and at least 4 injection lines, all injections manual', () => {
    // what_bug_this_catches: a split where an injection line is labelled with a template (rewarding a classifier that
    // obeys the injection) or where manual/injection cases are too few to measure false compiles.
    const rows = classifier(split);
    expect(LABELS.filter((l) => !rows.some((r) => r.label === l))).toEqual([]);
    expect(rows.filter((r) => r.label === 'manual').length).toBeGreaterThanOrEqual(8);
    expect(rows.filter((r) => r.injection).length).toBeGreaterThanOrEqual(4);
    expect(rows.filter((r) => r.injection && r.label !== 'manual').map((r) => r.id)).toEqual([]);
    expect(rows.filter((r) => r.label === 'manual' && r.params !== undefined).map((r) => r.id)).toEqual([]);
  });
});

describe('gold classifier across splits', () => {
  it('has no line repeated within or across splits', () => {
    // what_bug_this_catches: held-out lines that also appear in dev, which would let a threshold tuned on dev be
    // scored on lines it has already seen.
    const lines = SPLITS.flatMap((s) => classifier(s).map((r) => normaliseLine(r.line)));
    expect(lines.filter((l, i) => lines.indexOf(l) !== i)).toEqual([]);
  });

  it('keeps the mock provider demo lines out of the gold', () => {
    // what_bug_this_catches: the mock demo stub (a fixed lookup of the demo lines) being scored on gold rows it was
    // written to answer, which would make the stub look like a real classifier.
    const lines = SPLITS.flatMap((s) => classifier(s).map((r) => normaliseLine(r.line)));
    expect(MOCK_DEMO_LINES.filter((l) => lines.includes(normaliseLine(l)))).toEqual([]);
  });
});

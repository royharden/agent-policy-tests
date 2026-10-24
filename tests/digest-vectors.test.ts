// Fixed SHA-256 vectors for the canonical JSON digest (PLAN M1 AC3, Claude §5.1 digest-vectors.test.ts).
// The expected hex values were computed with node:crypto over canonical strings built independently from explicit
// code points (String.fromCodePoint for `"`, `\`, é, 😀), each checked to equal the literal below; no project code was
// run to produce them. `abc` and the empty string are the standard FIPS 180-2 vectors.
import { describe, expect, it } from 'vitest';
import { type Policy, validatePolicy } from '../src/policyfix/action';
import { canonicalJson, digestOf, policyDigestInput, policySha, sha256Hex } from '../src/policyfix/digest';
import type { Result } from '../src/policyfix/errors';

function unwrap<T>(result: Result<T>): T {
  if (!result.ok) throw new Error(`expected ok, got ${JSON.stringify(result.errors)}`);
  return result.value;
}

interface Vector {
  readonly name: string;
  readonly input: unknown;
  readonly canonical: string;
  readonly sha256: string;
}

const VECTORS: readonly Vector[] = [
  {
    name: 'nested key order is sorted recursively; arrays keep order',
    input: { c: { z: true, y: null }, b: 1, a: [3, 1, 2] },
    canonical: '{"a":[3,1,2],"b":1,"c":{"y":null,"z":true}}',
    sha256: '2a4b28cf0ebd27fc5e5d487bc4b7f051ee5043a09f774ecd9da630cf1e97fbd0',
  },
  {
    name: 'string values are NFC-normalised (e + combining acute → é)',
    input: { name: 'é' },
    canonical: '{"name":"é"}',
    sha256: '2f16b8477146a1b2ba7d6bb7cf7c9979c191cc2838a107dbf5f0d920b4cb3ba1',
  },
  {
    name: 'keys are NFC-normalised too',
    input: { 'é': 1 },
    canonical: '{"é":1}',
    sha256: 'ddcfcf4765da163969972bb20660092ca2787782d9352d1d8a38e93f70acf3bf',
  },
  {
    name: 'undefined properties are omitted',
    input: { a: 1, b: undefined },
    canonical: '{"a":1}',
    sha256: '015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862',
  },
  {
    name: 'array [1,2]',
    input: [1, 2],
    canonical: '[1,2]',
    sha256: '49a64717d5d4cb19952e6eac2946415cf6879adacf9908e7d872332d32c6e684',
  },
  {
    name: 'array [2,1] (order is significant)',
    input: [2, 1],
    canonical: '[2,1]',
    sha256: 'af1a1fc110b6094c48582b0ef83553cb7908d7a4365424eef28e76ef6c88d630',
  },
  {
    name: 'numbers use JSON.stringify form (-0 → 0, 1e21 → 1e+21)',
    input: { n: -0, f: 1.5, big: 1e21, neg: -2 },
    canonical: '{"big":1e+21,"f":1.5,"n":0,"neg":-2}',
    sha256: '46c2d6da4466e6bcd6a7d7fb5a2127f8e78baa6ee71459d5bbd4fd9b13f347e8',
  },
  {
    name: 'keys sort by UTF-16 code unit (B < _ < a < b < é)',
    input: { b: 0, 'é': 0, a: 0, _: 0, B: 0 },
    canonical: '{"B":0,"_":0,"a":0,"b":0,"é":0}',
    sha256: 'cbab73624c1da3b9385db875bd3a1bef1fd65da854e55a84e4cb13543249c5d1',
  },
  {
    name: 'quotes and newlines use JSON escapes',
    input: { q: 'say "hi"\n' },
    // 20 chars: the escapes are literal backslash sequences (\" \" \n), not a real newline (U+000A).
    canonical: '{"q":"say \\"hi\\"\\n"}',
    sha256: '0aaf9b20f0c695d5ed1356168464a5f38ab853afd001d82ac0cda322100e2b3a',
  },
  {
    name: 'astral characters are hashed as 4-byte UTF-8',
    input: { s: '😀' },
    canonical: '{"s":"😀"}',
    sha256: 'f9949e1006d1ca22bc0b60ea94f09779f11a8f0a29bae250fc7ab313d879f5e7',
  },
  {
    name: 'empty object',
    input: {},
    canonical: '{}',
    sha256: '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
  },
  {
    name: 'empty array',
    input: [],
    canonical: '[]',
    sha256: '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
  },
];

const POLICY: Policy = {
  engine_version: '0.1.0',
  grammar_version: '1',
  context: {
    project_root: '/workspace/demo',
    cwd: '/workspace/demo',
    home: '/home/dev',
    path_flavor: 'posix',
    case_insensitive_fs: false,
    grammar_version: '1',
  },
  default_unmatched: 'allow',
  rules: [
    {
      id: 'Q11.sql-drop',
      source_answer: 'Q11',
      template: 'data-money',
      effect: 'deny',
      match: [{ op: 'in', field: 'sql.verb', values: ['DROP', 'TRUNCATE'] }],
      intent: 'Block destructive SQL',
    },
  ],
  manual_items: [],
  dispositions: [{ source_answer: 'Q11', disposition: 'restricted', rule_ids: ['Q11.sql-drop'], manual_item_ids: [] }],
};

const POLICY_CANONICAL =
  '{"context":{"case_insensitive_fs":false,"cwd":"/workspace/demo","grammar_version":"1","home":"/home/dev","path_flavor":"posix","project_root":"/workspace/demo"},"default_unmatched":"allow","dispositions":[{"disposition":"restricted","manual_item_ids":[],"rule_ids":["Q11.sql-drop"],"source_answer":"Q11"}],"engine_version":"0.1.0","grammar_version":"1","manual_items":[],"rules":[{"effect":"deny","id":"Q11.sql-drop","intent":"Block destructive SQL","match":[{"field":"sql.verb","op":"in","values":["DROP","TRUNCATE"]}],"source_answer":"Q11","template":"data-money"}]}';
const POLICY_SHA = '060a6b5a1f11d92c409f09e784070fa762a35c6e704d8ddff3cf5e243666a34a';

describe('sha256Hex (@noble/hashes)', () => {
  // what_bug_this_catches: a wrong hash library wiring (e.g. hashing UTF-16 code units or hex-encoding twice)
  // that would silently change every policy_sha/fixtures_sha the runner compares.
  it('matches the FIPS 180-2 vectors', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});

describe('canonicalJson + digestOf fixed vectors', () => {
  for (const vector of VECTORS) {
    // what_bug_this_catches: a canonicaliser change (key order, NFC, number form, escaping, undefined handling)
    // that makes the browser and the exported runner disagree on digests for the same content.
    it(vector.name, () => {
      expect(unwrap(canonicalJson(vector.input))).toBe(vector.canonical);
      expect(unwrap(digestOf(vector.input))).toBe(vector.sha256);
    });
  }

  // what_bug_this_catches: insertion order leaking into the digest, so re-serialising the same policy stales approvals.
  it('is independent of key insertion order', () => {
    expect(unwrap(digestOf({ a: 1, b: { c: 2, d: 3 } }))).toBe(unwrap(digestOf({ b: { d: 3, c: 2 }, a: 1 })));
  });
});

describe('canonicalJson rejects values that cannot be hashed deterministically', () => {
  // what_bug_this_catches: NaN/Infinity silently serialised as null (JSON.stringify behaviour), making two different
  // documents share a digest.
  it('rejects NaN and Infinity with a pointer', () => {
    const nan = canonicalJson({ x: [1, Number.NaN] });
    expect(nan.ok).toBe(false);
    if (!nan.ok) expect(nan.errors[0]).toMatchObject({ code: 'non_finite', pointer: '/x/1' });
    const inf = canonicalJson({ y: Number.POSITIVE_INFINITY });
    expect(inf.ok).toBe(false);
    if (!inf.ok) expect(inf.errors[0]).toMatchObject({ code: 'non_finite', pointer: '/y' });
  });

  // what_bug_this_catches: [undefined] hashed as [null], colliding with a real null entry.
  it('rejects undefined inside arrays', () => {
    const result = canonicalJson([1, undefined]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors[0]).toMatchObject({ code: 'invalid_type', pointer: '/1' });
  });

  // what_bug_this_catches: two keys that are equal after NFC (é vs e+U+0301) silently overwriting each other.
  it('rejects keys that collide after NFC normalisation', () => {
    const result = canonicalJson({ 'é': 1, 'é': 2 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors[0]?.code).toBe('non_canonical');
  });

  // what_bug_this_catches: Date/Map/class instances hashed via their enumerable props (Date → {}), losing content.
  it('rejects non-plain objects, bigint and functions', () => {
    expect(canonicalJson({ when: new Date(0) }).ok).toBe(false);
    expect(canonicalJson({ m: new Map([[1, 2]]) }).ok).toBe(false);
    expect(canonicalJson({ n: BigInt(1) }).ok).toBe(false);
    expect(canonicalJson({ f: (): number => 1 }).ok).toBe(false);
  });

  // what_bug_this_catches: infinite recursion (stack overflow crash) on a cyclic object instead of a structured error.
  it('rejects cycles', () => {
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic['self'] = cyclic;
    const result = canonicalJson(cyclic);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors[0]).toMatchObject({ code: 'non_canonical', pointer: '/self' });
  });

  // what_bug_this_catches: a shared (non-cyclic) sub-object being mistaken for a cycle.
  it('accepts the same object referenced twice (DAG, not a cycle)', () => {
    const shared = { k: 1 };
    expect(unwrap(canonicalJson({ a: shared, b: shared }))).toBe('{"a":{"k":1},"b":{"k":1}}');
  });
});

describe('policy_sha', () => {
  // what_bug_this_catches: the policy digest covering the wrong field set (e.g. dropping context or default_unmatched,
  // so a context edit would not stale the report).
  it('hashes exactly the policy content fields (fixed vector)', () => {
    const policy = unwrap(validatePolicy(POLICY));
    expect(unwrap(canonicalJson(policyDigestInput(policy)))).toBe(POLICY_CANONICAL);
    expect(unwrap(policySha(policy))).toBe(POLICY_SHA);
  });

  // what_bug_this_catches: approvals being hashed into policy_sha, so acknowledging an item stales the report and the
  // export gate can never be satisfied (PLAN A14).
  it('excludes approvals and any other extra property', () => {
    const withApprovals = {
      ...POLICY,
      approvals: [{ item: 'Q11.sql-drop', digest: 'abc', approved_at: '2026-10-24T00:00:00Z' }],
    };
    expect(unwrap(policySha(withApprovals))).toBe(POLICY_SHA);
  });

  // what_bug_this_catches: a context change (e.g. project_root) not changing policy_sha, letting a stale report export.
  it('changes when the context changes', () => {
    const moved: Policy = { ...POLICY, context: { ...POLICY.context, project_root: '/workspace/other' } };
    expect(unwrap(policySha(moved))).not.toBe(POLICY_SHA);
  });

  // what_bug_this_catches: strict-policy mode (default_unmatched) not being part of the digest.
  it('changes when default_unmatched changes', () => {
    const strict: Policy = { ...POLICY, default_unmatched: 'ask' };
    expect(unwrap(policySha(strict))).not.toBe(POLICY_SHA);
  });
});

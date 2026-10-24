// Canonical JSON + SHA-256 (PLAN M1 AC3, Claude §2.5 "Digests"). SHA-256 comes from @noble/hashes (MIT, audited);
// there is no hand-written hash. Framework-free: the same code runs in the browser build and the esbuild runner.
//
// Canonical form:
//   - object keys NFC-normalised, then sorted by UTF-16 code unit order, recursively;
//   - arrays keep their order;
//   - strings NFC-normalised, then serialised with JSON.stringify escaping; the text is hashed as UTF-8;
//   - properties whose value is `undefined` are omitted; `undefined` inside an array is rejected;
//   - numbers must be finite and are serialised by JSON.stringify (so -0 → 0, 1e21 → 1e+21);
//   - only plain objects, arrays, strings, finite numbers, booleans and null are accepted (no Date/Map/class
//     instances, bigint, functions or symbols); cycles and NFC key collisions are rejected.
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import type { Fixture, Policy } from './action';
import type { EvaluationContext } from './context';
import { type ErrorCode, fail, makeError, ok, type PathSegment, type Result, toPointer } from './errors';

class CanonicalError extends Error {
  readonly code: ErrorCode;
  readonly path: readonly PathSegment[];

  constructor(code: ErrorCode, path: readonly PathSegment[], message: string) {
    super(message);
    this.code = code;
    this.path = path;
  }
}

function compareCodeUnits(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function encodeValue(value: unknown, path: readonly PathSegment[], ancestors: Set<object>): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new CanonicalError('non_finite', path, 'Non-finite numbers cannot be hashed.');
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value.normalize('NFC'));
    case 'object':
      return encodeContainer(value, path, ancestors);
    default:
      throw new CanonicalError('invalid_type', path, `Values of type ${typeof value} cannot be hashed.`);
  }
}

function encodeContainer(value: object, path: readonly PathSegment[], ancestors: Set<object>): string {
  if (ancestors.has(value)) throw new CanonicalError('non_canonical', path, 'Cyclic structure cannot be hashed.');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const items: readonly unknown[] = value;
      const parts = items.map((item, index) => {
        if (item === undefined) {
          throw new CanonicalError('invalid_type', [...path, index], 'undefined inside an array cannot be hashed.');
        }
        return encodeValue(item, [...path, index], ancestors);
      });
      return `[${parts.join(',')}]`;
    }
    const proto: unknown = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new CanonicalError('invalid_type', path, 'Only plain objects can be hashed.');
    }
    const record = value as Readonly<Record<string, unknown>>;
    const entries = new Map<string, unknown>();
    for (const rawKey of Object.keys(record)) {
      const entryValue = record[rawKey];
      if (entryValue === undefined) continue;
      const key = rawKey.normalize('NFC');
      if (entries.has(key)) {
        throw new CanonicalError('non_canonical', [...path, rawKey], `Keys collide after NFC normalisation: "${key}".`);
      }
      entries.set(key, entryValue);
    }
    const keys = [...entries.keys()].sort(compareCodeUnits);
    const parts = keys.map((key) => `${JSON.stringify(key)}:${encodeValue(entries.get(key), [...path, key], ancestors)}`);
    return `{${parts.join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

/** Canonical JSON text of a value, or a structured error naming the offending location. Never throws. */
export function canonicalJson(value: unknown): Result<string> {
  try {
    return ok(encodeValue(value, [], new Set<object>()));
  } catch (error: unknown) {
    if (error instanceof CanonicalError) {
      return fail([makeError(error.code, toPointer(error.path), error.message)]);
    }
    if (error instanceof RangeError) {
      return fail([makeError('too_deep', '', 'Value is too deeply nested to hash.')]);
    }
    throw error;
  }
}

/** Lower-case hex SHA-256 of the UTF-8 encoding of `text`. */
export function sha256Hex(text: string): string {
  return bytesToHex(sha256(utf8ToBytes(text)));
}

/** SHA-256 of the canonical JSON of `value`. */
export function digestOf(value: unknown): Result<string> {
  const canonical = canonicalJson(value);
  return canonical.ok ? ok(sha256Hex(canonical.value)) : canonical;
}

/** The exact fields hashed into policy_sha. */
export interface PolicyDigestInput {
  readonly engine_version: Policy['engine_version'];
  readonly grammar_version: Policy['grammar_version'];
  readonly context: Policy['context'];
  readonly default_unmatched: Policy['default_unmatched'];
  readonly rules: Policy['rules'];
  readonly manual_items: Policy['manual_items'];
  readonly dispositions: Policy['dispositions'];
}

/**
 * Picks the hashed policy fields. Approvals (and any other extra property a caller's object carries) are
 * deliberately excluded, so acknowledging an item never changes policy_sha or stales the report (PLAN A14).
 */
export function policyDigestInput(policy: Policy): PolicyDigestInput {
  return {
    engine_version: policy.engine_version,
    grammar_version: policy.grammar_version,
    context: policy.context,
    default_unmatched: policy.default_unmatched,
    rules: policy.rules,
    manual_items: policy.manual_items,
    dispositions: policy.dispositions,
  };
}

export function policySha(policy: Policy): Result<string> {
  return digestOf(policyDigestInput(policy));
}

/** Hash of the fixture list in order (the generator emits a stable, deduplicated order). */
export function fixturesSha(fixtures: readonly Fixture[]): Result<string> {
  return digestOf(fixtures);
}

export function contextSha(context: EvaluationContext): Result<string> {
  return digestOf(context);
}

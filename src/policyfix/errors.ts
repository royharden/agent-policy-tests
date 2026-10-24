// Structured validation errors and the Result union used by every policyfix entry point.
// Framework-free: imports only zod *types* (PLAN A23 import boundary).
import type { ZodIssue } from 'zod';

/** Every error code a policyfix API can return. Stable strings: they appear in exported reports. */
export const ERROR_CODES = [
  'file_too_large', // serialised text exceeds MAX_FILE_BYTES (UTF-8), checked before JSON.parse
  'too_deep', // JSON nesting exceeds MAX_JSON_DEPTH, checked before JSON.parse
  'invalid_json', // JSON.parse rejected the text
  'required', // a required field is missing
  'invalid_type', // wrong JSON type
  'unknown_key', // strict schema: key not allowed
  'too_long', // string (or joined argv) longer than its cap
  'too_short', // string shorter than its minimum (e.g. empty)
  'too_many', // array longer than its cap (rules, fixtures, argv, ...)
  'too_few', // array shorter than its minimum
  'out_of_range', // number outside its bounds (e.g. negative cents)
  'not_integer', // fractional number where an integer is required
  'non_finite', // NaN or +/-Infinity
  'invalid_value', // enum/literal/format mismatch
  'duplicate_id', // two entries share an id that must be unique
  'dangling_reference', // an id refers to a rule/item/answer that does not exist
  'reserved_id', // a user rule tried to use a built-in id such as opaque-construct
  'inconsistent', // two fields disagree (e.g. policy vs context grammar_version)
  'non_canonical', // value cannot be canonicalised for hashing (e.g. NFC key collision, cycle)
  'export_too_large', // generated fixtures/bundle file would exceed MAX_FILE_BYTES (A7)
  'too_many_errors', // error list truncated at MAX_REPORTED_ERRORS
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

/** One structured error: `pointer` is an RFC 6901 JSON pointer into the validated document ('' = root). */
export interface PolicyError {
  readonly code: ErrorCode;
  readonly pointer: string;
  readonly limit?: number;
  readonly message: string;
}

export type Result<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly errors: readonly PolicyError[] };

export type PathSegment = string | number;

export function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

export function fail(errors: readonly PolicyError[]): Result<never> {
  return { ok: false, errors };
}

export function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === 'string' && (ERROR_CODES as readonly string[]).includes(value);
}

/** Builds an error; `limit` is omitted (not set to undefined) when absent so reports stay canonical. */
export function makeError(code: ErrorCode, pointer: string, message: string, limit?: number): PolicyError {
  return limit === undefined ? { code, pointer, message } : { code, pointer, limit, message };
}

function escapePointerSegment(segment: PathSegment): string {
  return String(segment).replaceAll('~', '~0').replaceAll('/', '~1');
}

/** RFC 6901 pointer for a path; the empty path is the root pointer ''. */
export function toPointer(path: readonly PathSegment[]): string {
  let pointer = '';
  for (const segment of path) {
    pointer += `/${escapePointerSegment(segment)}`;
  }
  return pointer;
}

function issueLimit(value: number | bigint): number {
  return Number(value);
}

function errorFromIssue(issue: ZodIssue, basePath: readonly PathSegment[]): PolicyError[] {
  const path: readonly PathSegment[] = [...basePath, ...issue.path];
  const pointer = toPointer(path);
  switch (issue.code) {
    case 'invalid_type': {
      if (issue.received === 'undefined') {
        return [makeError('required', pointer, `Required field (expected ${issue.expected}).`)];
      }
      if (issue.received === 'nan') {
        return [makeError('non_finite', pointer, 'NaN is not allowed.')];
      }
      if (issue.expected === 'integer') {
        return [makeError('not_integer', pointer, `Expected an integer, received ${issue.received}.`)];
      }
      return [makeError('invalid_type', pointer, issue.message)];
    }
    case 'unrecognized_keys':
      return issue.keys.map((key) =>
        makeError('unknown_key', toPointer([...path, key]), `Unknown key "${key}" is not allowed (strict schema).`),
      );
    case 'too_big': {
      const limit = issueLimit(issue.maximum);
      if (issue.type === 'string') return [makeError('too_long', pointer, issue.message, limit)];
      if (issue.type === 'array' || issue.type === 'set') return [makeError('too_many', pointer, issue.message, limit)];
      return [makeError('out_of_range', pointer, issue.message, limit)];
    }
    case 'too_small': {
      const limit = issueLimit(issue.minimum);
      if (issue.type === 'string') return [makeError('too_short', pointer, issue.message, limit)];
      if (issue.type === 'array' || issue.type === 'set') return [makeError('too_few', pointer, issue.message, limit)];
      return [makeError('out_of_range', pointer, issue.message, limit)];
    }
    case 'not_finite':
      return [makeError('non_finite', pointer, 'Number must be finite.')];
    case 'custom': {
      const params: Readonly<Record<string, unknown>> = issue.params ?? {};
      const code = params['code'];
      const limit = params['limit'];
      return [
        makeError(
          isErrorCode(code) ? code : 'invalid_value',
          pointer,
          issue.message,
          typeof limit === 'number' ? limit : undefined,
        ),
      ];
    }
    default:
      return [makeError('invalid_value', pointer, issue.message)];
  }
}

/** Maps Zod issues to structured errors; `basePath` prefixes every pointer. */
export function fromZodIssues(issues: readonly ZodIssue[], basePath: readonly PathSegment[] = []): PolicyError[] {
  const errors: PolicyError[] = [];
  for (const issue of issues) {
    errors.push(...errorFromIssue(issue, basePath));
  }
  return errors;
}

/** Caps an error list so a hostile 2,000-row import cannot produce an unbounded report. */
export function truncateErrors(errors: readonly PolicyError[], max: number): readonly PolicyError[] {
  if (errors.length <= max) return errors;
  return [
    ...errors.slice(0, max),
    makeError('too_many_errors', '', `${errors.length - max} further errors omitted.`, max),
  ];
}

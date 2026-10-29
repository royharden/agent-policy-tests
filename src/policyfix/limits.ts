// Named caps (PLAN A6, A7) and the pre-parse checks that enforce the byte and depth caps before JSON.parse
// ever builds an object. Framework-free.
import { makeError, type PathSegment, type PolicyError, toPointer } from './errors';

// ---- A7 caps -------------------------------------------------------------------------------------------
/** Max characters in one shell command, SQL statement, path, URL, recipient or joined git argv. */
export const MAX_COMMAND_CHARS = 4096;
/** Max user rules in one policy (the built-in opaque-construct fallback is not counted). */
export const MAX_RULES = 200;
/** Max fixtures in one fixtures file; the generator returns a structured error above this (never truncates). */
export const MAX_FIXTURES = 2000;
/**
 * Max UTF-8 bytes of any imported file. The fixture generator and the bundle builder check their serialised output
 * against this same constant and return `export_too_large`, so the app never exports a bundle its runner rejects.
 */
export const MAX_FILE_BYTES = 16 * 1024 * 1024;
/** Max JSON nesting depth (objects + arrays) of any imported document. */
export const MAX_JSON_DEPTH = 32;

// ---- A6 analysis budgets (consumed by the normaliser/guard, M3) ---------------------------------------
/** Max nested shell wrappers (`bash -c`, `cmd /c`, ...) unwrapped per action; deeper → ask (opaque-construct). */
export const MAX_WRAPPER_DEPTH = 3;
/** Max sub-command nodes produced from one action; more → ask (opaque-construct). */
export const MAX_SUBCOMMAND_NODES = 128;
/** Max scanner + glob steps per action; more → ask (opaque-construct). */
export const MAX_ANALYSIS_STEPS = 20_000;

// ---- Schema caps for the remaining fields --------------------------------------------------------------
/** Max argv items in a git action (CONTRACTS C1). */
export const MAX_GIT_ARGS = 128;
/** Max characters of a rule/fixture/manual-item id. */
export const MAX_ID_CHARS = 128;
/** Max characters of a match field name. */
export const MAX_FIELD_NAME_CHARS = 64;
/** Max characters of free prose (rule intent, manual text, reasons). */
export const MAX_TEXT_CHARS = 4096;
/** Max characters of a version string. */
export const MAX_VERSION_CHARS = 32;
/** Max items in one match value list (globs, prefixes, hosts, names). */
export const MAX_LIST_ITEMS = 256;
/** Max predicate nodes in one rule's match conjunction. */
export const MAX_MATCH_NODES = 16;
/** Max manual markers in one policy. */
export const MAX_MANUAL_ITEMS = 200;
/** Max disposition entries (12 questionnaire answers + accepted free-text lines). */
export const MAX_DISPOSITIONS = 256;
/** Max structured errors returned by one validation call. */
export const MAX_REPORTED_ERRORS = 100;

// ---- Pre-parse checks ----------------------------------------------------------------------------------

/**
 * UTF-8 byte length of a JS string, computed from UTF-16 code units (no TextEncoder dependency).
 * Lone surrogates count as 3 bytes, matching TextEncoder's U+FFFD replacement.
 * Stops counting once `stopAbove` is exceeded (returns a value > stopAbove).
 */
export function utf8ByteLength(text: string, stopAbove: number = Number.POSITIVE_INFINITY): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) {
      bytes += 1;
    } else if (unit < 0x800) {
      bytes += 2;
    } else if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
    if (bytes > stopAbove) return bytes;
  }
  return bytes;
}

/** Byte cap check for imported (or about-to-be-exported) text. Returns null when within the cap. */
export function checkFileBytes(
  text: string,
  limit: number = MAX_FILE_BYTES,
  code: 'file_too_large' | 'export_too_large' = 'file_too_large',
): PolicyError | null {
  // Every UTF-16 code unit encodes to at least one byte, so a long string is rejected without scanning.
  if (text.length > limit || utf8ByteLength(text, limit) > limit) {
    return makeError(code, '', `Text exceeds ${limit} UTF-8 bytes.`, limit);
  }
  return null;
}

const QUOTE = 0x22; // "
const BACKSLASH = 0x5c; // \
const OPEN_BRACE = 0x7b; // {
const CLOSE_BRACE = 0x7d; // }
const OPEN_BRACKET = 0x5b; // [
const CLOSE_BRACKET = 0x5d; // ]
const COMMA = 0x2c; // ,

interface DepthFrame {
  readonly kind: 'object' | 'array';
  index: number;
  key: string | null;
  expectKey: boolean;
}

function isHexDigit(ch: string): boolean {
  return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

/** Decodes the body of a JSON string literal (without quotes) for pointer display. Never calls JSON.parse. */
function decodeJsonStringBody(body: string): string {
  let out = '';
  for (let i = 0; i < body.length; i += 1) {
    const ch = body.charAt(i);
    if (ch !== '\\') {
      out += ch;
      continue;
    }
    i += 1;
    const next = body.charAt(i);
    switch (next) {
      case 'n':
        out += '\n';
        break;
      case 't':
        out += '\t';
        break;
      case 'r':
        out += '\r';
        break;
      case 'b':
        out += '\b';
        break;
      case 'f':
        out += '\f';
        break;
      case 'u': {
        const hex = body.slice(i + 1, i + 5);
        if (hex.length === 4 && [...hex].every(isHexDigit)) {
          out += String.fromCharCode(Number.parseInt(hex, 16));
          i += 4;
        } else {
          out += '\\u';
        }
        break;
      }
      default:
        out += next; // \" \\ \/ and anything malformed (JSON.parse will reject the latter later)
    }
  }
  return out;
}

function framesToPath(stack: readonly DepthFrame[]): PathSegment[] {
  return stack.map((frame) => (frame.kind === 'array' ? frame.index : (frame.key ?? '')));
}

/**
 * Nesting-depth check by a single scan of the raw text that respects string literals and escapes.
 * Runs before JSON.parse, so a deeply nested document is rejected without building any object.
 * The pointer names the container that would exceed the cap. Does not validate JSON syntax.
 */
export function checkJsonDepth(text: string, maxDepth: number = MAX_JSON_DEPTH): PolicyError | null {
  const stack: DepthFrame[] = [];
  let inString = false;
  let escaped = false;
  let stringStart = 0;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (unit === BACKSLASH) {
        escaped = true;
      } else if (unit === QUOTE) {
        inString = false;
        const top = stack[stack.length - 1];
        if (top !== undefined && top.kind === 'object' && top.expectKey) {
          top.key = decodeJsonStringBody(text.slice(stringStart + 1, i));
          top.expectKey = false;
        }
      }
      continue;
    }
    switch (unit) {
      case QUOTE:
        inString = true;
        stringStart = i;
        break;
      case OPEN_BRACE:
      case OPEN_BRACKET: {
        if (stack.length + 1 > maxDepth) {
          return makeError(
            'too_deep',
            toPointer(framesToPath(stack)),
            `JSON nesting depth exceeds ${maxDepth} (at character ${i}).`,
            maxDepth,
          );
        }
        stack.push(
          unit === OPEN_BRACE
            ? { kind: 'object', index: 0, key: null, expectKey: true }
            : { kind: 'array', index: 0, key: null, expectKey: false },
        );
        break;
      }
      case CLOSE_BRACE:
      case CLOSE_BRACKET:
        stack.pop();
        break;
      case COMMA: {
        const top = stack[stack.length - 1];
        if (top !== undefined) {
          if (top.kind === 'array') top.index += 1;
          else top.expectKey = true;
        }
        break;
      }
      default:
        break;
    }
  }
  return null;
}

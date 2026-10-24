// Lexical path canonicalisation against the evaluation context (PLAN M3 AC4, A5; Claude §2.5 "Paths"; RUBRIC §3 Q01).
// Never touches the real filesystem: no symlink resolution, no existence checks, no environment reads.
//   - relative paths resolve against context.cwd; `.` / `..` collapse lexically (`..` at a root stays at the root);
//   - `~`, `$HOME`, `${HOME}` (windows also `%USERPROFILE%`) resolve only from context.home, and only when the caller asks
//     (`expandHome`; shell words arrive already expanded by the scanner);
//   - root containment is a segment-boundary test (`/workspace/demo-evil` is outside `/workspace/demo`);
//   - windows: `\` and `/` are equivalent, drive letters are case-folded, UNC (`\\server\share`), device (`\\?\`, `\\.\`)
//     and drive-relative (`C:notes.txt`) paths are opaque → the caller records an `ask`;
//   - segments compare case-insensitively when context.case_insensitive_fs is true.
// Framework-free, no regex.
import type { EvaluationContext, PathFlavor } from '../context';

export interface CanonicalPath {
  readonly flavor: PathFlavor;
  /** Upper-case drive letter on windows; null on posix. */
  readonly drive: string | null;
  readonly segments: readonly string[];
  /** Native display form: `/a/b` or `C:\a\b`. */
  readonly display: string;
  /** `/`-separated canonical form used for matching: `/a/b` or `C:/a/b`. */
  readonly key: string;
  readonly inside_root: boolean;
  /** `''` for the root itself, `a/b` below it, null outside the root. Original spelling (folding happens in match). */
  readonly root_relative: string | null;
  /** Final segment (`''` for a filesystem root). */
  readonly name: string;
}

export type PathResult =
  | { readonly ok: true; readonly path: CanonicalPath }
  | { readonly ok: false; readonly reason: string };

export interface PathOptions {
  /** Resolve `~`, `$HOME`, `${HOME}`, `%USERPROFILE%` from context.home; any other variable makes the path opaque. */
  readonly expandHome: boolean;
}

interface RawParse {
  readonly drive: string | null;
  readonly absolute: boolean;
  readonly segments: readonly string[];
}

type RawResult = { readonly ok: true; readonly value: RawParse } | { readonly ok: false; readonly reason: string };

function isAsciiLetter(ch: string): boolean {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

function isNameStart(ch: string): boolean {
  return isAsciiLetter(ch) || ch === '_';
}

function isNameChar(ch: string): boolean {
  return isNameStart(ch) || (ch >= '0' && ch <= '9');
}

function isSeparator(flavor: PathFlavor, ch: string): boolean {
  return ch === '/' || (flavor === 'windows' && ch === '\\');
}

function splitOn(flavor: PathFlavor, text: string): string[] {
  const parts: string[] = [];
  let current = '';
  for (const ch of text) {
    if (isSeparator(flavor, ch)) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts;
}

/** Collapses `.`, `..` and empty segments onto `base`. */
function collapse(base: readonly string[], parts: readonly string[]): string[] {
  const out = [...base];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      out.pop();
      continue;
    }
    out.push(part);
  }
  return out;
}

/**
 * Expands a leading home reference and rejects any other variable. Returns the rewritten text, or an error reason.
 * Only used for paths that did not come through a shell scanner (fs actions, template parameters).
 */
function expandHomeReferences(text: string, context: EvaluationContext): { ok: true; text: string } | { ok: false; reason: string } {
  const home = context.home;
  let rest = text;
  let prefix = '';
  if (rest === '~' || rest.startsWith('~/') || (context.path_flavor === 'windows' && rest.startsWith('~\\'))) {
    prefix = home;
    rest = rest.slice(1);
  } else if (rest.startsWith('~')) {
    return { ok: false, reason: `"${text}" refers to another user's home directory` };
  } else if (rest.startsWith('${HOME}')) {
    prefix = home;
    rest = rest.slice('${HOME}'.length);
  } else if (rest.startsWith('$HOME') && !isNameChar(rest.charAt('$HOME'.length))) {
    prefix = home;
    rest = rest.slice('$HOME'.length);
  } else if (context.path_flavor === 'windows' && rest.toUpperCase().startsWith('%USERPROFILE%')) {
    prefix = home;
    rest = rest.slice('%USERPROFILE%'.length);
  }
  for (let i = 0; i < rest.length; i += 1) {
    const ch = rest.charAt(i);
    const next = rest.charAt(i + 1);
    if (ch === '$' && (isNameStart(next) || next === '{' || next === '(')) {
      return { ok: false, reason: `"${text}" contains a variable that is not part of the evaluation context` };
    }
    if (context.path_flavor === 'windows' && ch === '%') {
      const close = rest.indexOf('%', i + 1);
      if (close > i + 1) return { ok: false, reason: `"${text}" contains an environment variable reference` };
    }
  }
  return { ok: true, text: prefix + rest };
}

function parsePosix(text: string, cwd: readonly string[]): RawResult {
  if (text.startsWith('/')) {
    return { ok: true, value: { drive: null, absolute: true, segments: collapse([], splitOn('posix', text)) } };
  }
  return { ok: true, value: { drive: null, absolute: false, segments: collapse(cwd, splitOn('posix', text)) } };
}

function parseWindows(text: string, cwdDrive: string | null, cwd: readonly string[]): RawResult {
  const first = text.charAt(0);
  const second = text.charAt(1);
  if (isSeparator('windows', first) && isSeparator('windows', second)) {
    if (text.charAt(2) === '?' || text.charAt(2) === '.') {
      return { ok: false, reason: `"${text}" is a device path (\\\\?\\ or \\\\.\\)` };
    }
    return { ok: false, reason: `"${text}" is a UNC path` };
  }
  if (isAsciiLetter(first) && second === ':') {
    const drive = first.toUpperCase();
    if (!isSeparator('windows', text.charAt(2))) {
      return { ok: false, reason: `"${text}" is drive-relative (no separator after "${first}:")` };
    }
    return { ok: true, value: { drive, absolute: true, segments: collapse([], splitOn('windows', text.slice(3))) } };
  }
  if (isSeparator('windows', first)) {
    return { ok: true, value: { drive: cwdDrive, absolute: true, segments: collapse([], splitOn('windows', text)) } };
  }
  if (text.includes(':')) {
    // `foo:bar` (alternate data stream) or another colon form the lexical analysis does not model.
    return { ok: false, reason: `"${text}" contains ":" outside a drive prefix` };
  }
  return { ok: true, value: { drive: cwdDrive, absolute: false, segments: collapse(cwd, splitOn('windows', text)) } };
}

/** Parses an absolute context path (project_root, cwd, home) — validated absolute by the context schema. */
function parseContextPath(context: EvaluationContext, text: string): RawParse {
  if (context.path_flavor === 'posix') {
    return { drive: null, absolute: true, segments: collapse([], splitOn('posix', text)) };
  }
  const drive = text.charAt(0).toUpperCase();
  return { drive, absolute: true, segments: collapse([], splitOn('windows', text.slice(3))) };
}

function fold(context: EvaluationContext, value: string): string {
  return context.case_insensitive_fs ? value.toLowerCase() : value;
}

function segmentsEqual(context: EvaluationContext, a: string, b: string): boolean {
  return fold(context, a) === fold(context, b);
}

function displayOf(flavor: PathFlavor, drive: string | null, segments: readonly string[]): string {
  if (flavor === 'posix') return `/${segments.join('/')}`;
  return `${drive ?? 'C'}:\\${segments.join('\\')}`;
}

function keyOf(flavor: PathFlavor, drive: string | null, segments: readonly string[]): string {
  if (flavor === 'posix') return `/${segments.join('/')}`;
  return `${drive ?? 'C'}:/${segments.join('/')}`;
}

/** Builds the canonical record for already-collapsed segments. */
export function buildCanonical(
  context: EvaluationContext,
  drive: string | null,
  segments: readonly string[],
): CanonicalPath {
  const root = parseContextPath(context, context.project_root);
  let inside = root.drive === drive && segments.length >= root.segments.length;
  if (inside) {
    for (let i = 0; i < root.segments.length; i += 1) {
      const a = root.segments[i];
      const b = segments[i];
      if (a === undefined || b === undefined || !segmentsEqual(context, a, b)) {
        inside = false;
        break;
      }
    }
  }
  const flavor = context.path_flavor;
  return {
    flavor,
    drive,
    segments,
    display: displayOf(flavor, drive, segments),
    key: keyOf(flavor, drive, segments),
    inside_root: inside,
    root_relative: inside ? segments.slice(root.segments.length).join('/') : null,
    name: segments.length === 0 ? '' : (segments[segments.length - 1] ?? ''),
  };
}

/**
 * Canonicalises `raw` against the context. Opaque forms (UNC, device, drive-relative, other users' homes,
 * non-context variables, NUL) return `{ok:false, reason}`; the caller records an `opaque-path` finding.
 */
export function canonicalisePath(raw: string, context: EvaluationContext, options: PathOptions): PathResult {
  if (raw.length === 0) return { ok: false, reason: 'empty path' };
  if (raw.includes('\u0000')) return { ok: false, reason: 'path contains a NUL character' };
  let text = raw;
  if (options.expandHome) {
    const expanded = expandHomeReferences(raw, context);
    if (!expanded.ok) return { ok: false, reason: expanded.reason };
    text = expanded.text;
  }
  const cwd = parseContextPath(context, context.cwd);
  const parsed = context.path_flavor === 'posix' ? parsePosix(text, cwd.segments) : parseWindows(text, cwd.drive, cwd.segments);
  if (!parsed.ok) return parsed;
  return { ok: true, path: buildCanonical(context, parsed.value.drive, parsed.value.segments) };
}

/** Joins segments onto a context path in its native flavour (used by templates to build example paths). */
export function joinContextPath(context: EvaluationContext, base: string, ...parts: readonly string[]): string {
  const sep = context.path_flavor === 'windows' ? '\\' : '/';
  let out = base;
  for (const part of parts) {
    if (part === '') continue;
    out = out.endsWith(sep) ? `${out}${part}` : `${out}${sep}${part}`;
  }
  return out;
}

/** The project root's sibling `<root><suffix>` (e.g. `/workspace/demo-evil`), outside the root by the segment test. */
export function siblingOfRoot(context: EvaluationContext, suffix: string): string {
  const root = context.project_root;
  const trimmed = root.endsWith('/') || root.endsWith('\\') ? root.slice(0, -1) : root;
  return `${trimmed}${suffix}`;
}

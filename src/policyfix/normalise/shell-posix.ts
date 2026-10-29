// posix shell normaliser (PLAN M3 AC3, A6; Claude §2.5 "posix scanner"; RUBRIC §4–§5; docs/GRAMMAR.md).
// Two stages, both hand-written and regex-free:
//   1. scanPosix — a character scanner for the supported subset: words with '…', "…", \-escapes, $VAR/${VAR}, $(…),
//      `…`, $((…)), ~; separators ; && || | |& & newline; subshells ( … ); comments; redirections. Every simple command
//      found anywhere (chains, pipes, substitutions, subshells) is returned flat — control flow is ignored, so
//      `true || rm -rf /` still deletes `/` for the policy.
//   2. analyseWords — wrapper unwrapping (sudo, doas, env, command, nohup, exec, time, nice, timeout, stdbuf, npx;
//      `bash|sh|zsh -c '<literal>'` up to MAX_WRAPPER_DEPTH), opaque constructs (eval, source, $VAR in command
//      position, inline interpreter code, scripts from stdin, xargs, find -exec), and per-command semantics that emit fs /
//      http / git / sql sub-actions (rm, cp, mv, tee, cat, grep, curl, wget, git, psql, …).
// Budgets (PLAN A6): one step budget shared with the glob matcher, MAX_SUBCOMMAND_NODES simple commands, wrapper depth.
// Over budget or unsupported syntax → an opaque finding (ask); sub-actions found before the limit are kept, so a
// visible deny still wins.
// Framework-free.
import { MAX_SUBCOMMAND_NODES, MAX_WRAPPER_DEPTH } from '../limits';
import { addOpaque, deleteMode, emitFsWord, emitGit, emitSql, emitUrlWord, pushSub } from './emit';
import { type ArgSpec, hasAnyFlag, type ParsedArgs, parsePosixArgs, valuesOf } from './flags';
import { AnalysisLimitError, type OpaqueFinding, opaqueFinding, type StepBudget, spendOrThrow } from './opaque';
import { joinContextPath } from './path';
import { emitRedirect, type RedirectOp, type RedirectSpec } from './redirect';
import type { Accumulator, ArgWord } from './types';
import { urlBasename } from './url';

// =========================================================================================================
// Stage 1: scanner
// =========================================================================================================

export interface ShellWord extends ArgWord {
  /** Source text of the word, quotes included. */
  readonly raw: string;
  /** `NAME=value` with an unquoted, literal NAME. */
  readonly assignment: boolean;
  /** Any part was quoted or escaped. */
  readonly quoted: boolean;
}

export interface ShellRedirect extends RedirectSpec {
  readonly fd: number | null;
  readonly target: ShellWord | null;
}

export interface SimpleCommand {
  readonly words: readonly ShellWord[];
  readonly redirects: readonly ShellRedirect[];
}

export interface ScanResult {
  readonly commands: readonly SimpleCommand[];
  readonly opaque: readonly OpaqueFinding[];
}

/** Maximum nesting of $(…), `…`, ( … ) inside one scan (independent of the wrapper depth). */
export const MAX_SCAN_NESTING = 16;

class ShellSyntaxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ShellSyntaxError';
  }
}

interface NodeCounter {
  nodes: number;
}

interface Shared {
  readonly budget: StepBudget;
  readonly home: string;
  readonly commands: SimpleCommand[];
  readonly opaque: OpaqueFinding[];
  readonly counter: NodeCounter;
  nest: number;
}

interface ScanState {
  readonly src: string;
  i: number;
  readonly shared: Shared;
}

interface WordBuilder {
  text: string;
  dynamic: boolean;
  wildcard: boolean;
  quoted: boolean;
  assignment: boolean;
  /** Only unquoted literal characters so far (assignment detection). */
  plain: boolean;
}

function isBlank(ch: string): boolean {
  return ch === ' ' || ch === '\t' || ch === '\r';
}

function isWordTerminator(ch: string): boolean {
  return (
    ch === '' ||
    isBlank(ch) ||
    ch === '\n' ||
    ch === ';' ||
    ch === '&' ||
    ch === '|' ||
    ch === '<' ||
    ch === '>' ||
    ch === '(' ||
    ch === ')'
  );
}

function isNameStart(ch: string): boolean {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_';
}

function isNameChar(ch: string): boolean {
  return isNameStart(ch) || (ch >= '0' && ch <= '9');
}

function isName(text: string): boolean {
  if (text.length === 0 || !isNameStart(text.charAt(0))) return false;
  for (const ch of text) if (!isNameChar(ch)) return false;
  return true;
}

function isDigits(text: string): boolean {
  return text.length > 0 && [...text].every((ch) => ch >= '0' && ch <= '9');
}

const SPECIAL_PARAMETERS = '@*#?-$!';

function peek(st: ScanState, offset = 0): string {
  return st.src.charAt(st.i + offset);
}

function step(st: ScanState, count = 1): void {
  spendOrThrow(st.shared.budget, count);
}

function enterNest(st: ScanState): void {
  st.shared.nest += 1;
  if (st.shared.nest > MAX_SCAN_NESTING) {
    throw new ShellSyntaxError(`substitution / subshell nesting deeper than ${MAX_SCAN_NESTING}`);
  }
}

function leaveNest(st: ScanState): void {
  st.shared.nest -= 1;
}

function skipBlanks(st: ScanState): void {
  for (;;) {
    const c = peek(st);
    if (isBlank(c)) {
      step(st);
      st.i += 1;
    } else if (c === '\\' && peek(st, 1) === '\n') {
      step(st);
      st.i += 2;
    } else {
      return;
    }
  }
}

function skipComment(st: ScanState): void {
  const end = st.src.indexOf('\n', st.i);
  const stop = end < 0 ? st.src.length : end;
  step(st, Math.max(1, stop - st.i));
  st.i = stop;
}

function scanNestedSource(st: ScanState, source: string): void {
  const inner: ScanState = { src: source, i: 0, shared: st.shared };
  scanList(inner, null);
}

function scanBacktick(st: ScanState, b: WordBuilder): void {
  const start = st.i;
  let j = st.i + 1;
  let content = '';
  for (;;) {
    const c = st.src.charAt(j);
    if (c === '') throw new ShellSyntaxError('unterminated backtick substitution');
    step(st);
    if (c === '\\') {
      const n = st.src.charAt(j + 1);
      if (n === '`' || n === '\\' || n === '$') {
        content += n;
        j += 2;
        continue;
      }
    }
    if (c === '`') break;
    content += c;
    j += 1;
  }
  st.i = j + 1;
  b.dynamic = true;
  b.plain = false;
  b.text += st.src.slice(start, st.i);
  enterNest(st);
  scanNestedSource(st, content);
  leaveNest(st);
}

function scanDollar(st: ScanState, b: WordBuilder, inDouble: boolean): void {
  const start = st.i;
  const n = peek(st, 1);
  b.plain = false;
  if (n === '(') {
    if (peek(st, 2) === '(') {
      // $(( arithmetic )): value unknown; a command substitution inside it is opaque.
      let depth = 2;
      let j = st.i + 3;
      while (j < st.src.length && depth > 0) {
        step(st);
        const c = st.src.charAt(j);
        if (c === '(') depth += 1;
        else if (c === ')') depth -= 1;
        j += 1;
      }
      if (depth > 0) throw new ShellSyntaxError('unterminated $(( arithmetic expansion');
      const content = st.src.slice(st.i + 3, j - 2);
      if (content.includes('$(') || content.includes('`')) {
        st.shared.opaque.push(opaqueFinding('shell-syntax', 'command substitution inside an arithmetic expansion'));
      }
      b.dynamic = true;
      b.text += st.src.slice(start, j);
      st.i = j;
      return;
    }
    st.i += 2;
    enterNest(st);
    scanList(st, ')');
    leaveNest(st);
    b.dynamic = true;
    b.text += st.src.slice(start, st.i);
    return;
  }
  if (n === '{') {
    let depth = 1;
    let j = st.i + 2;
    while (j < st.src.length && depth > 0) {
      step(st);
      const c = st.src.charAt(j);
      if (c === '{') depth += 1;
      else if (c === '}') depth -= 1;
      j += 1;
    }
    if (depth > 0) throw new ShellSyntaxError('unterminated ${ parameter expansion');
    const inner = st.src.slice(st.i + 2, j - 1);
    if (inner === 'HOME') {
      b.text += st.shared.home;
    } else {
      b.dynamic = true;
      b.text += st.src.slice(start, j);
      if (inner.includes('$(') || inner.includes('`')) {
        st.shared.opaque.push(opaqueFinding('dynamic-command', 'command substitution inside a ${…} expansion'));
      }
    }
    st.i = j;
    return;
  }
  if (isNameStart(n)) {
    let j = st.i + 1;
    while (j < st.src.length && isNameChar(st.src.charAt(j))) j += 1;
    step(st, j - st.i);
    const name = st.src.slice(st.i + 1, j);
    if (name === 'HOME') {
      b.text += st.shared.home;
    } else {
      b.dynamic = true;
      b.text += `$${name}`;
    }
    st.i = j;
    return;
  }
  if (n !== '' && ((n >= '0' && n <= '9') || SPECIAL_PARAMETERS.includes(n))) {
    b.dynamic = true;
    b.text += `$${n}`;
    st.i += 2;
    return;
  }
  if (!inDouble && n === "'") {
    // $'…' ANSI-C quoting: escapes can spell anything, so the value is treated as unknown.
    let j = st.i + 2;
    for (;;) {
      const c = st.src.charAt(j);
      if (c === '') throw new ShellSyntaxError("unterminated $'…' string");
      step(st);
      if (c === '\\') {
        j += 2;
        continue;
      }
      if (c === "'") break;
      j += 1;
    }
    b.dynamic = true;
    b.quoted = true;
    b.text += st.src.slice(start, j + 1);
    st.i = j + 1;
    return;
  }
  if (!inDouble && n === '"') {
    st.i += 1; // $"…" locale string: same as "…"
    scanDoubleQuoted(st, b);
    return;
  }
  b.text += '$';
  st.i += 1;
}

function scanDoubleQuoted(st: ScanState, b: WordBuilder): void {
  st.i += 1;
  b.quoted = true;
  b.plain = false;
  for (;;) {
    const c = peek(st);
    if (c === '') throw new ShellSyntaxError('unterminated double quote');
    step(st);
    if (c === '"') {
      st.i += 1;
      return;
    }
    if (c === '\\') {
      const n = peek(st, 1);
      if (n === '$' || n === '`' || n === '"' || n === '\\') {
        b.text += n;
        st.i += 2;
      } else if (n === '\n') {
        st.i += 2;
      } else {
        b.text += '\\';
        st.i += 1;
      }
      continue;
    }
    if (c === '$') {
      scanDollar(st, b, true);
      continue;
    }
    if (c === '`') {
      scanBacktick(st, b);
      continue;
    }
    b.text += c;
    st.i += 1;
  }
}

/** Unquoted `{…}` containing `,` or `..` before the closing brace (brace expansion). */
function braceExpansionAhead(st: ScanState): boolean {
  let sawSeparator = false;
  for (let j = st.i + 1; j < st.src.length; j += 1) {
    const c = st.src.charAt(j);
    if (isWordTerminator(c) || c === '"' || c === "'") return false;
    if (c === ',' || (c === '.' && st.src.charAt(j + 1) === '.')) sawSeparator = true;
    if (c === '}') return sawSeparator;
  }
  return false;
}

function scanWord(st: ScanState): ShellWord {
  const start = st.i;
  const b: WordBuilder = { text: '', dynamic: false, wildcard: false, quoted: false, assignment: false, plain: true };
  while (st.i < st.src.length) {
    const c = peek(st);
    if (isWordTerminator(c)) break;
    step(st);
    if (c === '\\') {
      const n = peek(st, 1);
      if (n === '\n') {
        st.i += 2;
        continue;
      }
      if (n === '') {
        b.text += '\\';
        st.i += 1;
        continue;
      }
      b.text += n;
      b.quoted = true;
      b.plain = false;
      st.i += 2;
      continue;
    }
    if (c === "'") {
      const end = st.src.indexOf("'", st.i + 1);
      if (end < 0) throw new ShellSyntaxError('unterminated single quote');
      step(st, end - st.i);
      b.text += st.src.slice(st.i + 1, end);
      b.quoted = true;
      b.plain = false;
      st.i = end + 1;
      continue;
    }
    if (c === '"') {
      scanDoubleQuoted(st, b);
      continue;
    }
    if (c === '$') {
      scanDollar(st, b, false);
      continue;
    }
    if (c === '`') {
      scanBacktick(st, b);
      continue;
    }
    if (c === '~' && st.i === start) {
      const n = peek(st, 1);
      if (n === '/' || isWordTerminator(n)) {
        b.text += st.shared.home;
        b.plain = false;
        st.i += 1;
        continue;
      }
      // ~user, ~+, ~-: not resolvable from the context.
      b.dynamic = true;
    }
    if (c === '=' && b.plain && !b.assignment && isName(b.text)) {
      b.assignment = true;
      b.plain = false;
      b.text += '=';
      st.i += 1;
      continue;
    }
    if (c === '*' || c === '?' || c === '[') b.wildcard = true;
    if (c === '{' && braceExpansionAhead(st)) b.wildcard = true;
    b.text += c;
    st.i += 1;
  }
  return {
    text: b.text,
    dynamic: b.dynamic,
    wildcard: b.wildcard,
    quoted: b.quoted,
    assignment: b.assignment,
    raw: st.src.slice(start, st.i),
  };
}

/** Redirection operators, longest first. `<<` (here-document) is handled before this table. */
const REDIRECT_OPERATORS: readonly (readonly [string, RedirectOp])[] = [
  ['&>>', 'append'],
  ['&>', 'write'],
  ['<<<', 'herestring'],
  ['<>', 'readwrite'],
  ['<&', 'read'],
  ['<', 'read'],
  ['>>', 'append'],
  ['>|', 'write'],
  ['>&', 'write'],
  ['>', 'write'],
];

function scanRedirect(st: ScanState, fd: number | null): ShellRedirect {
  const s = st.src;
  const at = st.i;
  if (s.startsWith('<<', at) && !s.startsWith('<<<', at)) {
    throw new ShellSyntaxError('here-documents are not analysed (the body is opaque)');
  }
  const entry = REDIRECT_OPERATORS.find(([candidate]) => s.startsWith(candidate, at));
  const operator = entry?.[0] ?? '>';
  let op: RedirectOp = entry?.[1] ?? 'write';
  step(st, operator.length);
  st.i += operator.length;
  skipBlanks(st);
  if (isWordTerminator(peek(st))) throw new ShellSyntaxError(`redirect "${operator}" has no target`);
  const target = scanWord(st);
  if ((operator === '>&' || operator === '<&') && (isDigits(target.text) || target.text === '-')) op = 'dup';
  const shown = fd === null ? operator : `${fd}${operator}`;
  return { op, operator: shown, fd, target };
}

function scanSimpleCommand(st: ScanState): void {
  const words: ShellWord[] = [];
  const redirects: ShellRedirect[] = [];
  for (;;) {
    skipBlanks(st);
    if (st.i >= st.src.length) break;
    const c = peek(st);
    const n = peek(st, 1);
    if (c === '\n' || c === ';' || c === '|' || c === ')') break;
    if (c === '&' && n !== '>') break;
    if (c === '(') {
      if (words.length > 0) throw new ShellSyntaxError('"(" after a word (function definition) is not supported');
      break;
    }
    if (c === '#') {
      skipComment(st);
      break;
    }
    if (c === '<' || c === '>' || (c === '&' && n === '>')) {
      redirects.push(scanRedirect(st, null));
      continue;
    }
    const word = scanWord(st);
    const after = peek(st);
    if (!word.quoted && isDigits(word.raw) && (after === '<' || after === '>')) {
      redirects.push(scanRedirect(st, Number(word.raw)));
      continue;
    }
    words.push(word);
  }
  if (words.length === 0 && redirects.length === 0) return;
  st.shared.counter.nodes += 1;
  if (st.shared.counter.nodes > MAX_SUBCOMMAND_NODES) {
    throw new AnalysisLimitError('node-budget', `more than ${MAX_SUBCOMMAND_NODES} sub-command nodes`);
  }
  st.shared.commands.push({ words, redirects });
}

function scanList(st: ScanState, closer: ')' | null): void {
  for (;;) {
    skipBlanks(st);
    if (st.i >= st.src.length) {
      if (closer !== null) throw new ShellSyntaxError(`missing "${closer}"`);
      return;
    }
    const c = peek(st);
    const n = peek(st, 1);
    if (c === ')') {
      if (closer === ')') {
        st.i += 1;
        return;
      }
      throw new ShellSyntaxError('unbalanced ")"');
    }
    if (c === '#') {
      skipComment(st);
      continue;
    }
    if (c === '\n' || c === ';' || c === '|' || (c === '&' && n !== '>')) {
      step(st);
      st.i += 1;
      continue;
    }
    if (c === '(') {
      step(st);
      st.i += 1;
      enterNest(st);
      scanList(st, ')');
      leaveNest(st);
      continue;
    }
    const before = st.i;
    scanSimpleCommand(st);
    if (st.i === before) throw new ShellSyntaxError(`unexpected character "${c}"`);
  }
}

/**
 * Scans a posix command string into flat simple commands. `home` resolves `~`, `$HOME` and `${HOME}`. Syntax errors
 * and budget hits become opaque findings; commands scanned before the problem are kept.
 */
export function scanPosix(command: string, home: string, budget: StepBudget, counter: NodeCounter): ScanResult {
  const shared: Shared = { budget, home, commands: [], opaque: [], counter, nest: 0 };
  const st: ScanState = { src: command, i: 0, shared };
  try {
    scanList(st, null);
  } catch (error: unknown) {
    if (error instanceof ShellSyntaxError) shared.opaque.push(opaqueFinding('shell-syntax', error.message));
    else if (error instanceof AnalysisLimitError) shared.opaque.push(opaqueFinding(error.code, error.message));
    else throw error;
  }
  return { commands: shared.commands, opaque: shared.opaque };
}

// =========================================================================================================
// Stage 2: command semantics
// =========================================================================================================

/** Reserved words that do not change what the following command does. */
const TRANSPARENT_KEYWORDS: readonly string[] = ['if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'while', 'until', '!', '{', '}'];
/** Constructs that bind variables or define code: their bodies cannot be attributed lexically. */
const OPAQUE_KEYWORDS: readonly string[] = ['for', 'case', 'esac', 'select', 'function', 'coproc'];
const EVAL_COMMANDS: readonly string[] = ['eval', 'source', '.'];

interface WrapperSpec {
  readonly spec: ArgSpec;
  /** Operands to skip after the options before the wrapped command (timeout DURATION). */
  readonly skipOperands?: number;
  /** Flags that make the wrapper itself opaque (env -S, npx -c). */
  readonly opaqueFlags?: readonly string[];
  /** Flags that mean "do not run anything" (command -v). */
  readonly lookupFlags?: readonly string[];
  /** Also skip `NAME=value` operands (env). */
  readonly skipAssignments?: boolean;
}

const WRAPPERS: Readonly<Record<string, WrapperSpec>> = {
  sudo: {
    spec: {
      valueFlags: ['-u', '-g', '-p', '-C', '-D', '-h', '-r', '-t', '-T', '-U', '--user', '--group', '--prompt', '--close-from', '--chdir', '--host', '--role', '--type', '--command-timeout', '--other-user'],
      stopAtFirstOperand: true,
    },
  },
  doas: { spec: { valueFlags: ['-u', '-C'], stopAtFirstOperand: true } },
  env: {
    spec: { valueFlags: ['-u', '--unset', '-C', '--chdir', '-S', '--split-string'], stopAtFirstOperand: true },
    opaqueFlags: ['-S', '--split-string'],
    skipAssignments: true,
  },
  command: { spec: { stopAtFirstOperand: true }, lookupFlags: ['-v', '-V'] },
  nohup: { spec: { stopAtFirstOperand: true } },
  exec: { spec: { valueFlags: ['-a'], stopAtFirstOperand: true } },
  time: { spec: { stopAtFirstOperand: true } },
  nice: { spec: { valueFlags: ['-n', '--adjustment'], stopAtFirstOperand: true } },
  timeout: { spec: { valueFlags: ['-s', '--signal', '-k', '--kill-after'], stopAtFirstOperand: true }, skipOperands: 1 },
  stdbuf: { spec: { valueFlags: ['-i', '-o', '-e', '--input', '--output', '--error'], stopAtFirstOperand: true } },
  npx: {
    spec: { valueFlags: ['-p', '--package', '-c', '--call', '--cache', '--userconfig'], stopAtFirstOperand: true },
    opaqueFlags: ['-c', '--call'],
  },
};

/** Elevation wrappers (Q04): emitted as their own command sub-action, then unwrapped. */
export const ELEVATION_COMMANDS: readonly string[] = ['sudo', 'doas'];

const RM_LONG: readonly string[] = [
  '--recursive', '--force', '--dir', '--interactive', '--one-file-system', '--no-preserve-root', '--preserve-root',
  '--verbose', '--help', '--version',
];
/** Canonical command flag names shared by free-text command predicates and their evaluated invocations. */
const RM_COMMAND_FLAG_ALIASES: Readonly<Record<string, string>> = { '-R': '-r', '--recursive': '-r', '--force': '-f' };

/** Commands whose arguments decide a publish/deploy rule (Q10): a variable operand is opaque. */
const PUBLISH_COMMAND_SPECS: Readonly<Record<string, ArgSpec>> = {
  npm: { valueFlags: ['-w', '--workspace', '--prefix', '--registry', '--userconfig', '--cache', '--loglevel', '--tag', '--access', '--otp', '-C'] },
  vercel: {
    valueFlags: ['--token', '-t', '--scope', '-S', '--cwd', '--local-config', '-A', '--global-config', '-Q', '--env', '-e', '--build-env', '-b', '--meta', '-m', '--regions', '--archive', '--target'],
  },
  terraform: {
    singleDashIsLong: true,
    valueFlags: ['-chdir', '-var', '-var-file', '-target', '-out', '-state', '-state-out', '-backup', '-lock-timeout', '-parallelism', '-replace'],
  },
  gh: { valueFlags: ['-R', '--repo', '--hostname'] },
};

interface ReadSpec {
  readonly spec: ArgSpec;
  /** The first operand is a pattern/script, unless one of `patternFlags` supplied it. */
  readonly firstIsPattern?: boolean;
  readonly patternFlags?: readonly string[];
  /** Flags whose value is a file that is read / written. */
  readonly readValueFlags?: readonly string[];
  readonly writeValueFlags?: readonly string[];
  /** Flags that make the operands written as well (sed -i). */
  readonly inPlaceFlags?: readonly string[];
  /** Operands containing `=` are variable assignments, not files (awk). */
  readonly skipAssignmentOperands?: boolean;
}

const PLAIN_READ: ReadSpec = { spec: {} };

const READ_COMMANDS: Readonly<Record<string, ReadSpec>> = {
  cat: PLAIN_READ, tac: PLAIN_READ, less: PLAIN_READ, more: PLAIN_READ, bat: PLAIN_READ, view: PLAIN_READ,
  strings: PLAIN_READ, cmp: PLAIN_READ, paste: PLAIN_READ, md5sum: PLAIN_READ, sha1sum: PLAIN_READ,
  sha256sum: PLAIN_READ, sha512sum: PLAIN_READ, vi: PLAIN_READ, vim: PLAIN_READ, nvim: PLAIN_READ,
  nano: PLAIN_READ, emacs: PLAIN_READ, hexdump: PLAIN_READ, wc: PLAIN_READ,
  head: { spec: { valueFlags: ['-n', '-c', '--lines', '--bytes'] } },
  tail: { spec: { valueFlags: ['-n', '-c', '--lines', '--bytes', '--pid', '-s', '--sleep-interval'] } },
  nl: { spec: { valueFlags: ['-b', '-n', '-s', '-w', '-v', '-i', '-d', '-f', '-h'] } },
  od: { spec: { valueFlags: ['-A', '-t', '-N', '-j', '-w'] } },
  xxd: { spec: { valueFlags: ['-l', '-s', '-c', '-g', '-o'] } },
  base64: { spec: { valueFlags: ['-w', '--wrap'] } },
  cut: { spec: { valueFlags: ['-d', '-f', '-c', '-b', '--delimiter', '--fields', '--characters', '--bytes'] } },
  sort: { spec: { valueFlags: ['-o', '--output', '-k', '--key', '-t', '--field-separator', '-S', '--buffer-size', '-T'] }, writeValueFlags: ['-o', '--output'] },
  uniq: { spec: { valueFlags: ['-f', '-s', '-w'] } },
  diff: { spec: { valueFlags: ['-U', '-C', '--label', '-I'] } },
  grep: {
    spec: { valueFlags: ['-e', '-f', '-m', '-A', '-B', '-C', '-d', '-D', '--regexp', '--file', '--max-count', '--context', '--after-context', '--before-context'] },
    firstIsPattern: true,
    patternFlags: ['-e', '-f', '--regexp', '--file'],
    readValueFlags: ['-f', '--file'],
  },
  rg: {
    spec: { valueFlags: ['-e', '-f', '-g', '-t', '-T', '-m', '-A', '-B', '-C', '-j', '-M', '--regexp', '--file', '--glob', '--type', '--max-count'] },
    firstIsPattern: true,
    patternFlags: ['-e', '-f', '--regexp', '--file'],
    readValueFlags: ['-f', '--file'],
  },
  sed: {
    spec: { valueFlags: ['-e', '-f', '-l', '--expression', '--file', '--line-length'], attachedValueFlags: ['-i'] },
    firstIsPattern: true,
    patternFlags: ['-e', '-f', '--expression', '--file'],
    readValueFlags: ['-f', '--file'],
    inPlaceFlags: ['-i', '--in-place'],
  },
  awk: {
    spec: { valueFlags: ['-f', '-v', '-F', '--file', '--assign', '--field-separator'] },
    firstIsPattern: true,
    patternFlags: ['-f', '--file'],
    readValueFlags: ['-f', '--file'],
    skipAssignmentOperands: true,
  },
};
// Aliases sharing a spec.
const READ_ALIASES: Readonly<Record<string, string>> = { egrep: 'grep', fgrep: 'grep', zgrep: 'grep', gawk: 'awk', mawk: 'awk', nawk: 'awk' };

const DELETE_COMMANDS: readonly string[] = ['rm', 'unlink', 'rmdir'];
const COPY_COMMANDS: readonly string[] = ['cp', 'mv', 'ln', 'install'];
const COPY_SPEC: ArgSpec = {
  valueFlags: ['-t', '--target-directory', '-S', '--suffix', '-m', '--mode', '-o', '--owner', '-g', '--group'],
};
const WRITE_COMMANDS: Readonly<Record<string, ArgSpec>> = {
  touch: { valueFlags: ['-d', '-t', '-r', '--date', '--reference'] },
  mkdir: { valueFlags: ['-m', '--mode'] },
  tee: {},
  truncate: { valueFlags: ['-s', '--size', '-r', '--reference'] },
};
const LIST_COMMANDS: readonly string[] = ['ls', 'dir', 'tree'];
const FIND_ACTIONS: readonly string[] = ['-delete', '-exec', '-execdir', '-ok', '-okdir', '-fprint', '-fprint0', '-fprintf', '-fls'];

const SHELLS: readonly string[] = ['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'mksh', 'fish'];
const INFO_FLAGS: readonly string[] = ['--version', '-V', '--help', '-h', '-v'];

interface InterpreterSpec {
  readonly codeFlags: readonly string[];
  /** Characters that, inside a short cluster, mean "code follows" (perl -ne, -pe). */
  readonly clusterCodeChars: string;
  readonly valueFlags: readonly string[];
  /** Flags that run a module/library instead of a script file (python -m): not stdin. */
  readonly moduleFlags?: readonly string[];
  /** First operands that evaluate code (deno eval). */
  readonly codeSubcommands?: readonly string[];
}

const PYTHON: InterpreterSpec = { codeFlags: ['-c'], clusterCodeChars: 'c', valueFlags: ['-m', '-W', '-X', '-Q'], moduleFlags: ['-m'] };
const NODE: InterpreterSpec = {
  codeFlags: ['-e', '--eval', '-p', '--print'],
  clusterCodeChars: 'ep',
  valueFlags: ['-r', '--require', '--import', '--loader', '--input-type', '--env-file', '--conditions', '-C'],
};
const INTERPRETERS: Readonly<Record<string, InterpreterSpec>> = {
  python: PYTHON, python2: PYTHON, python3: PYTHON,
  node: NODE, nodejs: NODE, bun: NODE,
  perl: { codeFlags: ['-e', '-E'], clusterCodeChars: 'eE', valueFlags: ['-I', '-M', '-m'] },
  ruby: { codeFlags: ['-e'], clusterCodeChars: 'e', valueFlags: ['-I', '-r'] },
  php: { codeFlags: ['-r', '--run'], clusterCodeChars: 'r', valueFlags: ['-c', '-d', '-f', '-z'] },
  deno: { codeFlags: ['--eval'], clusterCodeChars: '', valueFlags: [], codeSubcommands: ['eval', 'repl'] },
};

/** Basename of a command word with a trailing `.exe` removed (posix names stay case-sensitive). */
export function posixCommandName(text: string): string {
  const slash = text.lastIndexOf('/');
  const base = slash >= 0 ? text.slice(slash + 1) : text;
  return base.toLowerCase().endsWith('.exe') ? base.slice(0, -4) : base;
}

function texts(words: readonly ArgWord[]): string[] {
  return words.map((word) => word.text);
}

/** Parses arguments and emits the command sub-action. */
function emitCommand(acc: Accumulator, name: string, args: readonly ShellWord[], spec: ArgSpec): ParsedArgs<ShellWord> {
  const parsed = parsePosixArgs(args, spec);
  pushSub(acc, {
    kind: 'command',
    dialect: 'posix',
    name,
    words: [name, ...texts(parsed.operands)],
    flags: name === 'rm' ? [...new Set(parsed.flags.map((flag) => RM_COMMAND_FLAG_ALIASES[flag] ?? flag))] : parsed.flags,
    argv: texts(args),
  });
  return parsed;
}

function anyDynamic(words: readonly ArgWord[]): boolean {
  return words.some((word) => word.dynamic);
}

function handleDelete(acc: Accumulator, name: string, args: readonly ShellWord[]): void {
  const parsed = emitCommand(acc, name, args, name === 'rm' ? { longFlags: RM_LONG } : {});
  if (anyDynamic(args)) {
    addOpaque(acc, 'dynamic-operand', `${name} has an argument with a variable or substitution`);
    return;
  }
  const recursive = name === 'rm' && hasAnyFlag(parsed, ['-r', '-R', '--recursive']);
  const force = name === 'rm' && hasAnyFlag(parsed, ['-f', '--force']);
  const mode = deleteMode(recursive, force);
  for (const operand of parsed.operands) emitFsWord(acc, 'delete', operand, mode, `${name} operand`);
}

function handleCopy(acc: Accumulator, name: string, args: readonly ShellWord[]): void {
  const parsed = emitCommand(acc, name, args, COPY_SPEC);
  if (anyDynamic(args)) {
    addOpaque(acc, 'dynamic-operand', `${name} has an argument with a variable or substitution`);
    return;
  }
  const targetDir = valuesOf(parsed, ['-t', '--target-directory'])[0];
  let destination: ArgWord | undefined;
  let sources: readonly ArgWord[];
  if (targetDir !== undefined) {
    destination = targetDir;
    sources = parsed.operands;
  } else if (parsed.operands.length >= 2) {
    destination = parsed.operands[parsed.operands.length - 1];
    sources = parsed.operands.slice(0, -1);
  } else {
    return;
  }
  if (name !== 'ln') for (const source of sources) emitFsWord(acc, 'read', source, 'plain', `${name} source`);
  if (destination !== undefined) emitFsWord(acc, 'write', destination, 'plain', `${name} destination`);
}

function handleWrite(acc: Accumulator, name: string, args: readonly ShellWord[], spec: ArgSpec): void {
  const parsed = emitCommand(acc, name, args, spec);
  if (anyDynamic(args)) {
    addOpaque(acc, 'dynamic-operand', `${name} has an argument with a variable or substitution`);
    return;
  }
  for (const ref of valuesOf(parsed, ['-r', '--reference'])) emitFsWord(acc, 'read', ref, 'plain', `${name} reference`);
  for (const operand of parsed.operands) emitFsWord(acc, 'write', operand, 'plain', `${name} operand`);
}

function handleRead(acc: Accumulator, name: string, args: readonly ShellWord[], read: ReadSpec): void {
  const parsed = emitCommand(acc, name, args, read.spec);
  let files: readonly ShellWord[] = parsed.operands;
  if (read.firstIsPattern === true && !hasAnyFlag(parsed, read.patternFlags ?? [])) files = files.slice(1);
  if (read.skipAssignmentOperands === true) files = files.filter((word) => !word.text.includes('='));
  if (files.some((word) => word.dynamic)) {
    addOpaque(acc, 'dynamic-operand', `${name} reads a file named by a variable or substitution`);
  }
  const inPlace = hasAnyFlag(parsed, read.inPlaceFlags ?? []);
  for (const file of files) {
    if (file.dynamic || file.text === '-') continue;
    emitFsWord(acc, 'read', file, 'plain', `${name} operand`);
    if (inPlace) emitFsWord(acc, 'write', file, 'plain', `${name} in-place`);
  }
  for (const value of valuesOf(parsed, read.readValueFlags ?? [])) emitFsWord(acc, 'read', value, 'plain', `${name} file option`);
  for (const value of valuesOf(parsed, read.writeValueFlags ?? [])) emitFsWord(acc, 'write', value, 'plain', `${name} output option`);
}

function handleDd(acc: Accumulator, args: readonly ShellWord[]): void {
  emitCommand(acc, 'dd', args, {});
  for (const word of args) {
    const text = word.text;
    const isInput = text.startsWith('if=');
    const isOutput = text.startsWith('of=');
    if (!isInput && !isOutput) continue;
    const file: ArgWord = { text: text.slice(3), dynamic: word.dynamic, wildcard: word.wildcard };
    emitFsWord(acc, isInput ? 'read' : 'write', file, 'plain', `dd ${isInput ? 'if' : 'of'}`);
  }
}

// ---- curl / wget ------------------------------------------------------------------------------------------

const CURL_VALUE_FLAGS: readonly string[] = [
  '-d', '--data', '--data-ascii', '--data-binary', '--data-raw', '--data-urlencode', '--json', '-H', '--header', '-X',
  '--request', '-o', '--output', '-u', '--user', '-A', '--user-agent', '-e', '--referer', '-b', '--cookie', '-c',
  '--cookie-jar', '-F', '--form', '--form-string', '-T', '--upload-file', '-K', '--config', '-m', '--max-time',
  '--connect-timeout', '-w', '--write-out', '-x', '--proxy', '-U', '--proxy-user', '--url', '-r', '--range', '-C',
  '--continue-at', '-E', '--cert', '--cert-type', '--key', '--key-type', '--pass', '--cacert', '--capath', '--crlfile',
  '--proxy-cacert', '--proxy-cert', '--proxy-key', '--netrc-file', '--resolve', '--connect-to', '--interface', '--retry',
  '--retry-delay', '--retry-max-time', '-y', '--speed-time', '-Y', '--speed-limit', '--limit-rate', '-z', '--time-cond',
  '--max-filesize', '--max-redirs', '--output-dir', '--trace', '--trace-ascii', '--stderr', '--unix-socket',
  '--abstract-unix-socket', '-D', '--dump-header', '--variable', '--etag-save', '--etag-compare', '--hsts', '--alt-svc',
  '--oauth2-bearer', '--aws-sigv4', '--dns-servers', '--local-port', '--keepalive-time', '-Q', '--quote', '--mail-from',
  '--mail-rcpt', '--mail-auth', '-P', '--ftp-port', '--tls-max', '--ciphers', '--proto', '--proto-redir',
  '--preproxy', '--noproxy', '--happy-eyeballs-timeout-ms', '--expect100-timeout', '--sasl-authzid', '--login-options',
];
const CURL_FILE_DATA_FLAGS: readonly string[] = ['-d', '--data', '--data-ascii', '--data-binary', '--json'];
const CURL_READ_FLAGS: readonly string[] = [
  '-T', '--upload-file', '-K', '--config', '--key', '--cacert', '--capath', '--crlfile', '--proxy-cacert', '--proxy-cert',
  '--proxy-key', '--netrc-file', '--etag-compare',
];
const CURL_WRITE_FLAGS: readonly string[] = [
  '-o', '--output', '-D', '--dump-header', '-c', '--cookie-jar', '--trace', '--trace-ascii', '--stderr', '--etag-save',
];
const CURL_DATA_FLAGS: readonly string[] = [
  '-d', '--data', '--data-ascii', '--data-binary', '--data-raw', '--data-urlencode', '--json', '-F', '--form', '--form-string',
];

function literal(text: string, from: ArgWord): ArgWord {
  return { text, dynamic: from.dynamic, wildcard: from.wildcard };
}

function curlMethod(parsed: ParsedArgs<ShellWord>): string {
  const explicit = valuesOf(parsed, ['-X', '--request']).pop();
  if (explicit !== undefined && !explicit.dynamic) return explicit.text.toUpperCase();
  if (hasAnyFlag(parsed, ['-I', '--head'])) return 'HEAD';
  if (hasAnyFlag(parsed, ['-G', '--get'])) return 'GET';
  if (hasAnyFlag(parsed, ['-T', '--upload-file'])) return 'PUT';
  if (hasAnyFlag(parsed, CURL_DATA_FLAGS)) return 'POST';
  return 'GET';
}

function emitClientFile(acc: Accumulator, op: 'read' | 'write', word: ArgWord, origin: string): void {
  if (word.text === '-' || word.text === '') return;
  emitFsWord(acc, op, word, 'plain', origin);
}

function handleCurl(acc: Accumulator, name: string, args: readonly ShellWord[]): void {
  const parsed = emitCommand(acc, name, args, { valueFlags: CURL_VALUE_FLAGS });
  const method = curlMethod(parsed);
  const urls: ArgWord[] = [...parsed.operands, ...valuesOf(parsed, ['--url'])];
  for (const url of urls) emitUrlWord(acc, method, url, `${name} URL`);

  for (const value of valuesOf(parsed, CURL_FILE_DATA_FLAGS)) {
    if (value.text.startsWith('@')) emitClientFile(acc, 'read', literal(value.text.slice(1), value), `${name} data file`);
  }
  for (const value of valuesOf(parsed, ['--data-urlencode'])) {
    const at = value.text.indexOf('@');
    const eq = value.text.indexOf('=');
    if (at >= 0 && (eq < 0 || eq > at)) emitClientFile(acc, 'read', literal(value.text.slice(at + 1), value), `${name} data file`);
  }
  for (const value of valuesOf(parsed, ['-F', '--form'])) {
    const marker = Math.max(value.text.indexOf('=@'), value.text.indexOf('=<'));
    if (marker >= 0) {
      const rest = value.text.slice(marker + 2);
      const semicolon = rest.indexOf(';');
      emitClientFile(acc, 'read', literal(semicolon >= 0 ? rest.slice(0, semicolon) : rest, value), `${name} form file`);
    }
  }
  for (const value of valuesOf(parsed, ['-E', '--cert'])) {
    const colon = value.text.indexOf(':');
    emitClientFile(acc, 'read', literal(colon > 0 ? value.text.slice(0, colon) : value.text, value), `${name} certificate`);
  }
  for (const value of valuesOf(parsed, ['-b', '--cookie'])) {
    if (!value.text.includes('=')) emitClientFile(acc, 'read', value, `${name} cookie file`);
  }
  for (const value of valuesOf(parsed, CURL_READ_FLAGS)) emitClientFile(acc, 'read', value, `${name} input file`);
  for (const value of valuesOf(parsed, CURL_WRITE_FLAGS)) emitClientFile(acc, 'write', value, `${name} output file`);

  if (hasAnyFlag(parsed, ['-J', '--remote-header-name'])) {
    addOpaque(acc, 'dynamic-operand', `${name} -J writes a file named by the server`);
  }
  if (hasAnyFlag(parsed, ['-O', '--remote-name', '--remote-name-all'])) {
    const dir = valuesOf(parsed, ['--output-dir']).pop();
    for (const url of urls) {
      if (url.dynamic) continue;
      const base = urlBasename(url.text.includes('://') ? url.text : `http://${url.text}`);
      if (base === '') continue;
      const target = dir === undefined ? base : joinContextPath(acc.context, dir.text, base);
      emitClientFile(acc, 'write', literal(target, dir ?? url), `${name} -O output`);
    }
  }
}

const WGET_VALUE_FLAGS: readonly string[] = [
  '-O', '--output-document', '-o', '--output-file', '-a', '--append-output', '-P', '--directory-prefix', '-i',
  '--input-file', '--post-data', '--post-file', '--body-data', '--body-file', '--header', '-U', '--user-agent', '--user',
  '--password', '--http-user', '--http-password', '-e', '--execute', '-t', '--tries', '-T', '--timeout', '-w', '--wait',
  '--referer', '--method', '-B', '--base', '--config', '--load-cookies', '--save-cookies', '-Q', '--quota', '-l',
  '--level', '-D', '--domains', '-A', '--accept', '-R', '--reject', '--limit-rate', '--bind-address', '--ca-certificate',
  '--certificate', '--private-key',
];

function handleWget(acc: Accumulator, args: readonly ShellWord[]): void {
  const parsed = emitCommand(acc, 'wget', args, { valueFlags: WGET_VALUE_FLAGS });
  const methodValue = valuesOf(parsed, ['--method']).pop();
  const method =
    methodValue !== undefined && !methodValue.dynamic
      ? methodValue.text.toUpperCase()
      : valuesOf(parsed, ['--post-data', '--post-file']).length > 0
        ? 'POST'
        : 'GET';
  for (const url of parsed.operands) emitUrlWord(acc, method, url, 'wget URL');
  for (const value of valuesOf(parsed, ['-i', '--input-file', '--post-file', '--body-file', '--load-cookies', '--config', '--ca-certificate', '--certificate', '--private-key'])) {
    emitClientFile(acc, 'read', value, 'wget input file');
  }
  for (const value of valuesOf(parsed, ['-o', '--output-file', '-a', '--append-output', '--save-cookies'])) {
    emitClientFile(acc, 'write', value, 'wget log/cookie file');
  }
  const documents = valuesOf(parsed, ['-O', '--output-document']);
  if (documents.length > 0) {
    for (const value of documents) emitClientFile(acc, 'write', value, 'wget -O output');
    return;
  }
  const prefix = valuesOf(parsed, ['-P', '--directory-prefix']).pop();
  for (const url of parsed.operands) {
    if (url.dynamic) continue;
    const base = urlBasename(url.text.includes('://') ? url.text : `http://${url.text}`);
    const fileName = base === '' ? 'index.html' : base;
    const target = prefix === undefined ? fileName : joinContextPath(acc.context, prefix.text, fileName);
    emitClientFile(acc, 'write', literal(target, prefix ?? url), 'wget output');
  }
}

// ---- SQL clients ------------------------------------------------------------------------------------------

function emitSqlWord(acc: Accumulator, word: ArgWord, origin: string): void {
  if (word.dynamic) {
    addOpaque(acc, 'dynamic-operand', `${origin} SQL contains a variable or substitution`);
    return;
  }
  emitSql(acc, word.text);
}

function handleSqlClient(acc: Accumulator, name: string, args: readonly ShellWord[]): void {
  if (name === 'psql') {
    const parsed = emitCommand(acc, name, args, {
      valueFlags: ['-c', '--command', '-f', '--file', '-d', '--dbname', '-h', '--host', '-p', '--port', '-U', '--username', '-v', '--set', '--variable', '-o', '--output', '-L', '--log-file', '-P', '--pset', '-F', '-R', '-T'],
    });
    for (const sql of valuesOf(parsed, ['-c', '--command'])) emitSqlWord(acc, sql, 'psql -c');
    for (const file of valuesOf(parsed, ['-f', '--file'])) emitClientFile(acc, 'read', file, 'psql -f');
    for (const file of valuesOf(parsed, ['-o', '--output', '-L', '--log-file'])) emitClientFile(acc, 'write', file, 'psql output');
    return;
  }
  if (name === 'mysql') {
    const parsed = emitCommand(acc, name, args, {
      valueFlags: ['-e', '--execute', '-u', '--user', '-h', '--host', '-P', '--port', '-D', '--database', '--defaults-file', '-S', '--socket'],
    });
    for (const sql of valuesOf(parsed, ['-e', '--execute'])) emitSqlWord(acc, sql, 'mysql -e');
    return;
  }
  // sqlite3 [options] DB [SQL…]
  const parsed = emitCommand(acc, name, args, {
    singleDashIsLong: true,
    valueFlags: ['-cmd', '-separator', '-newline', '-nullvalue', '-init'],
  });
  for (const sql of valuesOf(parsed, ['-cmd'])) emitSqlWord(acc, sql, 'sqlite3 -cmd');
  for (const sql of parsed.operands.slice(1)) emitSqlWord(acc, sql, 'sqlite3');
}

// ---- shells and interpreters ------------------------------------------------------------------------------

function handleShell(acc: Accumulator, name: string, args: readonly ShellWord[], depth: number): void {
  emitCommand(acc, name, args, { stopAtFirstOperand: true });
  let hasCommandString = false;
  let readsStdin = false;
  let info = false;
  let i = 0;
  while (i < args.length) {
    const word = args[i];
    if (word === undefined) break;
    const text = word.text;
    if (word.dynamic) {
      addOpaque(acc, 'dynamic-command', `${name} option "${text}" contains a variable`);
      return;
    }
    if (text === '--') {
      i += 1;
      break;
    }
    if (text === '-') {
      readsStdin = true;
      i += 1;
      break;
    }
    if (text.startsWith('--')) {
      if (INFO_FLAGS.includes(text)) info = true;
      i += text === '--rcfile' || text === '--init-file' ? 2 : 1;
      continue;
    }
    if ((text.startsWith('-') || text.startsWith('+')) && text.length > 1) {
      const cluster = text.slice(1);
      if (cluster.includes('c')) hasCommandString = true;
      if (cluster.includes('s')) readsStdin = true;
      i += cluster.includes('o') || cluster.includes('O') ? 2 : 1;
      continue;
    }
    break;
  }
  const operands = args.slice(i);
  if (hasCommandString) {
    const script = operands[0];
    if (script === undefined) {
      addOpaque(acc, 'shell-syntax', `${name} -c without a command string`);
      return;
    }
    if (script.dynamic) {
      addOpaque(acc, 'dynamic-command', `${name} -c with a non-literal command string`);
      return;
    }
    if (depth + 1 > MAX_WRAPPER_DEPTH) {
      addOpaque(acc, 'wrapper-depth', `more than ${MAX_WRAPPER_DEPTH} nested shell wrappers`);
      return;
    }
    normalisePosixInto(acc, script.text, depth + 1);
    return;
  }
  if (readsStdin) {
    addOpaque(acc, 'stdin-script', `${name} reads commands from stdin`);
    return;
  }
  if (operands.length === 0 && !info) {
    addOpaque(acc, 'stdin-script', `${name} without a script reads commands from stdin`);
  }
  // Otherwise a script file runs; its content is unknown and the line is decided by the command alone (RUBRIC §4).
}

function handleInterpreter(acc: Accumulator, name: string, args: readonly ShellWord[], spec: InterpreterSpec): void {
  emitCommand(acc, name, args, { valueFlags: spec.valueFlags, stopAtFirstOperand: true });
  let info = false;
  let module = false;
  for (let i = 0; i < args.length; i += 1) {
    const word = args[i];
    if (word === undefined) break;
    const text = word.text;
    if (word.dynamic) {
      addOpaque(acc, 'dynamic-command', `${name} argument "${text}" contains a variable`);
      return;
    }
    if (text === '-') {
      addOpaque(acc, 'stdin-script', `${name} - reads a program from stdin`);
      return;
    }
    if (INFO_FLAGS.includes(text)) {
      info = true;
      continue;
    }
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      const flag = eq >= 0 ? text.slice(0, eq) : text;
      if (spec.codeFlags.includes(flag)) {
        addOpaque(acc, 'inline-code', `${name} ${flag} runs inline code`);
        return;
      }
      if (eq < 0 && spec.valueFlags.includes(flag)) i += 1;
      continue;
    }
    if (text.startsWith('-') && text.length > 1) {
      for (let j = 1; j < text.length; j += 1) {
        const c = text.charAt(j);
        if (spec.clusterCodeChars.includes(c) || spec.codeFlags.includes(`-${c}`)) {
          addOpaque(acc, 'inline-code', `${name} ${text} runs inline code`);
          return;
        }
        if (spec.valueFlags.includes(`-${c}`)) {
          if (spec.moduleFlags?.includes(`-${c}`) === true) module = true;
          if (j === text.length - 1) i += 1;
          break;
        }
      }
      continue;
    }
    if (spec.codeSubcommands?.includes(text) === true) {
      addOpaque(acc, 'inline-code', `${name} ${text} evaluates code`);
    }
    return; // a script file operand: not opaque
  }
  if (!info && !module) addOpaque(acc, 'stdin-script', `${name} without a script reads a program from stdin`);
}

// ---- dispatch ---------------------------------------------------------------------------------------------

function handleProgram(acc: Accumulator, name: string, args: readonly ShellWord[], depth: number): void {
  if (name === 'cd' || name === 'pushd' || name === 'popd') {
    emitCommand(acc, name, args, {});
    addOpaque(acc, 'dynamic-operand', `${name} changes the working directory; the lexical context is fixed`);
    return;
  }
  if (EVAL_COMMANDS.includes(name)) {
    emitCommand(acc, name, args, {});
    addOpaque(acc, 'eval', `${name} runs code that is not analysed`);
    return;
  }
  if (DELETE_COMMANDS.includes(name)) {
    handleDelete(acc, name, args);
    return;
  }
  if (COPY_COMMANDS.includes(name)) {
    handleCopy(acc, name, args);
    return;
  }
  const writeSpec = WRITE_COMMANDS[name];
  if (writeSpec !== undefined) {
    handleWrite(acc, name, args, writeSpec);
    return;
  }
  const readSpec = READ_COMMANDS[READ_ALIASES[name] ?? name];
  if (readSpec !== undefined) {
    handleRead(acc, name, args, readSpec);
    return;
  }
  if (name === 'dd') {
    handleDd(acc, args);
    return;
  }
  if (LIST_COMMANDS.includes(name)) {
    const parsed = emitCommand(acc, name, args, {});
    for (const operand of parsed.operands) {
      if (!operand.dynamic) emitFsWord(acc, 'list', operand, 'plain', `${name} operand`);
    }
    return;
  }
  if (name === 'find') {
    emitCommand(acc, name, args, { singleDashIsLong: true });
    if (args.some((word) => FIND_ACTIONS.includes(word.text))) {
      addOpaque(acc, 'indirect-exec', 'find with -exec/-delete acts on paths chosen at run time');
    }
    return;
  }
  if (name === 'xargs' || name === 'parallel') {
    emitCommand(acc, name, args, {});
    addOpaque(acc, 'indirect-exec', `${name} runs a command with arguments read from stdin`);
    return;
  }
  if (name === 'su') {
    const parsed = emitCommand(acc, name, args, { valueFlags: ['-c', '--command', '-s', '--shell', '-g', '--group'] });
    if (hasAnyFlag(parsed, ['-c', '--command'])) addOpaque(acc, 'indirect-exec', 'su -c runs a command string as another user');
    return;
  }
  if (name === 'curl') {
    handleCurl(acc, name, args);
    return;
  }
  if (name === 'wget') {
    handleWget(acc, args);
    return;
  }
  if (name === 'git') {
    emitCommand(acc, name, args, {});
    emitGit(acc, texts(args), args.map((word) => word.dynamic));
    return;
  }
  if (name === 'psql' || name === 'mysql' || name === 'sqlite3') {
    handleSqlClient(acc, name, args);
    return;
  }
  if (SHELLS.includes(name)) {
    handleShell(acc, name, args, depth);
    return;
  }
  const interpreter = INTERPRETERS[name];
  if (interpreter !== undefined) {
    handleInterpreter(acc, name, args, interpreter);
    return;
  }
  const publishSpec = PUBLISH_COMMAND_SPECS[name];
  if (publishSpec !== undefined) {
    const parsed = emitCommand(acc, name, args, publishSpec);
    if (parsed.operands.some((word) => word.dynamic)) {
      addOpaque(acc, 'dynamic-operand', `${name} subcommand or operand contains a variable`);
    }
    return;
  }
  emitCommand(acc, name, args, {});
}

/** Analyses one simple command's words (after redirects and leading assignments are removed). */
function analyseWords(acc: Accumulator, initial: readonly ShellWord[], depth: number): void {
  let words = initial;
  for (;;) {
    const head = words[0];
    if (head === undefined) return;
    if (head.dynamic) {
      addOpaque(acc, 'dynamic-command', `command word "${head.text}" is a variable or substitution`);
      return;
    }
    if (head.wildcard && head.text !== '[' && head.text !== '[[') {
      addOpaque(acc, 'dynamic-command', `command word "${head.text}" contains a glob`);
      return;
    }
    const name = posixCommandName(head.text);
    if (!head.quoted && TRANSPARENT_KEYWORDS.includes(head.text)) {
      words = words.slice(1);
      continue;
    }
    if (!head.quoted && OPAQUE_KEYWORDS.includes(head.text)) {
      addOpaque(acc, 'shell-syntax', `"${head.text}" construct is not analysed`);
      return;
    }
    if (name === '') return;
    const args = words.slice(1);
    const wrapper = WRAPPERS[name];
    if (wrapper === undefined) {
      handleProgram(acc, name, args, depth);
      return;
    }
    const parsed = emitCommand(acc, name, args, wrapper.spec);
    if ((name === 'env' && hasAnyFlag(parsed, ['-C', '--chdir'])) ||
        (name === 'sudo' && hasAnyFlag(parsed, ['-D', '--chdir']))) {
      addOpaque(acc, 'dynamic-operand', `${name} changes the working directory; the lexical context is fixed`);
    }
    if (wrapper.lookupFlags !== undefined && hasAnyFlag(parsed, wrapper.lookupFlags)) return;
    if (wrapper.opaqueFlags !== undefined && hasAnyFlag(parsed, wrapper.opaqueFlags)) {
      addOpaque(acc, 'indirect-exec', `${name} ${wrapper.opaqueFlags.join('/')} runs a command string`);
      return;
    }
    let rest = args.slice(parsed.firstOperandIndex + (wrapper.skipOperands ?? 0));
    if (wrapper.skipAssignments === true) {
      let k = 0;
      while (k < rest.length && rest[k]?.assignment === true) k += 1;
      rest = rest.slice(k);
    }
    words = rest;
  }
}

function analyseSimpleCommand(acc: Accumulator, command: SimpleCommand, depth: number): void {
  for (const redirect of command.redirects) emitRedirect(acc, redirect);
  let k = 0;
  while (k < command.words.length && command.words[k]?.assignment === true) k += 1;
  analyseWords(acc, command.words.slice(k), depth);
}

/**
 * Normalises a posix command string into the accumulator. `depth` is the current shell-wrapper depth (0 for the action
 * itself). Budget exhaustion during semantic analysis propagates as AnalysisLimitError to the action entry point.
 */
export function normalisePosixInto(acc: Accumulator, command: string, depth: number): void {
  const scan = scanPosix(command, acc.context.home, acc.budget, acc);
  acc.opaque.push(...scan.opaque);
  for (const simple of scan.commands) analyseSimpleCommand(acc, simple, depth);
}

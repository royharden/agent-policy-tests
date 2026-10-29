// Bounded lexical Windows shell subset. Completed commands are visited immediately: a malformed/budgeted suffix
// cannot erase an already visible deny. No shell is invoked. Dialect semantics live in the two caller modules.
import { MAX_SUBCOMMAND_NODES } from '../limits';
import { addOpaque } from './emit';
import { AnalysisLimitError, spendOrThrow } from './opaque';
import { emitRedirect, type RedirectSpec } from './redirect';
import type { Accumulator, ArgWord } from './types';

export interface WindowsWord extends ArgWord { readonly quoted: boolean }
export interface WindowsCommand { readonly words: readonly WindowsWord[]; readonly invoked: boolean }

export function windowsName(text: string): string {
  const name = text.split('\\').join('/').split('/').at(-1)?.toLowerCase() ?? '';
  return name.endsWith('.exe') ? name.slice(0, -4) : name;
}

export function isWindowsDevice(text: string): boolean {
  const name = text.toLowerCase();
  return name === 'nul' || name === 'nul:';
}

/** Only explicit literal syntax is supported. Variables other than PowerShell context HOME remain dynamic. */
export function scanWindowsInto(
  acc: Accumulator,
  src: string,
  dialect: 'powershell' | 'cmd',
  visit: (command: WindowsCommand) => void,
): void {
  let words: WindowsWord[] = [];
  let text = '';
  let active = false;
  let quoted = false;
  let dynamic = false;
  let wildcard = false;
  let invoked = false;
  let pending: Omit<RedirectSpec, 'target'> | null = null;
  let redirects: RedirectSpec[] = [];
  const put = (ch: string): void => {
    active = true;
    text += ch;
    if ('*?['.includes(ch)) wildcard = true;
  };
  const flushWord = (): void => {
    if (!active) return;
    const word: WindowsWord = { text, dynamic, wildcard, quoted };
    if (pending !== null) { redirects.push({ ...pending, target: word }); pending = null; }
    else words.push(word);
    text = ''; active = false; quoted = false; dynamic = false; wildcard = false;
  };
  const flushCommand = (): void => {
    flushWord();
    if (pending !== null) { redirects.push({ ...pending, target: null }); pending = null; }
    if (words.length > 0 || redirects.length > 0) {
      acc.nodes += 1;
      if (acc.nodes > MAX_SUBCOMMAND_NODES) throw new AnalysisLimitError('node-budget', 'too many Windows command nodes');
      for (const redirect of redirects) emitRedirect(acc, redirect, isWindowsDevice);
      if (words.length > 0) visit({ words, invoked });
    }
    words = []; redirects = []; invoked = false;
  };
  const variable = (start: number): number => {
    let end = start + 1;
    if (src[end] === '{') {
      end += 1;
      while (end < src.length && src[end] !== '}') { spendOrThrow(acc.budget); end += 1; }
      if (src[end] === '}') end += 1;
    } else {
      while (end < src.length && /[a-zA-Z0-9_:]/.test(src[end] ?? '')) { spendOrThrow(acc.budget); end += 1; }
    }
    const token = src.slice(start, end);
    if (token.toLowerCase() === '$home' || token.toLowerCase() === '${home}') put(acc.context.home);
    else { put(token); dynamic = true; }
    return end;
  };
  let i = 0;
  while (i < src.length) {
    spendOrThrow(acc.budget);
    const ch = src[i] ?? '';
    if (ch === ' ' || ch === '\t' || ch === '\r') { flushWord(); i += 1; continue; }
    if (dialect === 'powershell' && ch === '#' && !active) {
      while (i < src.length && src[i] !== '\n') { spendOrThrow(acc.budget); i += 1; }
      continue;
    }
    if (ch === '"' || (dialect === 'powershell' && ch === "'")) {
      const quote = ch; quoted = true; active = true; i += 1;
      let closed = false;
      while (i < src.length) {
        spendOrThrow(acc.budget);
        const q = src[i] ?? '';
        if (q === quote) {
          if (dialect === 'powershell' && quote === "'" && src[i + 1] === "'") { put("'"); i += 2; continue; }
          i += 1; closed = true; break;
        }
        if (dialect === 'powershell' && quote === '"' && q === '`') {
          const next = src[i + 1];
          if (next === undefined) break;
          // PowerShell escape sequences whose exact value is outside this path/argv subset stay opaque.
          if ('0abefnrtuv'.includes(next)) dynamic = true;
          put(next); i += 2; continue;
        }
        if (dialect === 'powershell' && quote === '"' && q === '$') { i = variable(i); continue; }
        if (dialect === 'cmd' && (q === '%' || q === '!')) dynamic = true;
        put(q); i += 1;
      }
      if (!closed) { addOpaque(acc, 'shell-syntax', `${dialect}: unterminated quote`); return; }
      continue;
    }
    const escape = dialect === 'powershell' ? '`' : '^';
    if (ch === escape) {
      const next = src[i + 1];
      if (next === undefined) { addOpaque(acc, 'shell-syntax', `${dialect}: dangling escape`); return; }
      if (dialect === 'cmd' && (next === '%' || next === '!')) dynamic = true;
      if (next !== '\n' && next !== '\r') put(next);
      i += next === '\r' && src[i + 2] === '\n' ? 3 : 2;
      continue;
    }
    if (dialect === 'powershell' && ch === '$') { i = variable(i); continue; }
    if (dialect === 'cmd' && (ch === '%' || ch === '!')) dynamic = true;
    // At a token boundary @ can introduce splatting/arrays/here-strings. Inside an argument it is literal data
    // (notably URL userinfo), which must reach destination parsing so a visible disallowed-host deny survives.
    if ('(){}'.includes(ch) || (dialect === 'powershell' && ch === '@' && !active)) {
      addOpaque(acc, 'shell-syntax', `${dialect}: expressions, blocks, arrays and grouped commands are unsupported`); return;
    }
    if (ch === '>' || ch === '<') {
      let operator = ch;
      // A file descriptor immediately preceding the operator is syntax, not an operand.
      if (active && (/^[0-9]+$/.test(text) || (dialect === 'powershell' && text === '*'))) {
        operator = text + ch; text = ''; active = false; wildcard = false;
      } else flushWord();
      if (pending !== null) { addOpaque(acc, 'shell-syntax', 'missing redirection target'); return; }
      i += 1;
      if (ch === '>' && src[i] === '>') { operator += '>'; i += 1; }
      if (src[i] === '&') {
        i += 1;
        const descriptor = src[i];
        if (descriptor === undefined || !'0123456789-'.includes(descriptor)) {
          addOpaque(acc, 'shell-syntax', 'unsupported stream duplication'); return;
        }
        i += 1; redirects.push({ op: 'dup', operator: `${operator}&${descriptor}`, target: null });
      } else {
        if (dialect === 'powershell' && ch === '<') { addOpaque(acc, 'shell-syntax', 'PowerShell input redirection is unsupported'); return; }
        pending = { op: ch === '<' ? 'read' : operator.endsWith('>>') ? 'append' : 'write', operator };
      }
      continue;
    }
    if (ch === '\n' || ch === '|' || ch === '&' || (dialect === 'powershell' && ch === ';')) {
      if (dialect === 'powershell' && ch === '&' && words.length === 0 && !active && redirects.length === 0) {
        invoked = true; i += 1; continue;
      }
      flushCommand();
      i += src[i + 1] === ch && (ch === '&' || ch === '|') ? 2 : 1;
      continue;
    }
    put(ch); i += 1;
  }
  flushCommand();
}

export function emitWindowsCommand(acc: Accumulator, dialect: 'powershell' | 'cmd', name: string, args: readonly ArgWord[], flags: readonly string[], operands: readonly ArgWord[]): void {
  acc.subs.push({ kind: 'command', dialect, name, argv: args.map((word) => word.text), flags, words: [name, ...operands.map((word) => word.text)] });
}

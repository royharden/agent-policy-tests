// Literal PowerShell subset; no evaluation, environment lookup, filesystem or shell calls.
import { MAX_WRAPPER_DEPTH } from '../limits';
import { addOpaque, deleteMode, emitFsWord, emitGit, emitUrlWord } from './emit';
import type { Accumulator, ArgWord } from './types';
import { emitWindowsCommand, scanWindowsInto, windowsName, type WindowsCommand } from './windows-scan';

const ALIASES: Readonly<Record<string, string>> = {
  rm: 'remove-item', ri: 'remove-item', del: 'remove-item', erase: 'remove-item', rd: 'remove-item', rmdir: 'remove-item',
  cat: 'get-content', gc: 'get-content', type: 'get-content', sc: 'set-content', ac: 'add-content',
  iwr: 'invoke-webrequest', irm: 'invoke-restmethod', iex: 'invoke-expression', sl: 'set-location', cd: 'set-location', chdir: 'set-location',
  echo: 'write-output', write: 'write-output', ls: 'get-childitem', dir: 'get-childitem', gci: 'get-childitem',
};
const PARAMS: Readonly<Record<string, readonly string[]>> = {
  'remove-item': ['path', 'literalpath', 'recurse', 'force', 'whatif', 'confirm', 'filter', 'include', 'exclude', 'erroraction'],
  'get-content': ['path', 'literalpath', 'raw', 'encoding', 'totalcount', 'tail'],
  'get-childitem': ['path', 'literalpath', 'recurse', 'force', 'name'],
  'set-content': ['path', 'literalpath', 'value', 'encoding', 'force', 'nonewline', 'whatif'],
  'add-content': ['path', 'literalpath', 'value', 'encoding', 'force', 'nonewline', 'whatif'],
  'out-file': ['filepath', 'literalpath', 'inputobject', 'append', 'force', 'encoding', 'nonewline', 'whatif'],
  'invoke-webrequest': ['uri', 'method', 'outfile', 'infile', 'body', 'headers', 'usebasicparsing'],
  'invoke-restmethod': ['uri', 'method', 'outfile', 'infile', 'body', 'headers'],
  'start-process': ['filepath', 'argumentlist', 'verb', 'workingdirectory', 'wait', 'nonewwindow'],
};
const SWITCHES = ['recurse', 'force', 'whatif', 'confirm', 'raw', 'name', 'append', 'nonewline', 'usebasicparsing', 'wait', 'nonewwindow'];

interface PsArgs {
  readonly operands: readonly ArgWord[];
  readonly flags: readonly string[];
  readonly values: ReadonlyMap<string, readonly ArgWord[]>;
  readonly uncertain: boolean;
}

function parameters(acc: Accumulator, name: string, args: readonly ArgWord[]): PsArgs {
  const known = PARAMS[name] ?? [];
  const operands: ArgWord[] = []; const flags: string[] = []; const values = new Map<string, ArgWord[]>();
  let uncertain = false;
  for (let i = 0; i < args.length; i += 1) {
    const word = args[i]; if (word === undefined) continue;
    if (word.dynamic) { addOpaque(acc, 'dynamic-operand', `${name}: dynamic argument`); uncertain = true; }
    if (!word.text.startsWith('-')) { operands.push(word); continue; }
    const colon = word.text.indexOf(':');
    const spelling = word.text.slice(1, colon < 0 ? undefined : colon).toLowerCase();
    const candidates = known.includes(spelling) ? [spelling] : known.filter((key) => key.startsWith(spelling));
    const key = candidates[0];
    if (candidates.length !== 1 || key === undefined || spelling.length === 0) {
      addOpaque(acc, 'shell-syntax', `${name}: unknown/ambiguous parameter ${word.text}`); uncertain = true; continue;
    }
    if (SWITCHES.includes(key)) {
      if (colon >= 0) { addOpaque(acc, 'dynamic-operand', `${name}: parameter switch expression`); uncertain = true; }
      else flags.push(`-${key}`);
      continue;
    }
    const value: ArgWord | undefined = colon >= 0 ? { ...word, text: word.text.slice(colon + 1) } : args[++i];
    if (value === undefined || value.text.length === 0 || (colon < 0 && value.text.startsWith('-'))) {
      addOpaque(acc, 'shell-syntax', `${name}: missing ${key} value`); uncertain = true; continue;
    }
    const list = values.get(key) ?? []; list.push(value); values.set(key, list);
  }
  return { operands, flags, values, uncertain };
}

function analyse(acc: Accumulator, command: WindowsCommand, depth: number): void {
  const head = command.words[0]; if (head === undefined) return;
  if (head.dynamic || head.wildcard) { addOpaque(acc, 'dynamic-command', 'PowerShell command is dynamic'); return; }
  if (head.quoted && !command.invoked) { addOpaque(acc, 'shell-syntax', 'quoted PowerShell expression without literal invocation'); return; }
  const rawName = windowsName(head.text);
  const name = ALIASES[rawName] ?? rawName;
  const args = command.words.slice(1);
  if (['invoke-expression', '.', 'invoke-command', 'invoke-item'].includes(name)) { addOpaque(acc, 'eval', `${name}: indirect execution`); return; }
  if (['powershell', 'pwsh'].includes(name)) {
    const first = args[0]?.text.toLowerCase();
    if ((first === '-command' || first === '-c') && args.length === 2 && args[1]?.dynamic === false) {
      if (depth >= MAX_WRAPPER_DEPTH) { addOpaque(acc, 'wrapper-depth', 'PowerShell wrapper depth exceeded'); return; }
      normalisePowerShellInto(acc, args[1].text, depth + 1); return;
    }
    addOpaque(acc, 'inline-code', `${name}: encoded, stdin, file or unsupported command flags`); return;
  }
  if (name === 'git') { emitWindowsCommand(acc, 'powershell', name, args, [], args); emitGit(acc, args.map((w) => w.text), args.map((w) => w.dynamic)); return; }
  if (name === 'set-location') { addOpaque(acc, 'dynamic-operand', 'PowerShell changes the lexical working directory'); return; }
  if (name === 'write-output') { emitWindowsCommand(acc, 'powershell', name, args, [], args); return; }
  if (PARAMS[name] === undefined) {
    emitWindowsCommand(acc, 'powershell', name, args, [], args);
    addOpaque(acc, 'indirect-exec', `PowerShell program ${name} is outside the modeled subset`); return;
  }
  const parsed = parameters(acc, name, args);
  emitWindowsCommand(acc, 'powershell', name, args, parsed.flags, parsed.operands);
  if (name === 'start-process') {
    const verb = parsed.values.get('verb')?.[0];
    if (verb?.dynamic === false && verb.text.toLowerCase() === 'runas') emitWindowsCommand(acc, 'powershell', 'runas', [], [], []);
    addOpaque(acc, 'indirect-exec', 'Start-Process payload is not analyzed'); return;
  }
  // Unknown parameters, filters and WhatIf change binding/effect semantics: retain ask, never guess an effect.
  if (parsed.uncertain || parsed.flags.includes('-whatif') || [...parsed.values.values()].some((values) => values.length > 1) || ['filter', 'include', 'exclude'].some((key) => parsed.values.has(key))) {
    addOpaque(acc, 'shell-syntax', `${name}: unsupported effect/binding parameter`); return;
  }
  const literal = parsed.values.get('literalpath');
  const explicitPaths = ['literalpath', 'path', 'filepath'].filter((key) => parsed.values.has(key));
  if (explicitPaths.length > 1 || (explicitPaths.length > 0 && parsed.operands.length > 0 && !['set-content', 'add-content', 'out-file'].includes(name))) {
    addOpaque(acc, 'shell-syntax', `${name}: unsupported mixed positional/path binding`); return;
  }
  const paths = literal ?? parsed.values.get('path') ?? parsed.values.get('filepath') ?? parsed.operands.slice(0, name === 'set-content' || name === 'add-content' ? 1 : undefined);
  if (name === 'invoke-webrequest' || name === 'invoke-restmethod') {
    const uri = parsed.values.get('uri') ?? parsed.operands;
    const method = parsed.values.get('method')?.[0];
    if (method?.dynamic === true) addOpaque(acc, 'dynamic-operand', 'dynamic HTTP method');
    for (const word of uri) emitUrlWord(acc, method?.text.toUpperCase() ?? 'GET', word, name);
    for (const word of parsed.values.get('outfile') ?? []) emitFsWord(acc, 'write', word, 'plain', `${name} OutFile`);
    for (const word of parsed.values.get('infile') ?? []) emitFsWord(acc, 'read', word, 'plain', `${name} InFile`);
    if (uri.length === 0) addOpaque(acc, 'shell-syntax', `${name}: missing URI`);
    return;
  }
  if (paths.length === 0) { addOpaque(acc, 'shell-syntax', `${name}: no explicit path`); return; }
  for (const original of paths) {
    const word = literal === undefined ? original : { ...original, wildcard: false };
    if (word.text.includes(',')) { addOpaque(acc, 'dynamic-operand', 'PowerShell path arrays are unsupported'); continue; }
    const op = name === 'remove-item' ? 'delete' : name === 'get-content' ? 'read' : name === 'get-childitem' ? 'list' : 'write';
    emitFsWord(acc, op, word, op === 'delete' ? deleteMode(parsed.flags.includes('-recurse'), parsed.flags.includes('-force')) : 'plain', name);
  }
}

export function normalisePowerShellInto(acc: Accumulator, command: string, depth: number): void {
  scanWindowsInto(acc, command, 'powershell', (simple) => analyse(acc, simple, depth));
}

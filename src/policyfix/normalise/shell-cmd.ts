// cmd's bounded literal command subset. Variables, batch control flow and indirect script bodies ask.
import { MAX_WRAPPER_DEPTH } from '../limits';
import { addOpaque, deleteMode, emitFsWord, emitGit } from './emit';
import type { Accumulator } from './types';
import { emitWindowsCommand, scanWindowsInto, windowsName, type WindowsCommand } from './windows-scan';

function analyse(acc: Accumulator, simple: WindowsCommand, depth: number): void {
  const head = simple.words[0]; if (head === undefined) return;
  if (head.dynamic || head.wildcard) { addOpaque(acc, 'dynamic-command', 'cmd command position contains expansion'); return; }
  const name = windowsName(head.text);
  const args = simple.words.slice(1);
  if (name === 'cmd') {
    let index = 0;
    while (args[index]?.text.toLowerCase() === '/d' || args[index]?.text.toLowerCase() === '/s') index += 1;
    if (args[index]?.text.toLowerCase() !== '/c' || args.slice(index + 1).some((w) => w.dynamic)) {
      addOpaque(acc, 'inline-code', 'cmd wrapper requires literal /c'); return;
    }
    const body = args.slice(index + 1);
    if (body.length === 0) { addOpaque(acc, 'stdin-script', 'cmd /c has no literal command'); return; }
    if (depth >= MAX_WRAPPER_DEPTH) { addOpaque(acc, 'wrapper-depth', 'cmd wrapper depth exceeded'); return; }
    // Multiple argv words are reconstructed only when no grouping/quote information is lost.
    if (body.length > 1 && body.some((w) => w.quoted || /[&|<>^]/.test(w.text))) {
      addOpaque(acc, 'shell-syntax', 'cmd /c complex quoting is unsupported'); return;
    }
    normaliseCmdInto(acc, body.map((w) => w.text).join(' '), depth + 1); return;
  }
  if (name === 'git') { emitWindowsCommand(acc, 'cmd', name, args, [], args); emitGit(acc, args.map((w) => w.text), args.map((w) => w.dynamic)); return; }
  if (['echo', 'rem', 'ver'].includes(name)) { emitWindowsCommand(acc, 'cmd', name, args, [], args); return; }
  if (name === 'cd' || name === 'chdir' || name === 'pushd' || name === 'popd') { addOpaque(acc, 'dynamic-operand', 'cmd changes the lexical cwd'); return; }
  if (['call', 'for', 'if', 'set', 'setlocal', 'endlocal', 'start', 'powershell', 'pwsh', 'wscript', 'cscript'].includes(name) || name.endsWith('.bat') || name.endsWith('.cmd')) {
    addOpaque(acc, 'indirect-exec', `${name}: indirect/batch execution`); return;
  }
  const flags = args.filter((w) => w.text.startsWith('/')).map((w) => w.text.toLowerCase());
  const operands = args.filter((w) => !w.text.startsWith('/'));
  emitWindowsCommand(acc, 'cmd', name, args, flags, operands);
  if (name === 'runas') { addOpaque(acc, 'indirect-exec', 'runas payload is opaque'); return; }
  if (['del', 'erase', 'rd', 'rmdir', 'type', 'dir'].includes(name)) {
    const allowed = name === 'del' || name === 'erase' ? ['/s', '/q', '/f'] : name === 'rd' || name === 'rmdir' ? ['/s', '/q'] : [];
    if (flags.some((flag) => !allowed.includes(flag)) || args.some((w) => w.dynamic)) {
      addOpaque(acc, 'dynamic-operand', `${name}: unsupported switch/expansion`); return;
    }
    if (operands.length === 0) { addOpaque(acc, 'shell-syntax', `${name}: no explicit path`); return; }
    const op = name === 'type' ? 'read' : name === 'dir' ? 'list' : 'delete';
    // RUBRIC Q03: /q suppresses prompts; only /f is force and only /s is recursive.
    for (const word of operands) emitFsWord(acc, op, word, op === 'delete' ? deleteMode(flags.includes('/s'), flags.includes('/f')) : 'plain', name);
    return;
  }
  addOpaque(acc, 'indirect-exec', `cmd program ${name} is outside the modeled subset`);
}

export function normaliseCmdInto(acc: Accumulator, command: string, depth: number): void {
  scanWindowsInto(acc, command, 'cmd', (simple) => analyse(acc, simple, depth));
}

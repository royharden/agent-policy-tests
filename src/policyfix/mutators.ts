// Mutations declare expectation transforms; they never ask the guard what an expectation should be.
import type { Action, Rule, ShellDialect, TrapName, Verdict } from './action';
import type { EvaluationContext } from './context';

export interface Mutation {
  readonly id: string;
  readonly trap: TrapName;
  readonly action: Action;
  readonly transform: 'preserve' | 'opaque';
  readonly expected_local: Verdict;
}

export interface MutationOptions {
  readonly seed?: number;
  /** Enable additional dialects only after their normalizers are implemented. */
  readonly dialects?: readonly ShellDialect[];
  readonly rule?: Rule;
}

export function quotePosix(text: string): string {
  return `'${text.replaceAll("'", "'\\''")}'`;
}

/** Deterministic ordering without global random state; this is ordering, not cryptography. */
function orderKey(text: string, seed: number): number {
  let value = seed >>> 0;
  for (const ch of text) value = Math.imul(value ^ ch.charCodeAt(0), 16777619) >>> 0;
  return value;
}

function plainWords(command: string): readonly string[] | null {
  for (const ch of command) if ('\'"\\$`;|&()<>\n\r\t*?[]{}'.includes(ch)) return null;
  const words = command.split(' ').filter((word) => word !== '');
  return words.length > 0 ? words : null;
}

/** Small bounded set: each preserving rewrite is limited to syntax for which the rewrite is valid. */
export function mutateAction(
  action: Action,
  expected: Verdict,
  context: EvaluationContext,
  options: MutationOptions = {},
): readonly Mutation[] {
  const out: Mutation[] = [];
  const add = (id: string, trap: TrapName, changed: Action, transform: 'preserve' | 'opaque' = 'preserve'): void => {
    out.push({ id, trap, action: changed, transform, expected_local: transform === 'opaque' ? 'ask' : expected });
  };
  // A command predicate can itself forbid a newly introduced wrapper (e.g. "never run eval" or "never env").
  // There is no universal preserving/opaque rewrite for such a rule, so retain its original declarations instead.
  const commandRule = options.rule?.match.some((node) => node.field.startsWith('command.')) === true;
  if (action.kind === 'shell' && action.dialect === 'posix' && !commandRule) {
    const command = action.command.trim();
    const words = plainWords(command);
    // The opaque wrapper quotes the entire source: no source effect remains visible outside eval.
    add('opaque-eval', 'opaque', { ...action, command: `eval ${quotePosix(command)}` }, 'opaque');
    if (words !== null) {
      add('chain', 'chained', { ...action, command: `true; ${command}` });
      add('env-prefix', 'prefix-wrap', { ...action, command: `env ${command}` });
      // Do not add shell depth to an existing shell wrapper or code-binding construct.
      if (!['bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'for', 'case', 'function', 'coproc'].includes(words[0] ?? '')) {
        add('shell-wrapper', 'shell-wrapper', { ...action, command: `bash -c ${quotePosix(command)}` });
      }
      if (words[0] === 'rm') {
        add('escaped-rm', 'prefix-wrap', { ...action, command: `\\${command}` });
        const flags = words.slice(1).filter((word) => word === '-rf' || word === '-fr');
        const operands = words.slice(1).filter((word) => !word.startsWith('-'));
        if (flags.length === 1 && words.length === operands.length + 2 && operands.length > 0) {
          add('flags-after-path', 'flag-reorder', { ...action, command: `rm ${operands.join(' ')} -r -f` });
          if ((options.dialects ?? ['posix']).includes('powershell')) {
            add('powershell-delete', 'dialect-swap', { kind: 'shell', dialect: 'powershell', command: `Remove-Item -Recurse -Force -LiteralPath ${operands.map((word) => `'${word.replaceAll("'", "''")}'`).join(',')}` });
          }
          // cmd directory deletion is equivalent only for recursive directory targets in the lexical model.
          if ((options.dialects ?? ['posix']).includes('cmd') && operands.length === 1 && !operands[0]?.includes('%')) {
            add('cmd-delete', 'dialect-swap', { kind: 'shell', dialect: 'cmd', command: `rmdir /s /q "${operands[0] ?? ''}"` });
          }
        }
      }
    }
  }
  if (action.kind === 'fs') {
    const path = action.path;
    if (!path.includes('$') && !path.includes('%') && !path.startsWith('~')) {
      const at = Math.max(path.lastIndexOf('/'), context.path_flavor === 'windows' ? path.lastIndexOf('\\') : -1);
      const name = path.slice(at + 1);
      if (name !== '' && name !== '.' && name !== '..') {
        const separator = context.path_flavor === 'windows' ? '\\' : '/';
        add('path-dotdot', 'path-traversal', { ...action, path: `${path.slice(0, at + 1)}policy-hop${separator}..${separator}${name}` });
      }
    }
    if (context.case_insensitive_fs) add('path-case', 'case-fold', { ...action, path: path.toUpperCase() });
  }
  if (action.kind === 'sql') {
    add('sql-case', 'case-fold', { ...action, statement: action.statement.toUpperCase() });
    const trimmed = action.statement.trim();
    const space = trimmed.indexOf(' ');
    if (space > 0 && ['DROP', 'TRUNCATE', 'DELETE', 'UPDATE', 'SELECT'].includes(trimmed.slice(0, space).toUpperCase())) {
      add('sql-comment', 'sql-comment-split', { ...action, statement: `${trimmed.slice(0, space)}/**/${trimmed.slice(space + 1)}` });
    }
  }
  if (action.kind === 'http') {
    add('url-case', 'case-fold', { ...action, url: action.url.toUpperCase() });
    try {
      const url = new URL(action.url);
      url.searchParams.set('policy_hint', 'api.example.test.evil.test');
      add('url-query', 'url-lookalike', { ...action, url: url.href });
    } catch { /* Invalid URLs stay covered by their declaration; there is no preserving URL rewrite. */ }
  }
  if (action.kind === 'message') add('recipient-case', 'case-fold', { ...action, to: action.to.toUpperCase() });
  if (action.kind === 'git' && action.args[0] === 'push' && action.args.length === 3) {
    const ref = action.args[2] ?? '';
    const force = ref.startsWith('+') ? '+' : '';
    const branch = force === '' ? ref : ref.slice(1);
    if (branch !== '' && !branch.startsWith('-') && !branch.includes(':') && !branch.includes('*') && branch !== 'HEAD' && branch !== '@') {
      add('destination-refspec', 'refspec-trick', { ...action, args: ['push', action.args[1] ?? 'origin', `${force}HEAD:${branch}`] });
    }
  }
  if (action.kind === 'payment') {
    const limit = options.rule?.match.find((node) => node.field === 'payment.amount_exceeds')?.arg;
    if (typeof limit === 'number') {
      const amount = expected === 'allow' ? limit : limit + 1;
      if (Number.isSafeInteger(amount)) add('amount-boundary', 'amount-boundary', { ...action, amount_cents: amount });
    }
  }
  const seed = options.seed ?? 21;
  return out.sort((a, b) => orderKey(a.id, seed) - orderKey(b.id, seed) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

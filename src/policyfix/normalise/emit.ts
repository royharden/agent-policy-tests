// Shared emitters: turn operands, URLs, git argv, SQL text and recipients into sub-actions on the accumulator, recording
// an opaque finding whenever an operand cannot be analysed. Used by every dialect and by the non-shell action kinds.
// Framework-free.
import type { FsOp, HttpMethod, MessageChannel } from '../action';
import { analyseGitArgs } from './git';
import { opaqueFinding, type OpaqueCode } from './opaque';
import { canonicalisePath } from './path';
import { parseRecipients } from './recipient';
import { analyseSql } from './sql';
import type { Accumulator, ArgWord, DeleteMode, SubAction } from './types';
import { parseUrl } from './url';

export function pushSub(acc: Accumulator, sub: SubAction): void {
  acc.subs.push(sub);
}

export function addOpaque(acc: Accumulator, code: OpaqueCode, detail: string): void {
  acc.opaque.push(opaqueFinding(code, detail));
}

export function deleteMode(recursive: boolean, force: boolean): DeleteMode {
  if (recursive && force) return 'recursive-force';
  if (recursive) return 'recursive';
  if (force) return 'force';
  return 'plain';
}

/**
 * Emits an fs sub-action for a literal path string.
 * `expandHome`: resolve `~`/`$HOME` here (fs actions); shell words arrive already expanded by their scanner.
 */
export function emitFsPath(
  acc: Accumulator,
  op: FsOp,
  raw: string,
  mode: DeleteMode,
  origin: string,
  expandHome: boolean,
): void {
  const result = canonicalisePath(raw, acc.context, { expandHome });
  if (!result.ok) {
    addOpaque(acc, 'opaque-path', `${origin}: ${result.reason}`);
    return;
  }
  pushSub(acc, { kind: 'fs', op, path: result.path, mode, origin });
}

/**
 * Emits an fs sub-action for a scanned shell word. A word with an unresolved expansion is opaque (no sub-action);
 * a word with an unquoted wildcard is evaluated literally **and** recorded as opaque, because its expansion depends on
 * the real filesystem (a visible deny on the literal path still wins).
 */
export function emitFsWord(acc: Accumulator, op: FsOp, word: ArgWord, mode: DeleteMode, origin: string): void {
  if (word.dynamic) {
    addOpaque(acc, 'dynamic-operand', `${origin} "${word.text}" contains a variable or substitution`);
    return;
  }
  emitFsPath(acc, op, word.text, mode, origin, false);
  if (word.wildcard && op !== 'list') {
    addOpaque(acc, 'wildcard-operand', `${origin} "${word.text}" contains a glob or brace expansion`);
  }
}

/** Emits an http sub-action for a URL (literal text). */
export function emitUrl(
  acc: Accumulator,
  method: HttpMethod | string,
  raw: string,
  origin: string,
  defaultScheme?: 'http',
): void {
  const parsed = defaultScheme === undefined ? parseUrl(raw) : parseUrl(raw, { defaultScheme });
  if (!parsed.ok) {
    addOpaque(acc, 'unparsable-url', `${origin}: ${parsed.reason}`);
    return;
  }
  pushSub(acc, { kind: 'http', method, host: parsed.host, userinfo: parsed.userinfo, url: raw, origin });
}

export function emitUrlWord(acc: Accumulator, method: string, word: ArgWord, origin: string): void {
  if (word.dynamic) {
    addOpaque(acc, 'dynamic-operand', `${origin} "${word.text}" contains a variable or substitution`);
    return;
  }
  emitUrl(acc, method, word.text, origin, 'http');
}

/** Emits git sub-actions for an argv (everything after `git`). */
export function emitGit(acc: Accumulator, args: readonly string[], dynamic: readonly boolean[] = []): void {
  const analysis = analyseGitArgs(args, dynamic);
  acc.opaque.push(...analysis.opaque);
  for (const op of analysis.operations) {
    pushSub(acc, { kind: 'git', subcommand: op.subcommand, operation: op.operation, branch: op.branch, force: op.force });
  }
}

/** Emits one sql sub-action per top-level statement. */
export function emitSql(acc: Accumulator, text: string): void {
  const analysis = analyseSql(text, acc.budget);
  acc.opaque.push(...analysis.opaque);
  for (const statement of analysis.statements) {
    pushSub(acc, { kind: 'sql', verb: statement.verb, bounded: statement.bounded, text: statement.text });
  }
}

/** Emits one message sub-action per recipient. */
export function emitRecipients(acc: Accumulator, channel: MessageChannel, to: string): void {
  const parsed = parseRecipients(channel, to);
  if (!parsed.ok) {
    addOpaque(acc, 'unparsable-recipient', `${channel} recipient: ${parsed.reason}`);
    return;
  }
  for (const recipient of parsed.recipients) {
    pushSub(acc, {
      kind: 'message',
      channel,
      recipient: recipient.raw.trim(),
      domain_status: recipient.status,
      domain: recipient.domain,
      userinfo: recipient.userinfo,
    });
  }
}

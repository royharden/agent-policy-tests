// Normaliser entry point (PLAN M3; Claude §2.5 "Guard pipeline"): one validated Action → flat typed sub-actions +
// opaque findings, against an explicit evaluation context. Purely lexical; never reads the real filesystem,
// environment, DNS or repository.
//
// Dialect dispatch shares the action accumulator, wrapper/node caps and scanner+glob budget across all three
// bounded dialects. Unsupported constructs contribute opaque findings without changing guard precedence.
// Framework-free.
import type { Action, ShellDialect } from '../action';
import type { EvaluationContext } from '../context';
import { addOpaque, deleteMode, emitFsPath, emitGit, emitRecipients, emitSql, emitUrl, pushSub } from './emit';
import { AnalysisLimitError, createBudget, type StepBudget } from './opaque';
import { normalisePosixInto } from './shell-posix';
import { normalisePowerShellInto } from './shell-powershell';
import { normaliseCmdInto } from './shell-cmd';
import type { Accumulator, Normalised, SubAction } from './types';

export type { Normalised, SubAction } from './types';

/** A dialect normaliser appends the sub-actions of `command` to the accumulator. `depth` = shell-wrapper depth. */
export type DialectNormaliser = (acc: Accumulator, command: string, depth: number) => void;

/** The dispatch point M5 extends. */
export const DIALECT_NORMALISERS: Readonly<Record<ShellDialect, DialectNormaliser>> = {
  posix: normalisePosixInto,
  powershell: normalisePowerShellInto,
  cmd: normaliseCmdInto,
};

function normaliseInto(acc: Accumulator, action: Action): void {
  switch (action.kind) {
    case 'shell':
      DIALECT_NORMALISERS[action.dialect](acc, action.command, 0);
      return;
    case 'fs':
      emitFsPath(
        acc,
        action.op,
        action.path,
        action.op === 'delete' ? deleteMode(action.recursive === true, false) : 'plain',
        'fs action',
        true,
      );
      return;
    case 'http':
      emitUrl(acc, action.method, action.url, 'http action');
      return;
    case 'sql':
      emitSql(acc, action.statement);
      return;
    case 'git':
      emitGit(acc, action.args);
      return;
    case 'payment':
      pushSub(acc, { kind: 'payment', amount_cents: action.amount_cents, currency: action.currency });
      return;
    case 'message':
      emitRecipients(acc, action.channel, action.to);
      return;
  }
}

/**
 * Normalises one schema-valid action. `budget` is shared with the guard's glob matching (PLAN A6: one 20,000-step
 * budget per action). A budget hit keeps the sub-actions produced so far and adds an opaque finding. Any other
 * exception propagates to the guard, which turns it into an `ask` (evaluator error).
 */
export function normaliseAction(
  action: Action,
  context: EvaluationContext,
  budget: StepBudget = createBudget(),
): Normalised {
  const acc: Accumulator = { context, budget, subs: [], opaque: [], nodes: 0 };
  try {
    normaliseInto(acc, action);
  } catch (error: unknown) {
    if (!(error instanceof AnalysisLimitError)) throw error;
    addOpaque(acc, error.code, error.message);
  }
  return { subs: acc.subs, opaque: acc.opaque };
}

/** One-line description of a sub-action, for guard reasons and the UI. */
export function describeSubAction(sub: SubAction): string {
  switch (sub.kind) {
    case 'command':
      return `command ${sub.words.join(' ')}${sub.flags.length > 0 ? ` (flags ${sub.flags.join(' ')})` : ''}`;
    case 'fs':
      return `fs ${sub.op} ${sub.path.display}${sub.mode === 'plain' ? '' : ` (${sub.mode})`} [${sub.origin}]`;
    case 'http':
      return `http ${sub.method} host ${sub.host}${sub.userinfo ? ' (userinfo present)' : ''}`;
    case 'sql':
      return `sql ${sub.verb}${sub.bounded ? '' : ' without a bounding WHERE'}`;
    case 'git':
      return `git ${sub.subcommand} ${sub.operation}${sub.branch === null ? ' (destination depends on repository state)' : ` ${sub.branch}`}${sub.force ? ' (force)' : ''}`;
    case 'payment':
      return `payment ${sub.amount_cents} cents ${sub.currency}`;
    case 'message':
      return `message ${sub.channel} to ${sub.recipient}${sub.domain === null ? ` (${sub.domain_status})` : ` (domain ${sub.domain})`}`;
  }
}

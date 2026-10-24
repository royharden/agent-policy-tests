// Normalised sub-action vocabulary (PLAN M3, Claude §2.5 "Guard pipeline"). The normaliser turns one validated Action
// into a flat list of typed sub-actions plus opaque findings; the guard evaluates every rule on every sub-action.
// Framework-free, type-only module.
import type { FsOp, HttpMethod, MessageChannel, ShellDialect } from '../action';
import type { EvaluationContext } from '../context';
import type { CanonicalPath } from './path';
import type { OpaqueFinding, StepBudget } from './opaque';

/** Kinds of normalised sub-action. `command` is a shell program invocation; the rest mirror the Action kinds. */
export const SUB_ACTION_KINDS = ['command', 'fs', 'http', 'sql', 'git', 'payment', 'message'] as const;
export type SubActionKind = (typeof SUB_ACTION_KINDS)[number];

/** How a delete was requested (Q03 restricts every mode except `plain`). */
export const DELETE_MODES = ['plain', 'recursive', 'force', 'recursive-force'] as const;
export type DeleteMode = (typeof DELETE_MODES)[number];

/** One shell program invocation after wrapper unwrapping (`sudo`, `env`, `\rm`, `bash -c '…'`). */
export interface CommandSubAction {
  readonly kind: 'command';
  readonly dialect: ShellDialect;
  /** Program name: basename of the command word, `.exe` stripped; lower-cased for PowerShell/cmd. */
  readonly name: string;
  /** `[name, ...operands]` — non-flag words with the values of known value-taking flags removed. */
  readonly words: readonly string[];
  /** Expanded flags (`-rf` → `-r`, `-f`; `--force=x` → `--force`; GNU long-option abbreviations resolved). */
  readonly flags: readonly string[];
  /** Every argument after the program name, as scanned (quotes removed). */
  readonly argv: readonly string[];
}

/** A filesystem effect: an fs action, a delete/read/write operand of a known command, or a redirect target. */
export interface FsSubAction {
  readonly kind: 'fs';
  readonly op: FsOp;
  readonly path: CanonicalPath;
  readonly mode: DeleteMode;
  /** Where the effect came from, for reasons (`fs action`, `rm operand`, `redirect >`, ...). */
  readonly origin: string;
}

export interface HttpSubAction {
  readonly kind: 'http';
  readonly method: HttpMethod | string;
  /** WHATWG hostname, lower-cased, one trailing dot removed. */
  readonly host: string;
  /** True when the URL authority carries userinfo (`user@host`). */
  readonly userinfo: boolean;
  readonly url: string;
  readonly origin: string;
}

export interface SqlSubAction {
  readonly kind: 'sql';
  /** First keyword of the statement (main verb after a WITH clause), upper-case. */
  readonly verb: string;
  /** True when a top-level WHERE exists and is not a constant tautology (`1=1`, `true`). */
  readonly bounded: boolean;
  /** Statement text with comments replaced by spaces (for reasons). */
  readonly text: string;
}

export const GIT_OPERATIONS = ['push', 'delete', 'none'] as const;
export type GitOperationKind = (typeof GIT_OPERATIONS)[number];

export interface GitSubAction {
  readonly kind: 'git';
  readonly subcommand: string;
  readonly operation: GitOperationKind;
  /** Destination branch (`refs/heads/` stripped); null when it depends on repository state. */
  readonly branch: string | null;
  /** Push forces the update (`-f`, `--force`, `--force-with-lease`, `+refspec`, `--mirror`). */
  readonly force: boolean;
}

export interface PaymentSubAction {
  readonly kind: 'payment';
  readonly amount_cents: number;
  readonly currency: string;
}

export const DOMAIN_STATUSES = ['domain', 'none', 'ambiguous'] as const;
export type DomainStatus = (typeof DOMAIN_STATUSES)[number];

/** One message recipient (a comma-separated `to` yields one sub-action per recipient). */
export interface MessageSubAction {
  readonly kind: 'message';
  readonly channel: MessageChannel;
  readonly recipient: string;
  /** `domain` = a domain was parsed; `none` = no domain (phone, #channel); `ambiguous` = cannot be decided. */
  readonly domain_status: DomainStatus;
  /** Lower-cased domain (webhook: URL hostname); null unless domain_status is `domain`. */
  readonly domain: string | null;
  /** Webhook URL with userinfo. */
  readonly userinfo: boolean;
}

export type SubAction =
  | CommandSubAction
  | FsSubAction
  | HttpSubAction
  | SqlSubAction
  | GitSubAction
  | PaymentSubAction
  | MessageSubAction;

/** Result of normalising one action. */
export interface Normalised {
  readonly subs: readonly SubAction[];
  readonly opaque: readonly OpaqueFinding[];
}

/**
 * Mutable accumulator shared by every part of one action's normalisation (wrapper recursion, substitutions,
 * redirects): one step budget, one node counter, one output list.
 */
export interface Accumulator {
  readonly context: EvaluationContext;
  readonly budget: StepBudget;
  readonly subs: SubAction[];
  readonly opaque: OpaqueFinding[];
  /** Sub-command nodes produced so far (cap MAX_SUBCOMMAND_NODES). */
  nodes: number;
}

/** A scanned shell argument as the argument parsers see it. */
export interface ArgWord {
  /** Value with quotes removed and context variables (`~`, `$HOME`) resolved; other expansions kept verbatim. */
  readonly text: string;
  /** Contains an expansion the lexical analysis cannot resolve (`$X`, `$(…)`, backticks, `~user`, `$'…'`). */
  readonly dynamic: boolean;
  /** Contains an unquoted glob or brace-expansion character (`*`, `?`, `[`, `{a,b}`). */
  readonly wildcard: boolean;
}

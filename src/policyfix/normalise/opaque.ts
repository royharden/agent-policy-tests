// Opaque findings and the per-action analysis budget (PLAN A6, A10; Claude §2.5 "Fail closed").
// Anything the bounded lexical analysis cannot see into becomes an OpaqueFinding; the guard turns every finding into an
// `ask` from the fixed built-in `opaque-construct` rule. A visible deny elsewhere in the same action still wins.
// Framework-free.
import { MAX_ANALYSIS_STEPS } from '../limits';

/** Stable reason codes (they appear in guard reasons and reports). */
export const OPAQUE_CODES = [
  'dialect-unsupported', // PowerShell / cmd until M5
  'dynamic-command', // $VAR / $(…) / backticks / glob in command position
  'eval', // eval, source, `.`
  'inline-code', // python -c, node -e, perl -e, …
  'stdin-script', // sh / bash / python reading a script from stdin (`… | sh`)
  'dynamic-operand', // non-context variable or substitution in a path / URL / argument that decides the verdict
  'wildcard-operand', // unquoted glob or brace expansion in a file operand (the expansion depends on the filesystem)
  'opaque-path', // UNC, \\?\, drive-relative, ~user, NUL
  'unparsable-url',
  'unparsable-recipient',
  'dynamic-sql', // EXEC, EXECUTE, DO, PREPARE
  'sql-syntax', // unterminated literal or comment
  'unknown-git', // unknown git subcommand (possible alias) or global option
  'git-dynamic', // variable inside a git push/branch argument
  'shell-syntax', // unterminated quote, unbalanced parenthesis, here-document, function definition, control structure
  'wrapper-depth', // more than MAX_WRAPPER_DEPTH nested shell wrappers
  'node-budget', // more than MAX_SUBCOMMAND_NODES sub-command nodes
  'step-budget', // more than MAX_ANALYSIS_STEPS scanner + glob steps
  'indirect-exec', // xargs, find -exec/-delete, env -S, npx -c, su -c
  'evaluator-error', // a rule could not be evaluated (invalid match, unexpected exception)
] as const;
export type OpaqueCode = (typeof OPAQUE_CODES)[number];

export interface OpaqueFinding {
  readonly code: OpaqueCode;
  /** Human-readable detail naming the construct. */
  readonly detail: string;
}

export function opaqueFinding(code: OpaqueCode, detail: string): OpaqueFinding {
  return { code, detail };
}

/** Steps shared by the scanner and the glob matcher for one action (PLAN A6: 20,000). */
export interface StepBudget {
  used: number;
  readonly max: number;
  exhausted: boolean;
}

export function createBudget(max: number = MAX_ANALYSIS_STEPS): StepBudget {
  return { used: 0, max, exhausted: false };
}

/** Spends `steps`; returns false (and marks the budget exhausted) once the cap is exceeded. */
export function spend(budget: StepBudget, steps = 1): boolean {
  if (budget.exhausted) return false;
  budget.used += steps;
  if (budget.used > budget.max) {
    budget.exhausted = true;
    return false;
  }
  return true;
}

/**
 * Thrown inside the scanner when a budget is exceeded; caught at the dialect entry point, which keeps every
 * sub-action produced so far (a visible deny still wins) and records an opaque finding.
 */
export class AnalysisLimitError extends Error {
  readonly code: OpaqueCode;

  constructor(code: OpaqueCode, detail: string) {
    super(detail);
    this.code = code;
    this.name = 'AnalysisLimitError';
  }
}

/** Spend or throw: the scanner's per-character check. */
export function spendOrThrow(budget: StepBudget, steps = 1): void {
  if (!spend(budget, steps)) {
    throw new AnalysisLimitError('step-budget', `analysis exceeded ${budget.max} steps`);
  }
}

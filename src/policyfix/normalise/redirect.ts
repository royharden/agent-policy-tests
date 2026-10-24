// Shell redirections → fs sub-actions (PLAN M3 AC3; Claude §2.5 "Shell redirections"; RUBRIC §3 Q02/Q05).
// posix forms (this milestone): `>`, `>>`, `>|`, `2>`, `&>`, `&>>`, `>&file`, `<`, `<>`. PowerShell/cmd forms are added
// in M5 through the same RedirectSpec.
//   - a literal target becomes `fs{op: write}` (`>`, `>>`, …) or `fs{op: read}` (`<`); `<>` yields both;
//   - a target with an unresolved expansion (`> "$F"`) is opaque → ask; a wildcard target is evaluated literally and
//     recorded as opaque;
//   - fd duplications (`2>&1`, `>&-`) and here-strings (`<<< data`) touch no file;
//   - the standard device files (`/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/stdin`, `/dev/tty`, `/dev/zero`,
//     `/dev/random`, `/dev/urandom`, `/dev/fd/N`) are not filesystem writes for this policy (documented in GRAMMAR.md).
// Framework-free.
import { addOpaque, emitFsWord } from './emit';
import type { Accumulator, ArgWord } from './types';

export const REDIRECT_OPS = ['read', 'write', 'append', 'readwrite', 'dup', 'herestring'] as const;
export type RedirectOp = (typeof REDIRECT_OPS)[number];

export interface RedirectSpec {
  readonly op: RedirectOp;
  /** Operator as written (`>`, `2>>`, `&>`, …), for reasons. */
  readonly operator: string;
  readonly target: ArgWord | null;
}

export const POSIX_DEVICE_TARGETS: readonly string[] = [
  '/dev/null',
  '/dev/stdout',
  '/dev/stderr',
  '/dev/stdin',
  '/dev/tty',
  '/dev/zero',
  '/dev/random',
  '/dev/urandom',
];

export function isPosixDeviceTarget(text: string): boolean {
  if (POSIX_DEVICE_TARGETS.includes(text)) return true;
  if (!text.startsWith('/dev/fd/')) return false;
  const rest = text.slice('/dev/fd/'.length);
  return rest.length > 0 && [...rest].every((ch) => ch >= '0' && ch <= '9');
}

/** Emits the fs effect of one redirection. `isDevice` lets each dialect name its own device files. */
export function emitRedirect(
  acc: Accumulator,
  redirect: RedirectSpec,
  isDevice: (text: string) => boolean = isPosixDeviceTarget,
): void {
  if (redirect.op === 'dup') return;
  if (redirect.op === 'herestring') {
    addOpaque(acc, 'dynamic-operand', 'here-string input is outside the supported redirection grammar');
    return;
  }
  const target = redirect.target;
  if (target === null) {
    addOpaque(acc, 'shell-syntax', `redirect "${redirect.operator}" has no target`);
    return;
  }
  if (target.dynamic) {
    addOpaque(acc, 'dynamic-operand', `redirect "${redirect.operator}" target "${target.text}" is not a literal`);
    return;
  }
  if (isDevice(target.text)) return;
  const origin = `redirect ${redirect.operator}`;
  if (redirect.op === 'read' || redirect.op === 'readwrite') emitFsWord(acc, 'read', target, 'plain', origin);
  if (redirect.op !== 'read') emitFsWord(acc, 'write', target, 'plain', origin);
}

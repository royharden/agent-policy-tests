// git argv analysis (PLAN M3 AC4; Claude §2.5 "git"; RUBRIC §3 Q08/Q09). Shared by `git` actions and `git …` shell
// commands. No repository state is ever read.
//   - global options before the subcommand (`-C dir`, `-c k=v`, `--git-dir=…`, `--no-pager`, …) are skipped; an unknown
//     global option or an unknown subcommand (possible alias, e.g. `git pom`) is opaque → ask;
//   - push: flags anywhere before `--` (GNU permutation), short clusters (`-fu`), unique long-option abbreviations;
//     force = `-f`, `--force`, `--force-with-lease[=…]`, `--force-if-includes`, `--mirror`, or a `+`-prefixed refspec;
//     the first operand is the remote, the rest are refspecs; `src:dst` uses `dst`, `:dst` deletes, `refs/heads/` is
//     stripped; `--delete`/`-d` turns every refspec into a deletion;
//   - a destination that depends on repository state (no refspec, `HEAD`, `@`, `--all`, `--mirror`, `--tags`, wildcard
//     refspecs) has branch null → the git-release template asks;
//   - `git branch -d|-D|--delete <names>` deletes local branches;
//   - every other known subcommand yields one `none` operation (not restricted by the templates).
// Framework-free, no regex.
import { expandLongPrefix } from './flags';
import { type OpaqueFinding, opaqueFinding } from './opaque';
import type { GitOperationKind } from './types';

export interface GitOperation {
  readonly subcommand: string;
  readonly operation: GitOperationKind;
  readonly branch: string | null;
  readonly force: boolean;
}

export interface GitAnalysis {
  readonly subcommand: string;
  readonly operations: readonly GitOperation[];
  readonly opaque: readonly OpaqueFinding[];
}

/** Subcommands the analysis recognises (porcelain + common plumbing). Anything else may be an alias → ask. */
export const KNOWN_GIT_SUBCOMMANDS: readonly string[] = [
  'add', 'am', 'annotate', 'apply', 'archive', 'bisect', 'blame', 'branch', 'bundle', 'cat-file', 'check-ignore',
  'checkout', 'cherry', 'cherry-pick', 'citool', 'clean', 'clone', 'commit', 'config', 'count-objects', 'describe',
  'diff', 'difftool', 'fetch', 'format-patch', 'fsck', 'gc', 'grep', 'gui', 'help', 'init', 'log', 'ls-files',
  'ls-remote', 'ls-tree', 'maintenance', 'merge', 'merge-base', 'mergetool', 'mv', 'notes', 'prune', 'pull', 'push',
  'range-diff', 'rebase', 'reflog', 'remote', 'repack', 'replace', 'rerere', 'reset', 'restore', 'rev-list', 'rev-parse',
  'revert', 'rm', 'shortlog', 'show', 'show-branch', 'show-ref', 'sparse-checkout', 'stash', 'status', 'submodule',
  'switch', 'tag', 'version', 'whatchanged', 'worktree',
];

// `--opt value` or `--opt=value`. (`--exec-path` takes its value only attached, so it is a flag option below.)
const GLOBAL_VALUE_OPTIONS: readonly string[] = ['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--config-env'];
const GLOBAL_FLAG_OPTIONS: readonly string[] = [
  '--no-pager', '-P', '-p', '--paginate', '--bare', '--no-replace-objects', '--literal-pathspecs', '--glob-pathspecs',
  '--noglob-pathspecs', '--icase-pathspecs', '--no-optional-locks', '--version', '--help', '--html-path', '--man-path',
  '--info-path', '--exec-path', '--no-advice',
];

const PUSH_LONG_OPTIONS: readonly string[] = [
  '--all', '--branches', '--mirror', '--tags', '--follow-tags', '--no-follow-tags', '--delete', '--force',
  '--force-with-lease', '--no-force-with-lease', '--force-if-includes', '--no-force-if-includes', '--set-upstream',
  '--dry-run', '--porcelain', '--prune', '--no-verify', '--verify', '--atomic', '--no-atomic', '--signed', '--no-signed',
  '--repo', '--push-option', '--receive-pack', '--exec', '--recurse-submodules', '--no-recurse-submodules', '--thin',
  '--no-thin', '--quiet', '--verbose', '--progress', '--no-progress', '--ipv4', '--ipv6',
];
const PUSH_VALUE_LONG: readonly string[] = ['--repo', '--push-option', '--receive-pack', '--exec'];
const PUSH_VALUE_SHORT: readonly string[] = ['-o'];
const FORCE_LONG: readonly string[] = ['--force', '--force-with-lease', '--force-if-includes'];
const UNKNOWN_DESTINATION_LONG: readonly string[] = ['--all', '--branches', '--mirror', '--tags'];

const BRANCH_DELETE_FLAGS: readonly string[] = ['-d', '-D', '--delete'];
const BRANCH_LONG_OPTIONS: readonly string[] = [
  '--delete', '--force', '--move', '--copy', '--list', '--all', '--remotes', '--verbose', '--quiet', '--track',
  '--no-track', '--set-upstream-to', '--unset-upstream', '--contains', '--no-contains', '--merged', '--no-merged',
  '--column', '--no-column', '--sort', '--points-at', '--format', '--color', '--no-color', '--abbrev', '--no-abbrev',
  '--edit-description', '--create-reflog', '--ignore-case', '--show-current', '--recurse-submodules',
];

/** Strips `refs/heads/`; returns null when the destination cannot be determined lexically. */
function destinationBranch(ref: string): string | null {
  if (ref === '' || ref === 'HEAD' || ref === '@' || ref.includes('*')) return null;
  if (ref.startsWith('refs/heads/')) return ref.slice('refs/heads/'.length);
  return ref;
}

interface Refspec {
  readonly force: boolean;
  readonly delete: boolean;
  readonly branch: string | null;
}

function parseRefspec(spec: string): Refspec {
  let text = spec;
  let force = false;
  if (text.startsWith('+')) {
    force = true;
    text = text.slice(1);
  }
  const colon = text.indexOf(':');
  if (colon < 0) return { force, delete: false, branch: destinationBranch(text) };
  const src = text.slice(0, colon);
  const dst = text.slice(colon + 1);
  if (src === '' && dst !== '') return { force, delete: true, branch: destinationBranch(dst) };
  return { force, delete: false, branch: destinationBranch(dst === '' ? src : dst) };
}

function classifyLong(name: string, known: readonly string[]): string | 'ambiguous-force' | 'ambiguous' {
  const resolved = expandLongPrefix(name, known);
  if (resolved.kind === 'exact' || resolved.kind === 'prefix') return resolved.name;
  if (resolved.kind === 'ambiguous') {
    return resolved.candidates.every((candidate) => FORCE_LONG.includes(candidate) || candidate.startsWith('--no-force'))
      ? 'ambiguous-force'
      : 'ambiguous';
  }
  return name;
}

function analysePush(args: readonly string[], dynamic: readonly boolean[], offset: number): GitAnalysis {
  let force = false;
  let deleteMode = false;
  let unknownDestination = false;
  let explicitRemote = false;
  const operands: string[] = [];
  const opaque: OpaqueFinding[] = [];
  let endOfOptions = false;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i] ?? '';
    if (dynamic[offset + i] === true) {
      opaque.push(opaqueFinding('git-dynamic', `git push argument "${arg}" contains a variable`));
      continue;
    }
    if (endOfOptions || !arg.startsWith('-') || arg === '-') {
      operands.push(arg);
      continue;
    }
    if (arg === '--') {
      endOfOptions = true;
      continue;
    }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      const name = classifyLong(eq >= 0 ? arg.slice(0, eq) : arg, PUSH_LONG_OPTIONS);
      if (name === 'ambiguous-force') {
        force = true;
        continue;
      }
      if (name === 'ambiguous') {
        opaque.push(opaqueFinding('unknown-git', `ambiguous git push option "${arg}"`));
        continue;
      }
      if (!PUSH_LONG_OPTIONS.includes(name)) {
        opaque.push(opaqueFinding('unknown-git', `unsupported git push option "${arg}"`));
        continue;
      }
      if (FORCE_LONG.includes(name)) force = true;
      if (name === '--mirror') force = true;
      if (UNKNOWN_DESTINATION_LONG.includes(name)) unknownDestination = true;
      if (name === '--delete') deleteMode = true;
      if (name === '--repo') explicitRemote = true;
      if (eq < 0 && PUSH_VALUE_LONG.includes(name)) {
        if (args[i + 1] === undefined) opaque.push(opaqueFinding('unknown-git', `git push ${name} has no value`));
        i += 1;
      }
      continue;
    }
    for (let j = 1; j < arg.length; j += 1) {
      const flag = `-${arg.charAt(j)}`;
      if (flag === '-f') force = true;
      if (flag === '-d') deleteMode = true;
      if (!['-f', '-d', '-u', '-n', '-q', '-v', '-4', '-6', '-o'].includes(flag)) {
        opaque.push(opaqueFinding('unknown-git', `unsupported git push option "${flag}"`));
      }
      if (PUSH_VALUE_SHORT.includes(flag)) {
        if (j === arg.length - 1) i += 1;
        break;
      }
    }
  }
  const refspecs = explicitRemote ? operands : operands.slice(1);
  const operations: GitOperation[] = [];
  if (refspecs.length === 0 || unknownDestination) {
    operations.push({ subcommand: 'push', operation: deleteMode ? 'delete' : 'push', branch: null, force });
  }
  for (const spec of refspecs) {
    if (deleteMode) {
      operations.push({ subcommand: 'push', operation: 'delete', branch: destinationBranch(spec.startsWith('+') ? spec.slice(1) : spec), force });
      continue;
    }
    const parsed = parseRefspec(spec);
    operations.push({
      subcommand: 'push',
      operation: parsed.delete ? 'delete' : 'push',
      branch: parsed.branch,
      force: force || parsed.force,
    });
  }
  return { subcommand: 'push', operations, opaque };
}

function analyseBranch(args: readonly string[], dynamic: readonly boolean[], offset: number): GitAnalysis {
  let deleting = false;
  const names: string[] = [];
  const opaque: OpaqueFinding[] = [];
  let endOfOptions = false;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i] ?? '';
    if (dynamic[offset + i] === true) {
      opaque.push(opaqueFinding('git-dynamic', `git branch argument "${arg}" contains a variable`));
      continue;
    }
    if (endOfOptions || !arg.startsWith('-') || arg === '-') {
      names.push(arg);
      continue;
    }
    if (arg === '--') {
      endOfOptions = true;
      continue;
    }
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      const name = classifyLong(eq >= 0 ? arg.slice(0, eq) : arg, BRANCH_LONG_OPTIONS);
      if (name === '--delete') deleting = true;
      continue;
    }
    for (let j = 1; j < arg.length; j += 1) {
      if (BRANCH_DELETE_FLAGS.includes(`-${arg.charAt(j)}`)) deleting = true;
    }
  }
  if (!deleting) return { subcommand: 'branch', operations: [{ subcommand: 'branch', operation: 'none', branch: null, force: false }], opaque };
  if (names.length === 0) return { subcommand: 'branch', operations: [], opaque };
  return {
    subcommand: 'branch',
    operations: names.map((name) => ({ subcommand: 'branch', operation: 'delete', branch: destinationBranch(name), force: false })),
    opaque,
  };
}

/**
 * Analyses git argv (everything after `git`). `dynamic[i]` marks shell words containing an unresolved expansion.
 */
export function analyseGitArgs(args: readonly string[], dynamic: readonly boolean[] = []): GitAnalysis {
  let i = 0;
  while (i < args.length) {
    const arg = args[i] ?? '';
    if (dynamic[i] === true) {
      return { subcommand: '', operations: [], opaque: [opaqueFinding('git-dynamic', `git argument "${arg}" contains a variable`)] };
    }
    if (!arg.startsWith('-')) break;
    const eq = arg.indexOf('=');
    const name = eq >= 0 ? arg.slice(0, eq) : arg;
    if (GLOBAL_VALUE_OPTIONS.includes(name)) {
      i += eq >= 0 ? 1 : 2;
      continue;
    }
    if (GLOBAL_FLAG_OPTIONS.includes(name)) {
      i += 1;
      continue;
    }
    return { subcommand: '', operations: [], opaque: [opaqueFinding('unknown-git', `unknown git global option "${arg}"`)] };
  }
  const subcommand = args[i];
  if (subcommand === undefined) {
    return { subcommand: '', operations: [{ subcommand: '', operation: 'none', branch: null, force: false }], opaque: [] };
  }
  if (!KNOWN_GIT_SUBCOMMANDS.includes(subcommand)) {
    return {
      subcommand,
      operations: [],
      opaque: [opaqueFinding('unknown-git', `unknown git subcommand "${subcommand}" (possibly an alias)`)],
    };
  }
  const rest = args.slice(i + 1);
  if (subcommand === 'push') return analysePush(rest, dynamic, i + 1);
  if (subcommand === 'branch') return analyseBranch(rest, dynamic, i + 1);
  return { subcommand, operations: [{ subcommand, operation: 'none', branch: null, force: false }], opaque: [] };
}

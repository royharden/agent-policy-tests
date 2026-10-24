// Template destructive-shell-fs (Q02 outside-root deletes/writes, Q03 recursive/force deletes inside the root with
// root-level exceptions, Q04 privilege elevation; free text: a command or path to forbid). RUBRIC §3 Q02–Q04.
// Rules match fs sub-actions (from fs actions, rm/rmdir/unlink operands, redirects, tee, cp/mv destinations, …) and
// command sub-actions (after wrapper unwrapping), so evasions such as `rm -fr`, `\rm`, `bash -c '…'` and
// `./node_modules/../src` are decided on the normalised form.
// PowerShell `Start-Process -Verb RunAs` elevation is added with the PowerShell normaliser in M5.
// Framework-free.
import type { Rule } from '../action';
import type { EvaluationContext } from '../context';
import { instantiateGlob } from '../glob';
import { MAX_COMMAND_CHARS } from '../limits';
import { normaliseAction } from '../normalise/index';
import { canonicalisePath, joinContextPath, siblingOfRoot } from '../normalise/path';
import type { CommandSubAction } from '../normalise/types';
import type { Answers } from '../questionnaire';
import {
  type AnswerOutcome,
  cleanList,
  type CompiledRule,
  type DeclaredExample,
  type FreeTextParams,
  fsAction,
  permitted,
  type PolicyTemplate,
  prohibited,
  sh,
  slug,
} from './common';

const TEMPLATE = 'destructive-shell-fs' as const;

export const DESTRUCTIVE_FIELDS = {
  'fs.op': ['eq', 'in'],
  'fs.inside_root': ['eq'],
  'fs.mode': ['eq', 'in'],
  'fs.root_relative': ['glob'],
  'fs.path': ['glob', 'prefix'],
  'command.name': ['command_name'],
  'command.words': ['prefix'],
  'command.flags': ['flags_include'],
} as const;

export const ELEVATION_NAMES: readonly string[] = ['sudo', 'doas', 'runas'];

function isPosix(context: EvaluationContext): boolean {
  return context.path_flavor === 'posix';
}

function inRoot(context: EvaluationContext, ...parts: readonly string[]): string {
  return joinContextPath(context, context.project_root, ...parts);
}

function outsideSibling(context: EvaluationContext, ...parts: readonly string[]): string {
  return joinContextPath(context, siblingOfRoot(context, '-evil'), ...parts);
}

/** Exception entry → root-relative glob patterns (`node_modules` → `node_modules`, `node_modules/**`). */
export function exceptionPatterns(except: readonly string[]): string[] {
  const out: string[] = [];
  for (const raw of cleanList(except)) {
    let entry = raw.split('\\').join('/');
    while (entry.startsWith('./')) entry = entry.slice(2);
    while (entry.endsWith('/')) entry = entry.slice(0, -1);
    if (entry.length === 0) continue;
    out.push(entry, `${entry}/**`);
  }
  return out;
}

function q02Rule(context: EvaluationContext): CompiledRule {
  const rule: Rule = {
    id: 'q02-outside-root-delete-write',
    source_answer: 'Q02',
    template: TEMPLATE,
    effect: 'deny',
    match: [
      { op: 'in', field: 'fs.op', values: ['delete', 'write'] },
      { op: 'eq', field: 'fs.inside_root', value: false },
    ],
    intent: 'Never delete or write anything outside the project root.',
  };
  const examples: DeclaredExample[] = isPosix(context)
    ? [
        prohibited('p1', sh('rm -rf /tmp/policy-check'), 'deny', 'Recursive delete of an absolute path outside the root.'),
        prohibited('p2', fsAction('write', outsideSibling(context, 'notes.txt')), 'deny', 'Sibling directory sharing the root prefix is outside (segment boundary).', 'path-traversal'),
        prohibited('p3', sh('echo x >> ~/.bashrc'), 'deny', 'Redirect appends to a file in the home directory.'),
        permitted('n1', fsAction('write', inRoot(context, 'src', 'app.ts')), 'Write inside the root.'),
        permitted('n2', fsAction('read', '/etc/hosts'), 'Reads outside the root are not restricted by Q02.'),
        permitted('n3', sh('rm ./tmp/notes.txt'), 'Plain delete inside the root.', 'near-miss-permitted'),
      ]
    : [
        prohibited('p1', fsAction('delete', joinContextPath(context, context.home, 'Documents'), true), 'deny', 'Recursive delete in the home directory, outside the root.'),
        prohibited('p2', fsAction('write', outsideSibling(context, 'notes.txt')), 'deny', 'Sibling directory sharing the root prefix is outside (segment boundary).', 'path-traversal'),
        permitted('n1', fsAction('write', inRoot(context, 'src', 'app.ts')), 'Write inside the root.'),
        permitted('n2', fsAction('read', joinContextPath(context, context.home, 'notes.txt')), 'Reads outside the root are not restricted by Q02.'),
      ];
  return { rule, parameters: ['Q01'], examples };
}

function q03Rule(answers: Answers, context: EvaluationContext): CompiledRule {
  const patterns = exceptionPatterns(answers.Q03.except);
  const rule: Rule = {
    id: 'q03-recursive-force-delete-in-root',
    source_answer: 'Q03',
    template: TEMPLATE,
    effect: 'deny',
    match: [
      { op: 'eq', field: 'fs.op', value: 'delete' },
      { op: 'eq', field: 'fs.inside_root', value: true },
      { op: 'in', field: 'fs.mode', values: ['recursive', 'force', 'recursive-force'] },
      ...(patterns.length > 0 ? [{ op: 'glob' as const, field: 'fs.root_relative', patterns, negate: true }] : []),
    ],
    intent:
      patterns.length > 0
        ? `Never delete recursively or with force inside the project root, except under ${cleanList(answers.Q03.except).join(', ')}.`
        : 'Never delete recursively or with force inside the project root.',
  };
  const exception = cleanList(answers.Q03.except)[0];
  const exceptionDir = exception === undefined ? undefined : instantiateGlob(exception.split('\\').join('/'), 'policy-test');
  const examples: DeclaredExample[] = [];
  if (isPosix(context)) {
    examples.push(
      prohibited('p1', sh('rm -rf ./build'), 'deny', 'Recursive force delete of a non-exception directory.'),
      prohibited('p2', sh('rm -f ./coverage/lcov.info'), 'deny', 'Force alone counts (Q03 covers recursive OR force).'),
      prohibited('p3', sh('rm -r --force ./src'), 'deny', 'Split long-form flags.', 'flag-reorder'),
    );
    if (exceptionDir !== undefined) {
      examples.push(
        prohibited('p4', sh(`rm -rf ./${exceptionDir}/../src`), 'deny', 'Traversal out of an exception directory lands on src.', 'path-traversal'),
        permitted('n1', sh(`rm -rf ./${exceptionDir}`), 'Root-level exception directory.', 'near-miss-permitted'),
      );
    }
    examples.push(
      permitted('n2', sh('rm ./tmp/notes.txt'), 'Plain (non-recursive, non-force) delete inside the root.', 'near-miss-permitted'),
      permitted('n3', fsAction('delete', inRoot(context, 'tmp', 'notes.txt')), 'Plain fs delete inside the root.'),
    );
  } else {
    examples.push(
      prohibited('p1', fsAction('delete', inRoot(context, 'build'), true), 'deny', 'Recursive delete of a non-exception directory.'),
      prohibited('p2', fsAction('delete', inRoot(context, 'src'), true), 'deny', 'Recursive delete of the source tree.'),
    );
    if (exceptionDir !== undefined) {
      examples.push(permitted('n1', fsAction('delete', inRoot(context, ...exceptionDir.split('/')), true), 'Root-level exception directory.', 'near-miss-permitted'));
    }
    examples.push(permitted('n2', fsAction('delete', inRoot(context, 'tmp', 'notes.txt')), 'Plain fs delete inside the root.'));
    if (exceptionDir === undefined) {
      examples.push(permitted('n3', fsAction('write', inRoot(context, 'src', 'app.ts')), 'A write is not a delete.'));
    }
  }
  return { rule, parameters: ['Q01'], examples };
}

function q04Rule(): CompiledRule {
  const rule: Rule = {
    id: 'q04-privilege-elevation',
    source_answer: 'Q04',
    template: TEMPLATE,
    effect: 'deny',
    match: [{ op: 'command_name', field: 'command.name', names: [...ELEVATION_NAMES] }],
    intent: 'Never elevate privileges (sudo, doas, runas).',
  };
  const examples: DeclaredExample[] = [
    prohibited('p1', sh('sudo -n true'), 'deny', 'Any sudo invocation is elevation, whatever it runs.'),
    prohibited('p2', sh('doas ls'), 'deny', 'doas is elevation.'),
    prohibited('p3', sh('ls -la && sudo whoami'), 'deny', 'Elevation chained after a benign command.', 'chained'),
    permitted('n1', sh('grep -c sudo docs/setup.md'), 'The word sudo as data.', 'near-miss-permitted'),
    permitted('n2', sh('echo "never use sudo here"'), 'The word sudo inside an echo string.', 'near-miss-permitted'),
  ];
  return { rule, parameters: [], examples };
}

function compile(answers: Answers, context: EvaluationContext): readonly AnswerOutcome[] {
  const posix = isPosix(context);
  return [
    answers.Q02.block
      ? { source_answer: 'Q02', disposition: 'restricted', rules: [q02Rule(context)], witnesses: [], reason: 'Deletes and writes outside the root are denied.' }
      : {
          source_answer: 'Q02',
          disposition: 'not-restricted',
          rules: [],
          witnesses: [
            permitted('w1', fsAction('delete', outsideSibling(context, 'notes.txt')), 'Q02 off: deletes outside the root are allowed.'),
            permitted('w2', fsAction('write', outsideSibling(context, 'notes.txt')), 'Q02 off: writes outside the root are allowed.'),
          ],
          reason: 'Answered "no restriction".',
        },
    answers.Q03.block
      ? { source_answer: 'Q03', disposition: 'restricted', rules: [q03Rule(answers, context)], witnesses: [], reason: 'Recursive/force deletes inside the root are denied outside the exceptions.' }
      : {
          source_answer: 'Q03',
          disposition: 'not-restricted',
          rules: [],
          witnesses: [
            permitted('w1', fsAction('delete', inRoot(context, 'build'), true), 'Q03 off: recursive deletes inside the root are allowed.'),
            posix
              ? permitted('w2', sh('rm -rf ./build'), 'Q03 off: rm -rf inside the root is allowed.')
              : permitted('w2', fsAction('delete', inRoot(context, 'src'), true), 'Q03 off: recursive deletes inside the root are allowed.'),
          ],
          reason: 'Answered "no restriction".',
        },
    answers.Q04.block
      ? { source_answer: 'Q04', disposition: 'restricted', rules: [q04Rule()], witnesses: [], reason: 'Privilege elevation is denied.' }
      : {
          source_answer: 'Q04',
          disposition: 'not-restricted',
          rules: [],
          witnesses: [
            permitted('w1', sh('sudo -n true'), 'Q04 off: sudo is allowed.'),
            permitted('w2', sh('doas ls'), 'Q04 off: doas is allowed.'),
          ],
          reason: 'Answered "no restriction".',
        },
  ];
}

/** A deliberately small literal command subset; values/expressions we cannot preserve in the match stay manual. */
function freeTextCommand(command: string, context: EvaluationContext): CommandSubAction | null {
  if (command.length > MAX_COMMAND_CHARS - 20) return null; // Leave room for the declared wrapper/chain examples.
  for (const ch of command) {
    const alnum = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
    if (!alnum && !' _-./:@+'.includes(ch)) return null;
  }
  const words = command.split(' ').filter((word) => word.length > 0);
  if (words.includes('--')) return null; // Flag-looking literal operands need a richer match representation.
  const normalised = normaliseAction(sh(command), context);
  const commands = normalised.subs.filter((sub): sub is CommandSubAction => sub.kind === 'command');
  const only = commands[0];
  if (normalised.opaque.length > 0 || commands.length !== 1 || only === undefined || only.name !== words[0]) return null;
  // Only rm's recursive/force switches have supported flag semantics here. Its aliases are canonicalised by the
  // same normaliser used by the guard, so -rf, -fr, -R -f and --recursive --force compile to the same predicates.
  if (only.flags.length > 0 && (only.name !== 'rm' || only.flags.some((flag) => flag !== '-r' && flag !== '-f'))) return null;
  return only;
}

/** Escape a canonical literal path before embedding it in the glob language (context paths are literals too). */
function literalPathPattern(path: string): string {
  let pattern = '';
  for (const ch of path) {
    if ('\\*?[]'.includes(ch)) pattern += '\\';
    pattern += ch;
  }
  return pattern;
}

function compileFreeText(id: string, text: string, params: FreeTextParams, context: EvaluationContext): CompiledRule | null {
  const command = params.command?.trim();
  if (command !== undefined && command.length > 0) {
    const normalised = freeTextCommand(command, context);
    if (normalised === null) return null;
    const words = normalised.words;
    const first = normalised.name;
    const rule: Rule = {
      id: `ft-${slug(id)}-command`,
      source_answer: `freetext:${id}`,
      template: TEMPLATE,
      effect: 'deny',
      match: [
        { op: 'prefix', field: 'command.words', prefixes: [words.join(' ')] },
        ...(normalised.flags.length > 0
          ? [{ op: 'flags_include' as const, field: 'command.flags', flags: [...normalised.flags] }]
          : []),
      ],
      intent: `Never run "${command}" (free text: ${text}).`,
    };
    return {
      rule,
      parameters: [],
      examples: [
        prohibited('p1', sh(command), 'deny', 'The command itself, including its required flags.'),
        prohibited('p2', sh(`ls && ${command}`), 'deny', 'Chained after a benign command.', 'chained'),
        prohibited('p3', sh(`bash -c '${command}'`), 'deny', 'Inside a literal bash -c string.', 'shell-wrapper'),
        permitted('n1', sh(`${first === 'echo' ? 'printf' : 'echo'} "${command}"`), 'The command as data.', 'near-miss-permitted'),
        permitted('n2', sh(first === 'true' ? 'false' : 'true'), 'An unrelated command.', 'near-miss-permitted'),
      ],
    };
  }
  const path = params.path?.trim();
  if (path !== undefined && path.length > 0) {
    const operations = params.fs_ops ?? (/^never write (?!or )/i.test(text) ? ['write'] as const : /^never delete (?!or )/i.test(text) ? ['delete'] as const : ['delete', 'write'] as const);
    if (operations.length === 0 || operations.some((op) => op !== 'delete' && op !== 'write')) return null;
    // `path` is a literal target, not a glob or shell expression. Only leading context-home references expand.
    if ([...path].some((ch) => '*?[`\n\r'.includes(ch))) return null;
    const canonical = canonicalisePath(path, context, { expandHome: true });
    if (!canonical.ok || canonical.path.key.includes('{') || canonical.path.key.includes('}')) return null;
    const pattern = literalPathPattern(canonical.path.key);
    const descendants = `${pattern.endsWith('/') ? pattern : `${pattern}/`}**`;
    if (descendants.length > MAX_COMMAND_CHARS) return null;
    const rule: Rule = {
      id: `ft-${slug(id)}-path`,
      source_answer: `freetext:${id}`,
      template: TEMPLATE,
      effect: 'deny',
      match: [
        { op: 'in', field: 'fs.op', values: [...operations] },
        { op: 'glob', field: 'fs.path', patterns: [pattern, descendants] },
      ],
      intent: `Never ${operations.join(' or ')} ${path} (free text: ${text}).`,
    };
    return {
      rule,
      parameters: ['Q01'],
      examples: [
        prohibited('p1', fsAction(operations[0] ?? 'write', path), 'deny', 'Requested operation on the exact path.'),
        prohibited('p2', fsAction(operations[0] ?? 'write', joinContextPath(context, path, 'policy-test.txt')), 'deny', 'Requested operation beneath the path.'),
        permitted('n1', fsAction('read', path), 'Reading is not restricted by this line.'),
        permitted('n2', fsAction('list', path), 'Listing is not restricted by this line.'),
      ],
    };
  }
  return null;
}

export const destructiveShellFsTemplate: PolicyTemplate = {
  id: TEMPLATE,
  title: 'Destructive shell and filesystem actions',
  answers: ['Q02', 'Q03', 'Q04'],
  fields: DESTRUCTIVE_FIELDS,
  conflicts: [
    { owner_template: 'secrets-paths', effect: 'deny', reason: 'A permitted delete or write may touch a secret path (e.g. rm -rf ./node_modules/.env).' },
    {
      owner_template: 'destructive-shell-fs',
      effect: 'deny',
      reason: 'Q02, Q03 and Q04 overlap: a near-miss permitted by one rule (a plain delete inside the root, a sudo-free command) may be blocked by a sibling rule.',
    },
  ],
  compile,
  compileFreeText,
};

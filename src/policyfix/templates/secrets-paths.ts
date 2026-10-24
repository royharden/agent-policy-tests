// Template secrets-paths (Q05 secret globs + exceptions; free text: one more secret glob). RUBRIC §3 Q05.
//   - any read, write or delete of a matching path is denied (listing a directory is not a read);
//   - globs without `/` match the final path segment anywhere (inside or outside the root: `~/.ssh/id_ed25519`);
//   - globs with `/` are anchored at the project root (`secrets/**` = everything below `<root>/secrets`);
//   - globs starting with `/`, a drive letter or `~` match the canonical absolute path;
//   - matching is case-folded on every platform (`.Env`, `server.PEM`);
//   - exceptions are part of the predicate (negated nodes in the same rule), not a later allow: `.env.example` is
//     excepted by its exact final segment, `.env.example.bak` is still a secret.
// Framework-free.
import type { MatchNode, Rule } from '../action';
import type { EvaluationContext } from '../context';
import { instantiateGlob } from '../glob';
import { joinContextPath } from '../normalise/path';
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

const TEMPLATE = 'secrets-paths' as const;

export const SECRETS_FIELDS = {
  'fs.op': ['eq', 'in'],
  'fs.name_ci': ['glob', 'in', 'eq'],
  'fs.root_relative_ci': ['glob'],
  'fs.path_ci': ['glob'],
} as const;

const TOUCHING_OPS = ['read', 'write', 'delete'];

function isPosix(context: EvaluationContext): boolean {
  return context.path_flavor === 'posix';
}

function inRoot(context: EvaluationContext, ...parts: readonly string[]): string {
  return joinContextPath(context, context.project_root, ...parts);
}

function isAbsoluteGlob(glob: string): boolean {
  const c0 = glob.charAt(0);
  return c0 === '/' || c0 === '~' || (glob.charAt(1) === ':' && ((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z')));
}

/** Absolute glob → the `/`-separated canonical key form match.ts compares against (`C:/x`, `/home/dev/x`). */
function absoluteKeyGlob(glob: string, context: EvaluationContext): string {
  let text = glob.split('\\').join('/');
  if (text === '~' || text.startsWith('~/')) text = context.home.split('\\').join('/') + text.slice(1);
  if (text.charAt(1) === ':') text = text.charAt(0).toUpperCase() + text.slice(1);
  return text;
}

function rootRelativeGlob(glob: string): string {
  let text = glob.split('\\').join('/');
  while (text.startsWith('./')) text = text.slice(2);
  return text;
}

interface SecretSpec {
  readonly names: readonly string[];
  readonly rootPaths: readonly string[];
  readonly absolutePaths: readonly string[];
  readonly nameExceptions: readonly string[];
  readonly pathExceptions: readonly string[];
}

function splitSpec(globs: readonly string[], exceptions: readonly string[], context: EvaluationContext): SecretSpec {
  const names: string[] = [];
  const rootPaths: string[] = [];
  const absolutePaths: string[] = [];
  for (const glob of cleanList(globs)) {
    if (isAbsoluteGlob(glob)) absolutePaths.push(absoluteKeyGlob(glob, context));
    else if (glob.includes('/') || glob.includes('\\')) rootPaths.push(rootRelativeGlob(glob));
    else names.push(glob);
  }
  const nameExceptions: string[] = [];
  const pathExceptions: string[] = [];
  for (const exception of cleanList(exceptions)) {
    if (exception.includes('/') || exception.includes('\\')) pathExceptions.push(rootRelativeGlob(exception));
    else nameExceptions.push(exception);
  }
  return { names, rootPaths, absolutePaths, nameExceptions, pathExceptions };
}

function exceptionNodes(spec: SecretSpec): MatchNode[] {
  const nodes: MatchNode[] = [];
  if (spec.nameExceptions.length > 0) {
    nodes.push({ op: 'in', field: 'fs.name_ci', values: [...spec.nameExceptions], negate: true });
  }
  if (spec.pathExceptions.length > 0) {
    nodes.push({ op: 'glob', field: 'fs.root_relative_ci', patterns: [...spec.pathExceptions], negate: true });
  }
  return nodes;
}

function isException(name: string, spec: SecretSpec): boolean {
  return spec.nameExceptions.some((exception) => exception.toLowerCase() === name.toLowerCase());
}

/** A concrete name the glob matches that is not an exception. */
function concreteName(glob: string, spec: SecretSpec): string {
  for (const fill of ['policy-test', 'local', 'x1']) {
    const candidate = instantiateGlob(glob, fill);
    if (!isException(candidate, spec)) return candidate;
  }
  return instantiateGlob(glob, 'policy-test');
}

function nameExamples(spec: SecretSpec, context: EvaluationContext): DeclaredExample[] {
  const glob = spec.names[0] ?? '.env';
  const name = concreteName(glob, spec);
  const secondGlob = spec.names[1] ?? glob;
  const second = concreteName(secondGlob, spec);
  const upper = name.toUpperCase();
  const examples: DeclaredExample[] = [];
  if (isPosix(context)) {
    examples.push(
      prohibited('p1', sh(`cat ./${name}`), 'deny', `Reads ${name} in the root.`),
      prohibited('p2', sh(`echo x > ./config/${name}`), 'deny', 'A redirect writes a secret name.'),
    );
  } else {
    examples.push(
      prohibited('p1', fsAction('read', inRoot(context, name)), 'deny', `Reads ${name} in the root.`),
      prohibited('p2', fsAction('write', inRoot(context, 'config', name)), 'deny', 'Writes a secret name.'),
    );
  }
  examples.push(
    prohibited('p3', fsAction('read', joinContextPath(context, context.home, '.ssh', second)), 'deny', 'Name globs match anywhere, also outside the root.'),
  );
  if (upper !== name) {
    examples.push(prohibited('p4', fsAction('read', inRoot(context, 'config', upper)), 'deny', 'Secret names are case-folded on every platform.', 'case-fold'));
  }
  const exception = spec.nameExceptions[0];
  if (exception !== undefined) {
    examples.push(
      isPosix(context)
        ? permitted('n1', sh(`cat ./${exception}`), 'The declared exception.', 'near-miss-permitted')
        : permitted('n1', fsAction('read', inRoot(context, exception)), 'The declared exception.', 'near-miss-permitted'),
    );
  }
  examples.push(permitted('n2', fsAction('read', inRoot(context, 'README.md')), 'A non-secret file.'));
  if (isPosix(context)) {
    examples.push(permitted('n3', sh(`echo "${name} files must never be committed"`), 'The name only as data.', 'near-miss-permitted'));
  } else {
    examples.push(permitted('n3', fsAction('list', inRoot(context, 'config')), 'Listing a directory is not a read of its files.'));
  }
  return examples;
}

function rootPathExamples(spec: SecretSpec, context: EvaluationContext): DeclaredExample[] {
  const relative = instantiateGlob(spec.rootPaths[0] ?? 'secrets/**', 'policy-test.txt');
  const segments = relative.split('/').filter((segment) => segment.length > 0);
  const first = segments[0] ?? 'secrets';
  return [
    isPosix(context)
      ? prohibited('p1', sh(`cat ./${relative}`), 'deny', 'Reads below the anchored secret path.')
      : prohibited('p1', fsAction('read', inRoot(context, ...segments)), 'deny', 'Reads below the anchored secret path.'),
    prohibited('p2', fsAction('write', inRoot(context, ...segments)), 'deny', 'Writes below the anchored secret path.'),
    isPosix(context)
      ? permitted('n1', sh(`cat ./${first}/../README.md`), 'Traversal back out of the secret directory.', 'path-traversal')
      : permitted('n1', fsAction('read', inRoot(context, first, '..', 'README.md')), 'Traversal back out of the secret directory.', 'path-traversal'),
    permitted('n2', fsAction('read', joinContextPath(context, context.home, ...segments)), 'The same relative path outside the root is not anchored there.'),
  ];
}

function absoluteExamples(spec: SecretSpec, context: EvaluationContext): DeclaredExample[] {
  const target = instantiateGlob(spec.absolutePaths[0] ?? '/', 'policy-test');
  return [
    prohibited('p1', fsAction('read', target), 'deny', 'Reads the absolute secret path.'),
    prohibited('p2', fsAction('write', target), 'deny', 'Writes the absolute secret path.'),
    permitted('n1', fsAction('read', inRoot(context, 'README.md')), 'A non-secret file.'),
    permitted('n2', fsAction('list', target), 'Listing is not a read.'),
  ];
}

function secretRules(idPrefix: string, source: Rule['source_answer'], spec: SecretSpec, context: EvaluationContext, label: string): CompiledRule[] {
  const exceptions = exceptionNodes(spec);
  const exceptionText = [...spec.nameExceptions, ...spec.pathExceptions];
  const suffix = exceptionText.length > 0 ? ` (except ${exceptionText.join(', ')})` : '';
  const rules: CompiledRule[] = [];
  if (spec.names.length > 0) {
    rules.push({
      rule: {
        id: `${idPrefix}-secret-name`,
        source_answer: source,
        template: TEMPLATE,
        effect: 'deny',
        match: [{ op: 'in', field: 'fs.op', values: TOUCHING_OPS }, { op: 'glob', field: 'fs.name_ci', patterns: [...spec.names] }, ...exceptions],
        intent: `Never read, write or delete files named ${spec.names.join(', ')}${suffix}${label}.`,
      },
      parameters: [],
      examples: nameExamples(spec, context),
    });
  }
  if (spec.rootPaths.length > 0) {
    rules.push({
      rule: {
        id: `${idPrefix}-secret-root-path`,
        source_answer: source,
        template: TEMPLATE,
        effect: 'deny',
        match: [{ op: 'in', field: 'fs.op', values: TOUCHING_OPS }, { op: 'glob', field: 'fs.root_relative_ci', patterns: [...spec.rootPaths] }, ...exceptions],
        intent: `Never read, write or delete ${spec.rootPaths.join(', ')} under the project root${suffix}${label}.`,
      },
      parameters: ['Q01'],
      examples: rootPathExamples(spec, context),
    });
  }
  if (spec.absolutePaths.length > 0) {
    rules.push({
      rule: {
        id: `${idPrefix}-secret-absolute-path`,
        source_answer: source,
        template: TEMPLATE,
        effect: 'deny',
        match: [{ op: 'in', field: 'fs.op', values: TOUCHING_OPS }, { op: 'glob', field: 'fs.path_ci', patterns: [...spec.absolutePaths] }, ...exceptions],
        intent: `Never read, write or delete ${spec.absolutePaths.join(', ')}${suffix}${label}.`,
      },
      parameters: ['Q01'],
      examples: absoluteExamples(spec, context),
    });
  }
  return rules;
}

function compile(answers: Answers, context: EvaluationContext): readonly AnswerOutcome[] {
  const spec = splitSpec(answers.Q05.secret_globs, answers.Q05.exceptions, context);
  const rules = secretRules('q05', 'Q05', spec, context, '');
  if (rules.length === 0) {
    return [
      {
        source_answer: 'Q05',
        disposition: 'not-restricted',
        rules: [],
        witnesses: [
          permitted('w1', fsAction('read', inRoot(context, '.env')), 'Q05 empty: no path is secret.'),
          permitted('w2', fsAction('read', joinContextPath(context, context.home, '.ssh', 'id_ed25519')), 'Q05 empty: key files are not protected.'),
        ],
        reason: 'No secret globs were given (a deny-list answered empty).',
      },
    ];
  }
  return [{ source_answer: 'Q05', disposition: 'restricted', rules, witnesses: [], reason: 'Reads, writes and deletes of secret paths are denied.' }];
}

function compileFreeText(id: string, text: string, params: FreeTextParams, context: EvaluationContext): CompiledRule | null {
  const glob = (params.glob ?? params.path)?.trim();
  if (glob === undefined || glob.length === 0) return null;
  const spec = splitSpec([glob], params.except ?? [], context);
  const rules = secretRules(`ft-${slug(id)}`, `freetext:${id}`, spec, context, ` (free text: ${text})`);
  return rules[0] ?? null;
}

export const secretsPathsTemplate: PolicyTemplate = {
  id: TEMPLATE,
  title: 'Secret paths',
  answers: ['Q05'],
  fields: SECRETS_FIELDS,
  conflicts: [
    { owner_template: 'destructive-shell-fs', effect: 'deny', reason: 'A permitted near-miss that writes or deletes outside the root (or recursively inside it) is blocked by Q02/Q03.' },
  ],
  compile,
  compileFreeText,
};

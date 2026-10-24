// Template git-release (Q08 force push, Q09 protected branches, Q10 publish/deploy commands; free text: one more
// protected branch). RUBRIC §3 Q08–Q10.
//   - rules match git sub-actions produced from `git` actions and `git …` shell commands after refspec parsing:
//     `HEAD:main` pushes to main, `+main` forces, `:main` / `--delete main` / `git branch -D main` delete;
//   - a push whose destination depends on repository state (bare `git push`, `git push origin`, `HEAD`) asks;
//   - `*` in a branch glob does not cross `/` (release/* matches release/2026.10, not release-notes);
//   - publish/deploy commands are matched on the normalised command words, so global flags before the subcommand
//     (`terraform -chdir=infra apply`) and wrappers (`npx vercel --prod`, `bash -c 'npm publish'`) are seen;
//     `npm publish --dry-run`, `npm pack`, `terraform plan`, `gh release view` are not publishes.
// Framework-free.
import type { Rule, RuleEffect } from '../action';
import type { EvaluationContext } from '../context';
import { instantiateGlob } from '../glob';
import type { Answers } from '../questionnaire';
import {
  type AnswerOutcome,
  cleanList,
  type CompiledRule,
  type DeclaredExample,
  type FreeTextParams,
  gitAction,
  permitted,
  type PolicyTemplate,
  prohibited,
  sh,
  slug,
} from './common';

const TEMPLATE = 'git-release' as const;
const WITNESS_BRANCH = 'feature/policy-witness';

export const GIT_FIELDS = {
  'git.subcommand': ['eq'],
  'git.operation': ['eq', 'in'],
  'git.force': ['eq'],
  'git.branch': ['glob'],
  'git.branch_known': ['eq'],
  'command.words': ['prefix'],
  'command.name': ['command_name'],
  'command.flags': ['flags_include'],
} as const;

function q08Rule(): CompiledRule {
  return {
    rule: {
      id: 'q08-force-push',
      source_answer: 'Q08',
      template: TEMPLATE,
      effect: 'deny',
      match: [
        { op: 'eq', field: 'git.subcommand', value: 'push' },
        { op: 'eq', field: 'git.force', value: true },
      ],
      intent: 'Never force push (any branch).',
    },
    parameters: [],
    examples: [
      prohibited('p1', gitAction('push', '--force', 'origin', WITNESS_BRANCH), 'deny', 'Explicit --force.'),
      prohibited('p2', gitAction('push', 'origin', `+${WITNESS_BRANCH}`), 'deny', 'A + refspec forces the update.', 'refspec-trick'),
      prohibited('p3', gitAction('push', 'origin', WITNESS_BRANCH, '-f'), 'deny', 'Flag after the operands.', 'flag-reorder'),
      prohibited('p4', sh(`git push --force-with-lease origin ${WITNESS_BRANCH}`), 'deny', '--force-with-lease is a force push.'),
      prohibited('p5', gitAction('push', '--force', '--delete', 'origin', WITNESS_BRANCH), 'deny', 'A forced remote deletion is still a push.'),
      prohibited('p6', gitAction('push', '--force', 'origin', `:${WITNESS_BRANCH}`), 'deny', 'A forced deletion refspec is still a push.', 'refspec-trick'),
      permitted('n1', gitAction('push', 'origin', WITNESS_BRANCH), 'A normal push.', 'near-miss-permitted'),
      permitted('n2', gitAction('commit', '-m', 'chore: never force push'), 'Force push mentioned as data.', 'near-miss-permitted'),
      permitted('n3', gitAction('fetch', '--force', 'origin'), 'A forced fetch is not a push.', 'near-miss-permitted'),
      permitted('n4', gitAction('branch', '-D', WITNESS_BRANCH), 'Force-deleting a local branch is not a push.', 'near-miss-permitted'),
    ],
  };
}

function protectedRule(id: string, source: Rule['source_answer'], branches: readonly string[], label: string): CompiledRule {
  const first = instantiateGlob(branches[0] ?? 'main', 'policy-test');
  const second = branches[1] === undefined ? undefined : instantiateGlob(branches[1], 'policy-test');
  const examples: DeclaredExample[] = [
    prohibited('p1', gitAction('push', 'origin', `HEAD:${first}`), 'deny', 'The destination after the colon is protected.', 'refspec-trick'),
    prohibited('p2', gitAction('push', 'origin', '--delete', first), 'deny', 'Deleting a protected branch.'),
    prohibited('p3', gitAction('push', 'origin', `:${first}`), 'deny', 'An empty source deletes the destination.', 'refspec-trick'),
    prohibited('p4', gitAction('branch', '-D', first), 'deny', 'Deleting the local protected branch.'),
    prohibited('p5', sh(`git push origin ${first}`), 'deny', 'Push to the protected branch from a shell command.'),
  ];
  if (second !== undefined) {
    examples.push(prohibited('p6', gitAction('push', 'origin', `refs/heads/${second}`), 'deny', 'refs/heads/ is stripped before the glob test.'));
  }
  examples.push(
    permitted('n1', gitAction('push', 'origin', WITNESS_BRANCH), 'An unprotected branch.', 'near-miss-permitted'),
    permitted('n2', gitAction('push', 'origin', `${first}:${WITNESS_BRANCH}`), 'The source is protected; the destination is not.', 'refspec-trick'),
    permitted('n3', gitAction('branch', '-d', 'feature/old-ui'), 'Deleting an unprotected local branch.', 'near-miss-permitted'),
  );
  return {
    rule: {
      id,
      source_answer: source,
      template: TEMPLATE,
      effect: 'deny',
      match: [
        { op: 'in', field: 'git.operation', values: ['push', 'delete'] },
        { op: 'glob', field: 'git.branch', patterns: [...branches] },
      ],
      intent: `Never push to, force-update or delete ${branches.join(', ')}${label}.`,
    },
    parameters: [],
    examples,
  };
}

function unknownDestinationRule(): CompiledRule {
  return {
    rule: {
      id: 'q09-push-destination-unknown',
      source_answer: 'Q09',
      template: TEMPLATE,
      effect: 'ask',
      match: [
        { op: 'in', field: 'git.operation', values: ['push', 'delete'] },
        { op: 'eq', field: 'git.branch_known', value: false },
      ],
      intent: 'Ask before a push whose destination depends on repository state (it may be a protected branch).',
    },
    parameters: [],
    examples: [
      prohibited('p1', gitAction('push'), 'ask', 'Bare git push.'),
      prohibited('p2', gitAction('push', 'origin'), 'ask', 'Remote without a refspec.'),
      prohibited('p3', gitAction('push', 'origin', 'HEAD'), 'ask', 'HEAD depends on the checked-out branch.', 'refspec-trick'),
      permitted('n1', gitAction('push', 'origin', WITNESS_BRANCH), 'An explicit destination.'),
      permitted('n2', gitAction('fetch', 'origin'), 'Not a push.'),
    ],
  };
}

interface PublishCommand {
  readonly id: string;
  readonly label: string;
  readonly match: Rule['match'];
  readonly prohibited: readonly [string, string, ...string[]];
  readonly permitted: readonly [string, string, ...string[]];
}

const PUBLISH_COMMANDS: readonly PublishCommand[] = [
  {
    id: 'q10-npm-publish',
    label: 'npm publish (except --dry-run)',
    match: [
      { op: 'prefix', field: 'command.words', prefixes: ['npm publish'] },
      { op: 'flags_include', field: 'command.flags', flags: ['--dry-run'], negate: true },
    ],
    prohibited: ['npm publish', 'npm publish --access public', "bash -c 'npm publish'"],
    permitted: ['npm publish --dry-run', 'npm pack', 'npm run publish-docs'],
  },
  {
    id: 'q10-vercel-prod',
    label: 'vercel --prod',
    match: [
      { op: 'command_name', field: 'command.name', names: ['vercel'] },
      { op: 'flags_include', field: 'command.flags', flags: ['--prod'] },
    ],
    prohibited: ['vercel --prod', 'vercel deploy --prod', 'npx vercel --prod'],
    permitted: ['vercel', 'vercel deploy'],
  },
  {
    id: 'q10-terraform-apply',
    label: 'terraform apply',
    match: [{ op: 'prefix', field: 'command.words', prefixes: ['terraform apply'] }],
    prohibited: ['terraform apply', 'terraform -chdir=infra apply -auto-approve'],
    permitted: ['terraform plan -out=tfplan', 'terraform validate'],
  },
  {
    id: 'q10-gh-release-create',
    label: 'gh release create',
    match: [{ op: 'prefix', field: 'command.words', prefixes: ['gh release create'] }],
    prohibited: ['gh release create v1.0.0', 'gh release create v1.0.0 --repo demo/app --notes x'],
    permitted: ['gh release view v1.0.0', 'gh pr create --fill'],
  },
];

function publishRules(effect: RuleEffect): CompiledRule[] {
  return PUBLISH_COMMANDS.map((command) => ({
    rule: {
      id: command.id,
      source_answer: 'Q10',
      template: TEMPLATE,
      effect,
      match: command.match,
      intent: `${effect === 'deny' ? 'Never run' : 'Ask before running'} ${command.label}.`,
    },
    parameters: [],
    examples: [
      ...command.prohibited.map((text, index) => prohibited(`p${index + 1}`, sh(text), effect, `Publish/deploy command: ${text}.`)),
      ...command.permitted.map((text, index) => permitted(`n${index + 1}`, sh(text), `Not a publish: ${text}.`, 'near-miss-permitted')),
    ],
  }));
}

function compile(answers: Answers, _context: EvaluationContext): readonly AnswerOutcome[] {
  const branches = cleanList(answers.Q09.branches);
  return [
    answers.Q08.block
      ? { source_answer: 'Q08', disposition: 'restricted', rules: [q08Rule()], witnesses: [], reason: 'Force pushes are denied.' }
      : {
          source_answer: 'Q08',
          disposition: 'not-restricted',
          rules: [],
          witnesses: [
            permitted('w1', gitAction('push', '--force', 'origin', WITNESS_BRANCH), 'Q08 off: force push is allowed.'),
            permitted('w2', gitAction('push', 'origin', `+${WITNESS_BRANCH}`), 'Q08 off: + refspecs are allowed.'),
          ],
          reason: 'Answered "no restriction".',
        },
    branches.length > 0
      ? {
          source_answer: 'Q09',
          disposition: 'restricted',
          rules: [protectedRule('q09-protected-branch-update', 'Q09', branches, ''), unknownDestinationRule()],
          witnesses: [],
          reason: 'Pushes to and deletions of protected branches are denied; unknown destinations ask.',
        }
      : {
          source_answer: 'Q09',
          disposition: 'not-restricted',
          rules: [],
          witnesses: [
            permitted('w1', gitAction('push', 'origin', 'main'), 'Q09 empty: no branch is protected.'),
            permitted('w2', gitAction('branch', '-D', 'main'), 'Q09 empty: deleting main is allowed.'),
          ],
          reason: 'No protected branches were given (a deny-list answered empty).',
        },
    answers.Q10.mode === 'none'
      ? {
          source_answer: 'Q10',
          disposition: 'not-restricted',
          rules: [],
          witnesses: [
            permitted('w1', sh('npm publish'), 'Q10 none: publishing is allowed.'),
            permitted('w2', sh('terraform apply'), 'Q10 none: applying is allowed.'),
          ],
          reason: 'Answered "no restriction".',
        }
      : {
          source_answer: 'Q10',
          disposition: 'restricted',
          rules: publishRules(answers.Q10.mode),
          witnesses: [],
          reason: `Publish/deploy commands: ${answers.Q10.mode}.`,
        },
  ];
}

function compileFreeText(id: string, text: string, params: FreeTextParams, _context: EvaluationContext): CompiledRule | null {
  const branch = params.branch?.trim();
  if (branch === undefined || branch.length === 0) return null;
  return protectedRule(`ft-${slug(id)}-branch`, `freetext:${id}`, [branch], ` (free text: ${text})`);
}

export const gitReleaseTemplate: PolicyTemplate = {
  id: TEMPLATE,
  title: 'Git and release',
  answers: ['Q08', 'Q09', 'Q10'],
  fields: GIT_FIELDS,
  conflicts: [
    { owner_template: 'git-release', effect: 'deny', reason: 'Q08 and Q09 overlap: a permitted push near-miss of one may be a force push or a protected-branch push for the other.' },
    { owner_template: 'git-release', effect: 'ask', reason: 'A permitted push near-miss whose destination depends on repository state asks (q09-push-destination-unknown).' },
    { owner_template: 'destructive-shell-fs', effect: 'deny', reason: 'A permitted publish near-miss run under sudo is denied by Q04.' },
  ],
  compile,
  compileFreeText,
};

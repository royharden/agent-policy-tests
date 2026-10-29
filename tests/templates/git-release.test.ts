import { describe, expect, it } from 'vitest';
import { compileOrThrow, expectTemplateExamplesHold, reference, referenceOutput, verdictOf } from '../helpers/reference';
import { guard } from '../../src/policyfix/guard';

describe('git-release template', () => {
  it('ships truthful isolation examples for push, branch and release rules', () => {
    // what_bug_this_catches: refspec and release predicates failing their own declared prohibited/permitted examples.
    expectTemplateExamplesHold(referenceOutput('posix'), 'git-release');
  });

  it.each([
    { args: ['push', '--force', '--delete', 'origin', 'feature/demo'] },
    { args: ['push', '--force', 'origin', ':feature/demo'] },
    { args: ['push', 'origin', '+:feature/demo'] },
  ])('denies force pushes even when the operation is a remote deletion: $args', ({ args }) => {
    // what_bug_this_catches: Q08 checking operation=push misses forced remote deletes normalized as operation=delete.
    const direct = verdictOf('posix', { kind: 'git', args });
    expect(direct.verdict).toBe('deny');
    expect(direct.rule_id).toBe('q08-force-push');
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: `git ${args.join(' ')}` }).rule_id).toBe('q08-force-push');
  });

  it('keeps local branch deletion governed by branch protection, independently of force-push policy', () => {
    // what_bug_this_catches: broadening Q08 to every delete with a force flag would conflate local and remote actions.
    expect(verdictOf('posix', { kind: 'git', args: ['branch', '-D', 'feature/demo'] }).verdict).toBe('allow');
    expect(verdictOf('posix', { kind: 'git', args: ['branch', '-D', 'main'] }).rule_id).toBe('q09-protected-branch-update');
    expect(verdictOf('posix', { kind: 'git', args: ['push', '--delete', 'origin', 'feature/demo'] }).verdict).toBe('allow');
  });

  it.each(['npm publish', 'terraform -chdir=infra apply', 'npx vercel --prod', 'gh release create v1'])('denies the release command %s', (command) => {
    // what_bug_this_catches: flags before subcommands or wrappers hiding a release operation.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command }).verdict).toBe('deny');
  });

  it.each(['npm publish --dry-run', 'npm pack', 'terraform plan', 'gh release view v1', 'terraform destroy'])('permits the scoped near-miss %s', (command) => {
    // what_bug_this_catches: over-broad release prefix rules blocking operations the questionnaire never restricted.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command }).verdict).toBe('allow');
  });

  it('compiles ask mode and free-text branch parameters without requiring a live classifier', () => {
    // what_bug_this_catches: ignoring the publish effect or accepting a classified line without compiling its target.
    const ref = reference('posix');
    const output = compileOrThrow({ ...ref.answers, Q10: { mode: 'ask' } }, ref.context, [{ id: 'hotfix', text: 'never push to the hotfix branch', label: 'git-release', params: { branch: 'hotfix' } }]);
    expect(guard(output.policy, { kind: 'shell', dialect: 'posix', command: 'npm publish' }, ref.context).verdict).toBe('ask');
    expect(guard(output.policy, { kind: 'git', args: ['push', 'origin', 'HEAD:hotfix'] }, ref.context).verdict).toBe('deny');
  });
});

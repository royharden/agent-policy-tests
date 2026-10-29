import { describe, expect, it } from 'vitest';
import { analyseGitArgs } from '../../src/policyfix/normalise/git';
import { verdictOf } from '../helpers/reference';

describe('git destination parsing', () => {
  it.each([
    [['push', 'origin', '+main'], 'push', 'main', true],
    [['push', 'origin', 'HEAD:main'], 'push', 'main', false],
    [['push', 'origin', ':main'], 'delete', 'main', false],
    [['push', '--delete', 'origin', 'refs/heads/main'], 'delete', 'main', false],
    [['branch', '-D', 'main'], 'delete', 'main', false],
    [['push', '--repo=origin', 'HEAD:main'], 'push', 'main', false],
  ] as const)('extracts operations from %j', (args, operation, branch, force) => {
    // what_bug_this_catches: checking source refs or dropping delete/force markers misses protected destination updates.
    expect(analyseGitArgs(args).operations).toContainEqual(expect.objectContaining({ operation, branch, force }));
  });

  it('distinguishes source from destination and asks for state-dependent or unsupported syntax', () => {
    // what_bug_this_catches: a protected source creates a false positive; unknown destinations/options must not become allow.
    expect(verdictOf('posix', { kind: 'git', args: ['push', 'origin', 'main:feature/demo'] }).verdict).toBe('allow');
    for (const args of [['push'], ['push', 'origin', 'HEAD'], ['pom'], ['push', '--unknown', 'origin', 'feature/demo']]) {
      expect(verdictOf('posix', { kind: 'git', args }).verdict).toBe('ask');
    }
  });
});

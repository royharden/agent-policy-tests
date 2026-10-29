import { describe, expect, it } from 'vitest';
import { normaliseAction } from '../../src/policyfix/normalise/index';
import { createBudget } from '../../src/policyfix/normalise/opaque';
import { reference, verdictOf } from '../helpers/reference';

describe('posix scanner and effects', () => {
  it.each([
    'rm -fr src', 'rm src --recursive --force', '\\rm -rf src',
    'MODE=test env command nohup rm -rf src', "bash -lc 'rm -rf src'",
    'true || rm -rf src', 'echo ok | rm -rf src', 'echo "$(rm -rf src)"', 'echo `rm -rf src`',
  ])('finds the delete in %s', (command) => {
    // what_bug_this_catches: wrapper, flag-order or chained-command spellings bypassing the same recursive-delete restriction.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command }).verdict).toBe('deny');
  });

  it('respects quotes and escapes without treating command names in data as effects', () => {
    // what_bug_this_catches: substring matching fabricating a delete from quoted text, or splitting a quoted file at spaces.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'echo "rm -rf /"' }).verdict).toBe('allow');
    const result = normaliseAction({ kind: 'shell', dialect: 'posix', command: 'cat "docs/a b.md" docs/c\\ d.md' }, reference('posix').context);
    expect(result.opaque).toEqual([]);
    expect(result.subs.filter((sub) => sub.kind === 'fs').map((sub) => sub.path.root_relative)).toEqual(['docs/a b.md', 'docs/c d.md']);
  });

  it.each(['$CMD src', 'source ./setup.sh', 'python3 -c "print(1)"', 'echo code | sh', 'cat "$BUILD_DIR/file"', 'echo "unterminated', 'cd ../other; rm -rf dist', 'env -C ../other rm -rf dist'])('asks for unsupported or context-changing input: %s', (command) => {
    // what_bug_this_catches: uncertain code, paths or changed cwd falling through to an apparently harmless exception.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command }).verdict).toBe('ask');
  });

  it('caps shell-wrapper depth, nodes and scanner work', () => {
    // what_bug_this_catches: nesting and long chains exhausting the analyzer without producing an opaque ask.
    const wrap = (text: string): string => `bash -c '${text.replaceAll("'", "'\\''")}'`;
    const three = wrap(wrap(wrap('true')));
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: three }).verdict).toBe('allow');
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: wrap(three) }).verdict).toBe('ask');
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'true;'.repeat(129) }).verdict).toBe('ask');
    const limited = normaliseAction({ kind: 'shell', dialect: 'posix', command: 'echo hello' }, reference('posix').context, createBudget(2));
    expect(limited.opaque.some((finding) => finding.code === 'step-budget')).toBe(true);
  });
});

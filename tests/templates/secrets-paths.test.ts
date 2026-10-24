// Template secrets-paths (Q05): declared examples hold in isolation; RUBRIC Q05 rulings (PLAN M3 AC6).
import { describe, expect, it } from 'vitest';
import { compileOrThrow, expectTemplateExamplesHold, reference, referenceOutput, verdictOf } from '../helpers/reference';

const sh = (command: string): { kind: 'shell'; dialect: 'posix'; command: string } => ({ kind: 'shell', dialect: 'posix', command });

describe('secrets-paths template', () => {
  it('declares ≥2 prohibited and ≥2 permitted examples per rule that hold in isolation (posix and windows)', () => {
    // what_bug_this_catches: a secret rule whose examples disagree with its predicate (e.g. the exception compiled as a
    // later allow) would generate fixtures with the wrong expected verdict.
    expectTemplateExamplesHold(referenceOutput('posix'), 'secrets-paths');
    expectTemplateExamplesHold(referenceOutput('windows'), 'secrets-paths');
  });

  it('keeps .env.example permitted and .env.example.bak secret', () => {
    // what_bug_this_catches: the exception implemented as a prefix/substring would also excuse `.env.example.bak`.
    expect(verdictOf('posix', sh('cat .env.example')).verdict).toBe('allow');
    expect(verdictOf('posix', sh('cat .env.example.bak')).verdict).toBe('deny');
    expect(verdictOf('posix', sh('cat .ENV.EXAMPLE')).verdict).toBe('allow');
  });

  it('case-folds secret names on the case-sensitive posix context', () => {
    // what_bug_this_catches: folding only when context.case_insensitive_fs is true misses `server.PEM` on posix.
    expect(verdictOf('posix', { kind: 'fs', op: 'read', path: '/workspace/demo/certs/server.PEM' }).verdict).toBe('deny');
    expect(verdictOf('posix', sh('cat .Env')).verdict).toBe('deny');
  });

  it('matches slash-less globs anywhere and anchors secrets/** at the root', () => {
    // what_bug_this_catches: anchoring every glob at the root misses ~/.ssh/id_ed25519; not anchoring secrets/** blocks
    // ~/secrets/notes.txt and still needs traversal handling.
    expect(verdictOf('posix', sh('cat ~/.ssh/id_ed25519')).verdict).toBe('deny');
    expect(verdictOf('posix', sh('cat ./secrets/api.txt')).verdict).toBe('deny');
    expect(verdictOf('posix', sh('cat ./secrets/../README.md')).verdict).toBe('allow');
    expect(verdictOf('posix', { kind: 'fs', op: 'read', path: '/home/dev/secrets/notes.txt' }).verdict).toBe('allow');
  });

  it('does not treat lookalike names or names as data as secrets', () => {
    // what_bug_this_catches: substring matching on ".env" blocks `.envrc`, `env.ts` and an echo that only names the file.
    expect(verdictOf('posix', sh('less .envrc')).verdict).toBe('allow');
    expect(verdictOf('posix', sh('cat src/env.ts')).verdict).toBe('allow');
    expect(verdictOf('posix', sh('echo ".env files must never be committed"')).verdict).toBe('allow');
  });

  it('sees reads through traversal, substitution and copies', () => {
    // what_bug_this_catches: only checking the literal operand misses `./config/../.env.production`, `$(cat .env)` and
    // the write half of `cp .env.example .env.local`.
    expect(verdictOf('posix', sh('cat ./config/../.env.production')).verdict).toBe('deny');
    expect(verdictOf('posix', sh('echo "$(cat .env)"')).verdict).toBe('deny');
    expect(verdictOf('posix', sh('cp .env.example .env.local')).verdict).toBe('deny');
  });

  it('compiles an empty glob list to not-restricted with witnesses', () => {
    // what_bug_this_catches: an empty deny-list compiled to a match-everything rule (or to a silent drop with no
    // disposition) would either block every file or hide the answer.
    const ref = reference('posix');
    const output = compileOrThrow({ ...ref.answers, Q05: { secret_globs: [], exceptions: [] } }, ref.context);
    const entry = output.dispositions.find((candidate) => candidate.source_answer === 'Q05');
    expect(entry?.disposition).toBe('not-restricted');
    expect((output.witnesses['Q05'] ?? []).length).toBeGreaterThanOrEqual(2);
  });
});

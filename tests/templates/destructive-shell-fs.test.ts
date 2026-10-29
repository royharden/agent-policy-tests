// Template destructive-shell-fs (Q02/Q03/Q04): declared examples hold in isolation; key near-misses (PLAN M3 AC6).
import { describe, expect, it } from 'vitest';
import { guardInIsolation } from '../../src/policyfix/guard';
import { destructiveShellFsTemplate, exceptionPatterns } from '../../src/policyfix/templates/destructive-shell-fs';
import { TEMPLATES_BY_ID } from '../../src/policyfix/templates/index';
import { compileOrThrow, expectTemplateExamplesHold, reference, referenceOutput, verdictOf } from '../helpers/reference';

describe('destructive-shell-fs template', () => {
  it('declares ≥2 prohibited and ≥2 permitted examples per rule that hold in isolation (posix and windows)', () => {
    // what_bug_this_catches: a template rule whose declared examples do not match its own match nodes (a rule that
    // never fires, or fires on its near-misses) would feed M4 fixtures with wrong expectations.
    expectTemplateExamplesHold(referenceOutput('posix'), 'destructive-shell-fs');
    expectTemplateExamplesHold(referenceOutput('windows'), 'destructive-shell-fs');
  });

  it('allows the root-level exceptions and denies traversal out of them', () => {
    // what_bug_this_catches: exceptions matched by substring (`node_modules` anywhere) or before canonicalisation
    // would let `rm -rf ./node_modules/../src` delete the source tree.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'rm -rf ./node_modules' }).verdict).toBe('allow');
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'rm -fr dist .cache' }).verdict).toBe('allow');
    const traversal = verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'rm -rf ./node_modules/../src' });
    expect(traversal.verdict).toBe('deny');
    expect(traversal.rule_id).toBe('q03-recursive-force-delete-in-root');
  });

  it('treats rm -f alone as force and a plain rm inside the root as allowed', () => {
    // what_bug_this_catches: requiring both -r and -f (or only -r) for Q03 misses `rm -f ./coverage/lcov.info`.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'rm -f ./coverage/lcov.info' }).verdict).toBe('deny');
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'rm ./tmp/notes.txt' }).verdict).toBe('allow');
  });

  it('does not apply exceptions outside the root or to nested node_modules', () => {
    // what_bug_this_catches: exceptions matched on the final segment (`.cache` anywhere) would allow `rm -rf ~/.cache`
    // and `rm -rf ./packages/app/node_modules/../../src`.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'rm -rf ~/.cache' }).rule_id).toBe('q02-outside-root-delete-write');
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'rm -rf ./src/node_modules' }).verdict).toBe('deny');
  });

  it('uses a segment-boundary root test', () => {
    // what_bug_this_catches: a string-prefix root test treats /workspace/demo-evil as inside /workspace/demo.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'rm -rf /workspace/demo-evil' }).verdict).toBe('deny');
    expect(verdictOf('posix', { kind: 'fs', op: 'write', path: '/workspace/demo/src/a.ts' }).verdict).toBe('allow');
  });

  it('denies elevation even when the wrapped command is harmless, and not the word sudo as data', () => {
    // what_bug_this_catches: unwrapping sudo without emitting its own command sub-action would drop Q04 entirely.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'sudo -n true' }).rule_id).toBe('q04-privilege-elevation');
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command: 'grep -c sudo docs/setup.md' }).verdict).toBe('allow');
  });

  it('compiles Q03 without exceptions to a rule without the negated glob', () => {
    // what_bug_this_catches: an empty exception list compiled to `NOT glob []` is rejected by the schema (min 1) and
    // would make compile fail instead of restricting every recursive delete.
    const ref = reference('posix');
    const output = compileOrThrow({ ...ref.answers, Q03: { block: true, except: [] } }, ref.context);
    const rule = output.rules.find((candidate) => candidate.id === 'q03-recursive-force-delete-in-root');
    expect(rule?.match.some((node) => node.op === 'glob')).toBe(false);
    expect(exceptionPatterns(['./node_modules/', 'dist'])).toEqual(['node_modules', 'node_modules/**', 'dist', 'dist/**']);
  });

  it('declares conflict ownership for M4', () => {
    // what_bug_this_catches: without declarations, every composed block of a permitted near-miss (e.g. a delete of a
    // secret inside node_modules) would be an undeclared conflict.
    const owners = TEMPLATES_BY_ID['destructive-shell-fs'].conflicts.map((conflict) => conflict.owner_template);
    expect(owners).toContain('secrets-paths');
  });

  it('compiles a free-text command line to a deny rule on the command words', () => {
    // what_bug_this_catches: matching free-text commands as substrings would block `echo "terraform destroy"`.
    const ref = reference('posix');
    const output = compileOrThrow(ref.answers, ref.context, [
      { id: 'ft-1', text: 'never run terraform destroy', label: 'destructive-shell-fs', params: { command: 'terraform destroy' } },
    ]);
    expectTemplateExamplesHold(output, 'destructive-shell-fs');
    const ruleId = output.dispositions.find((entry) => entry.source_answer === 'freetext:ft-1')?.rule_ids[0];
    expect(ruleId).toBe('ft-ft-1-command');
  });

  it.each(['rm -rf', 'rm --recursive --force', 'rm -R -f'])('preserves required normalized flags for free-text %s', (command) => {
    // what_bug_this_catches: raw `rm -rf` prefixes never matched command.words because the normalizer strips flags;
    // dropping the flags from the predicate instead would wrongly deny plain rm.
    const ref = reference('posix');
    const output = compileOrThrow(ref.answers, ref.context, [
      { id: 'rm-flags', text: `never run ${command}`, label: 'destructive-shell-fs', params: { command } },
    ]);
    expectTemplateExamplesHold(output, 'destructive-shell-fs');
    const rule = output.rules.find((candidate) => candidate.id === 'ft-rm-flags-command');
    expect(rule).toBeDefined();
    if (rule === undefined) throw new Error('free-text rm rule missing');
    for (const invocation of ['rm -fr ./build', 'rm ./build -r -f', 'rm --force --recursive ./build', "bash -c 'rm -Rf ./build'"]) {
      expect(guardInIsolation(rule, { kind: 'shell', dialect: 'posix', command: invocation }, ref.context).verdict).toBe('deny');
    }
    for (const invocation of ['rm ./build', 'rm -r ./build', 'rm -f ./build', 'rmdir ./build', 'echo "rm -rf ./build"']) {
      expect(guardInIsolation(rule, { kind: 'shell', dialect: 'posix', command: invocation }, ref.context).verdict).toBe('allow');
    }
  });

  it('keeps literal command operands alongside required flags', () => {
    // what_bug_this_catches: fixing stripped flags by compiling only the command name would silently drop its target.
    const ref = reference('posix');
    const compiled = destructiveShellFsTemplate.compileFreeText('target', 'never run rm -rf ./build', { command: 'rm -rf ./build' }, ref.context);
    expect(compiled).not.toBeNull();
    if (compiled === null) throw new Error('free-text command missing');
    expect(guardInIsolation(compiled.rule, { kind: 'shell', dialect: 'posix', command: 'rm ./build -fr' }, ref.context).verdict).toBe('deny');
    expect(guardInIsolation(compiled.rule, { kind: 'shell', dialect: 'posix', command: 'rm -rf ./cache' }, ref.context).verdict).toBe('allow');
  });

  it.each(['echo', 'man', 'true'])('declares valid data and unrelated witnesses for a bare %s restriction', (command) => {
    // what_bug_this_catches: using the forbidden executable itself for a permitted example contradicts the rule.
    const ref = reference('posix');
    const output = compileOrThrow(ref.answers, ref.context, [
      { id: 'bare', text: `never run ${command}`, label: 'destructive-shell-fs', params: { command } },
    ]);
    expectTemplateExamplesHold(output, 'destructive-shell-fs');
  });

  it.each(['terraform -chdir=infra destroy', 'curl -X POST', 'rm --interactive=never', 'rm -x', 'rm "$BUILD"', 'rm *.log', 'rm ./build; echo done', 'bash -c "rm -rf ./build"'])('keeps unsupported free-text command forms manual: %s', (command) => {
    // what_bug_this_catches: accepting unrepresentable values, dynamic operands or compound syntax as an active rule
    // can produce a restriction that never fires or silently loses part of the intended condition.
    const ref = reference('posix');
    const output = compileOrThrow(ref.answers, ref.context, [
      { id: 'unsupported', text: `never run ${command}`, label: 'destructive-shell-fs', params: { command } },
    ]);
    expect(output.dispositions.find((entry) => entry.source_answer === 'freetext:unsupported')?.disposition).toBe('manual');
    expect(output.manual_items.some((item) => item.source_answer === 'freetext:unsupported')).toBe(true);
  });

  it.each([
    ['build', '/workspace/demo/packages/app/build'],
    ['./cache/../build', '/workspace/demo/packages/app/build'],
    ['../shared', '/workspace/demo/packages/shared'],
    ['~/archive', '/home/dev/archive'],
    ['$HOME/archive', '/home/dev/archive'],
    ['${HOME}/archive', '/home/dev/archive'],
    ['/', '/'],
  ])('canonicalizes the free-text literal path %s using the evaluation context', (path, absolute) => {
    // what_bug_this_catches: relative/home/traversal parameters compiled to raw globs miss absolute normalized fs.path;
    // a root target also needs a single separator before its descendant glob.
    const ref = reference('posix');
    const context = { ...ref.context, cwd: '/workspace/demo/packages/app' };
    const output = compileOrThrow({ ...ref.answers, Q01: { context } }, context, [
      { id: 'path', text: `never write or delete ${path}`, label: 'destructive-shell-fs', params: { path } },
    ]);
    const rule = output.rules.find((candidate) => candidate.id === 'ft-path-path');
    expect(rule).toBeDefined();
    if (rule === undefined) throw new Error('free-text path rule missing');
    expectTemplateExamplesHold({ ...output, rules: [rule] }, 'destructive-shell-fs');
    expect(guardInIsolation(rule, { kind: 'fs', op: 'write', path }, context).verdict).toBe('deny');
    expect(guardInIsolation(rule, { kind: 'fs', op: 'delete', path: absolute, recursive: true }, context).verdict).toBe('deny');
    const child = `${absolute.endsWith('/') ? absolute : `${absolute}/`}child.txt`;
    expect(guardInIsolation(rule, { kind: 'fs', op: 'write', path: child }, context).verdict).toBe('deny');
    expect(guardInIsolation(rule, { kind: 'fs', op: 'read', path: absolute }, context).verdict).toBe('allow');
    if (absolute !== '/') expect(guardInIsolation(rule, { kind: 'fs', op: 'write', path: `${absolute}-other` }, context).verdict).toBe('allow');
  });

  it('canonicalizes Windows relative and home parameters with context case folding', () => {
    // what_bug_this_catches: POSIX-only parameter fixes still miss Windows separators, traversal and home expansion.
    const ref = reference('windows');
    for (const path of ['.\\cache\\..\\build', '~\\archive', '%USERPROFILE%\\archive']) {
      const compiled = destructiveShellFsTemplate.compileFreeText('windows-path', `never write ${path}`, { path }, ref.context);
      expect(compiled).not.toBeNull();
      if (compiled === null) throw new Error('Windows free-text path rule missing');
      const target = path.startsWith('.') ? 'c:/WORKSPACE/demo/BUILD/child.txt' : 'c:/USERS/dev/ARCHIVE/child.txt';
      expect(guardInIsolation(compiled.rule, { kind: 'fs', op: 'write', path: target }, ref.context).verdict).toBe('deny');
    }
  });

  it.each(['$BUILD', '$HOME/$BUILD', '~another/build', '$(pwd)/build', '`pwd`/build', 'build/*', 'build/[ab]'])('keeps unsupported free-text paths manual: %s', (path) => {
    // what_bug_this_catches: a dynamic or unsupported path must not become a seemingly executable but ineffective rule.
    const ref = reference('posix');
    const output = compileOrThrow(ref.answers, ref.context, [
      { id: 'unsupported-path', text: `never write ${path}`, label: 'destructive-shell-fs', params: { path } },
    ]);
    expect(output.dispositions.find((entry) => entry.source_answer === 'freetext:unsupported-path')?.disposition).toBe('manual');
  });

  it.each(['C:build', '\\\\files.example.test\\share\\build', '\\\\?\\C:\\build'])('keeps opaque Windows free-text paths manual: %s', (path) => {
    // what_bug_this_catches: drive-relative, UNC and device targets cannot be resolved against the lexical context.
    expect(destructiveShellFsTemplate.compileFreeText('opaque-path', `never write ${path}`, { path }, reference('windows').context)).toBeNull();
  });
});

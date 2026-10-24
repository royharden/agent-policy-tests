import { describe, expect, it } from 'vitest';
import { normaliseAction } from '../../src/policyfix/normalise/index';
import { createBudget } from '../../src/policyfix/normalise/opaque';
import { reference, verdictOf } from '../helpers/reference';

describe('bounded cmd literals', () => {
  it.each(['DEL /S /Q src', 'erase src /s /q', 'rD /s /q src', 'rmdir src /S /Q', 'r^d /s /q src', 'cmd /d /c "rmdir /s /q src"', 'echo ok && del /s /q src', 'echo ok | del /s /q src', 'type .env'])('finds restricted cmd effects: %s', (command) => {
    // what_bug_this_catches: aliases, case, switch order, escaped program spelling or literal cmd wrappers evading delete/read effects.
    expect(verdictOf('windows', { kind: 'shell', dialect: 'cmd', command }).verdict).toBe('deny');
  });

  it.each(['rmdir /s /q node_modules', 'echo "del /s /q src"', 'type .env.example', 'echo ok > NUL'])('permits modeled near misses: %s', (command) => {
    // what_bug_this_catches: treating quoted data, the declared root exception or the null device as a prohibited operation.
    expect(verdictOf('windows', { kind: 'shell', dialect: 'cmd', command }).verdict).toBe('allow');
  });

  it.each(['del /q src', 'erase src /Q', 'rd /q src', 'rmdir src /Q'])('keeps quiet-only deletion plain and permitted: %s', (command) => {
    // what_bug_this_catches: mapping /q prompt suppression to force falsely denies in-root plain deletions under Q03.
    const action = { kind: 'shell', dialect: 'cmd', command } as const;
    const result = normaliseAction(action, reference('windows').context);
    expect(result.opaque).toEqual([]);
    expect(result.subs.filter((sub) => sub.kind === 'fs').map((sub) => sub.mode)).toEqual(['plain']);
    expect(verdictOf('windows', action).verdict).toBe('allow');
  });

  it.each([
    { command: 'del /f src', mode: 'force' },
    { command: 'erase /Q src /F', mode: 'force' },
    { command: 'del /s src', mode: 'recursive' },
    { command: 'rmdir /S /Q src', mode: 'recursive' },
    { command: 'del /s /q /f src', mode: 'recursive-force' },
  ])('retains recursive/force deletion restrictions: $command', ({ command, mode }) => {
    // what_bug_this_catches: fixing quiet-only false blocks must preserve /f force and /s recursive Q03 restrictions.
    const action = { kind: 'shell', dialect: 'cmd', command } as const;
    const result = normaliseAction(action, reference('windows').context);
    expect(result.opaque).toEqual([]);
    expect(result.subs.filter((sub) => sub.kind === 'fs').map((sub) => sub.mode)).toEqual([mode]);
    expect(verdictOf('windows', action).rule_id).toBe('q03-recursive-force-delete-in-root');
  });

  it.each(['%TOOL% src', 'del /s /q %TARGET%', 'del /s /q !TARGET!', 'call delete.cmd', 'for %x in (src) do del %x', 'cmd /k "echo ok"', 'echo "unfinished', 'del /unknown src'])('asks for unsupported cmd syntax: %s', (command) => {
    // what_bug_this_catches: batch/expansion/unknown-switch input silently being treated as safe literal argv.
    expect(verdictOf('windows', { kind: 'shell', dialect: 'cmd', command }).verdict).toBe('ask');
  });

  it('shares recursion/node/step caps and retains previous completed commands', () => {
    // what_bug_this_catches: Windows wrappers resetting a shared action budget or malformed suffixes erasing earlier effects.
    const context = reference('windows').context;
    expect(verdictOf('windows', { kind: 'shell', dialect: 'cmd', command: 'del /s /q src & echo "unfinished' }).verdict).toBe('deny');
    expect(verdictOf('windows', { kind: 'shell', dialect: 'cmd', command: 'cmd /c cmd /c cmd /c cmd /c echo ok' }).verdict).toBe('ask');
    expect(normaliseAction({ kind: 'shell', dialect: 'cmd', command: 'echo ok &'.repeat(129) }, context).opaque.some((finding) => finding.code === 'node-budget')).toBe(true);
    expect(normaliseAction({ kind: 'shell', dialect: 'cmd', command: 'echo hello' }, context, createBudget(2)).opaque.some((finding) => finding.code === 'step-budget')).toBe(true);
  });
});

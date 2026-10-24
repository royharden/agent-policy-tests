import { describe, expect, it } from 'vitest';
import { verdictOf } from './helpers/reference';

describe('posix redirect effects', () => {
  it.each(['echo x > .env', 'echo x >> ../outside/log', 'echo x 2> ../outside/log', 'echo x &> ../outside/log', 'cat < .env', 'true <> .env', 'echo x | tee ../outside/log'])('checks the filesystem target of %s', (command) => {
    // what_bug_this_catches: redirects and tee writing outside the root or reading secrets without emitting fs sub-actions.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command }).verdict).toBe('deny');
  });

  it.each(['echo x > "$OUT"', 'cat <<< data', 'cat << EOF\ndata\nEOF'])('asks for unsupported input or target: %s', (command) => {
    // what_bug_this_catches: a dynamic target or unsupported here-input silently skipping lexical analysis.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command }).verdict).toBe('ask');
  });

  it.each(['echo x > /dev/null', 'echo x 2>&1', 'echo x > ./docs/log'])('permits modeled harmless redirect forms: %s', (command) => {
    // what_bug_this_catches: fd duplication or documented device streams being fabricated as outside-root file writes.
    expect(verdictOf('posix', { kind: 'shell', dialect: 'posix', command }).verdict).toBe('allow');
  });
});

describe('Windows redirect and output effects', () => {
  it.each([
    ['powershell', 'Write-Output x > .env'], ['powershell', 'Write-Output x 2>> ../outside/log'],
    ['powershell', 'Write-Output x | Out-File -FilePath ../outside/log'],
    ['powershell', 'Set-Content -LiteralPath .env -Value x'], ['powershell', 'Add-Content .env x'],
    ['cmd', 'echo x > .env'], ['cmd', 'echo x 2>> ../outside/log'], ['cmd', 'type < .env'],
  ] as const)('emits filesystem effects: %s %s', (dialect, command) => {
    // what_bug_this_catches: Windows output cmdlets and native redirects bypassing path/secret rules.
    expect(verdictOf('windows', { kind: 'shell', dialect, command }).verdict).toBe('deny');
  });

  it.each([
    ['powershell', 'Write-Output x > $OUT'], ['powershell', 'Out-File -FilePath $OUT'],
    ['cmd', 'echo x > %OUT%'], ['cmd', 'echo x >'],
  ] as const)('asks for unresolved redirect targets: %s %s', (dialect, command) => {
    // what_bug_this_catches: missing/dynamic redirect targets disappearing from normalization.
    expect(verdictOf('windows', { kind: 'shell', dialect, command }).verdict).toBe('ask');
  });

  it.each([['powershell', 'Write-Output x 2>&1'], ['cmd', 'echo x 2>&1'], ['cmd', 'echo x > nul']] as const)('does not fabricate file writes for stream/device syntax: %s %s', (dialect, command) => {
    // what_bug_this_catches: fd duplication and documented null-device output becoming filesystem writes.
    expect(verdictOf('windows', { kind: 'shell', dialect, command }).verdict).toBe('allow');
  });
});

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

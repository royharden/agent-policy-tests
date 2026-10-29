import { describe, expect, it } from 'vitest';
import { basename } from 'node:path';
import { main, reportExitCode } from '../cli/policy-runner';
import type { Fixture } from '../src/policyfix/action';
import { referenceOutput } from './helpers/reference';

describe('dependency-free runner contract (source tests)', () => {
  it('recomputes Gap, ignores report.json and distinguishes strict exit from policy defaults', async () => {
    // what_bug_this_catches: trusting a saved Pass, requiring dependency state at runtime, or conflating CLI strict with unmatched ask.
    const policy = referenceOutput('posix').policy; const reads: string[] = []; const writes: string[] = [];
    const io = { readText: async (path: string): Promise<string> => { reads.push(basename(path)); if (basename(path) === 'policy.json') return JSON.stringify(policy); if (basename(path) === 'fixtures.json') return '{"fixtures":[]}'; throw new Error('Must not read saved report'); }, write: (text: string): void => { writes.push(text); } };
    expect(await main([], io)).toBe(0);
    expect(await main(['--strict'], io)).toBe(2);
    expect(reads).not.toContain('report.json');
    expect(writes.some((text) => text.includes('"status":"Gap"'))).toBe(true);
  });

  it('returns invalid/Fail before strict Gap and reports malformed flags/JSON structurally', async () => {
    // what_bug_this_catches: strict mode masking a real Fail as exit 2, or malformed input escaping as an unhandled exception.
    const policy = referenceOutput('posix').policy;
    const fixture: Fixture = { id: 'wrong', rule_id: 'q12-over-limit', source_answer: 'Q12', action: { kind: 'payment', amount_cents: 5001, currency: 'USD' }, expected_local: 'allow', origin: 'template' };
    const output: string[] = [];
    const io = { readText: async (path: string): Promise<string> => basename(path) === 'policy.json' ? JSON.stringify(policy) : JSON.stringify({ fixtures: [fixture] }), write: (text: string): void => { output.push(text); } };
    expect(await main(['--strict'], io)).toBe(1);
    expect(await main(['--unknown'], io)).toBe(1);
    expect(await main([], { ...io, readText: async () => '{' })).toBe(1);
    expect(output.some((text) => text.includes('"ok":false'))).toBe(true);
    expect(reportExitCode({ status: 'Fail' }, true)).toBe(1);
  });
});

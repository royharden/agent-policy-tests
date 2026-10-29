import { describe, expect, it } from 'vitest';
import { parseOptions } from '../eval/run';
import { claimHeldout, exactSha256, verifyManifest } from '../src/lib/evalkit';
import type { JournalStore } from '../src/lib/callledger';

function journal(initial = ''): JournalStore & { text: string } {
  const state = { text: initial, read: async (): Promise<string> => state.text, append: async (line: string): Promise<void> => { state.text += line; }, exclusive: async <T>(fn: () => Promise<T>): Promise<T> => fn() };
  return state;
}

describe('evaluation publication gates', () => {
  it('defaults to dev/offline and rejects invalid or live sampling arguments', () => {
    // what_bug_this_catches: default held-out/live execution or silently accepting misspelled mode flags.
    expect(parseOptions([])).toEqual({ split: 'dev', live: false, rerun_reason: null, sample_only: false });
    expect(() => parseOptions(['--split', 'other'])).toThrow();
    expect(() => parseOptions(['--sample-heldout', '--live'])).toThrow();
  });

  it('verifies exact frozen bytes before evaluation', async () => {
    // what_bug_this_catches: accepting labels changed after freeze or treating normalized line endings as identical bytes.
    const bytes = new TextEncoder().encode('synthetic\n');
    const text = JSON.stringify({ seed: 21, frozen_at: '2026-10-24', files: { 'data.jsonl': { bytes: bytes.length, sha256: exactSha256(bytes) } } });
    expect((await verifyManifest(text, async () => bytes)).seed).toBe(21);
    await expect(verifyManifest(text, async () => new TextEncoder().encode('synthetic\r\n'))).rejects.toThrow();
  });

  it('requires matching owner sample evidence and a reason after an attempted run', async () => {
    // what_bug_this_catches: agent-generated approval, stale-manifest approval, concurrent/repeated exposure or crash retries bypassing held-out discipline.
    const ids = Array.from({ length: 20 }, (_, i) => `synthetic-${i}`); const hash = 'a'.repeat(64);
    const attempt = { kind: 'attempt' as const, run_id: 'run-one', manifest_sha256: hash, at: '2026-10-24T22:00:00Z', rerun_reason: null };
    await expect(claimHeldout(journal(), attempt, ids)).rejects.toThrow();
    // Test-only in-memory receipt; this does not create an actual project owner-review record.
    const receipt = { kind: 'owner-review', reviewer: 'Roy', approved: true, manifest_sha256: hash, sample_ids: ids, reviewed_at: '2026-10-24T21:00:00Z' };
    const store = journal(`${JSON.stringify(receipt)}\n`);
    await claimHeldout(store, attempt, ids);
    await expect(claimHeldout(store, { ...attempt, run_id: 'run-two' }, ids)).rejects.toThrow();
    await claimHeldout(store, { ...attempt, run_id: 'run-two', rerun_reason: 'Explicit synthetic rerun fixture.' }, ids);
    expect(store.text.split('\n').filter((line) => line.includes('"kind":"attempt"'))).toHaveLength(2);
  });
});

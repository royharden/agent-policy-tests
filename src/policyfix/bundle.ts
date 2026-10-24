import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { bindReviewReport, checkReportBinding, exportReadiness, type ReviewSnapshot } from './approvals';
import { fail, makeError, ok, type Result } from './errors';
import { MAX_FILE_BYTES } from './limits';
import { evaluatePolicy } from './score';

export const BUNDLE_NAMES = ['policy.json', 'fixtures.json', 'report.json', 'MANUAL-ITEMS.md', 'policy-runner.mjs', 'README.md', 'bundle-manifest.json'] as const;
export type BundleName = (typeof BUNDLE_NAMES)[number];
export interface BundleFiles { readonly files: Readonly<Record<BundleName, Uint8Array>>; readonly status: 'Pass' | 'Fail' | 'Gap' }

function jsonBytes(value: unknown): Uint8Array { return utf8ToBytes(`${JSON.stringify(value, null, 2)}\n`); }
export function hashBytes(bytes: Uint8Array): string { return bytesToHex(sha256(bytes)); }

/** Shared M6 approval truth, followed by a fresh report computation; a matching forged outcome is never exported. */
export function buildBundle(snapshot: ReviewSnapshot, runnerBytes: Uint8Array): Result<BundleFiles> {
  const ready = exportReadiness(snapshot);
  if (!ready.ok) return ready;
  if (!ready.value.ready) return fail([makeError('inconsistent', '/review', ready.value.reasons.join(' '))]);
  const binding = checkReportBinding(snapshot);
  if (!binding.ok) return binding;
  if (runnerBytes.length === 0) return fail([makeError('required', '/runner', 'The built same-origin policy-runner.mjs asset is missing or empty. Run the documented build before exporting.')]);
  const evaluated = evaluatePolicy(snapshot.policy, snapshot.fixtures);
  if (!evaluated.ok) return evaluated;
  const report = bindReviewReport(evaluated.value, snapshot.inputs, snapshot.approvals);
  if (!report.ok) return report;
  const manual = ['# Manual items', '', 'Acknowledgement preserves each manual Gap; it does not enforce the restriction.', '', ...snapshot.policy.manual_items.flatMap((item) => [`## ${item.id}`, '', item.text, '', `Reason: ${item.reason}`, ''])].join('\n');
  const readme = `# Policy test bundle\n\nThis bundle proves this evaluator only. It is not a security boundary and does not prove agent enforcement.\n\nObserved status: ${report.value.status}. Manual acknowledgements preserve Gap. Approvals are in report.json; the runner ignores saved report outcomes and recomputes policy + fixtures.\n\nNode 20 or newer, no dependencies/network required after the runner has been built:\n\n\`\`\`sh\nnode policy-runner.mjs --strict\n\`\`\`\n\nIn CI, unpack this bundle and run that command as a normal step. Invalid input or Fail exits 1; otherwise --strict with Gap exits 2; otherwise 0. policy.default_unmatched is separate from --strict. Do not approve-and-execute an ask.\n\nMANUAL-ITEMS.md records unexecutable restrictions. bundle-manifest.json hashes final bytes of the other six files; it does not hash itself.\n`;
  const entries = {
    'policy.json': jsonBytes(snapshot.policy), 'fixtures.json': jsonBytes({ fixtures: snapshot.fixtures }),
    'report.json': jsonBytes(report.value), 'MANUAL-ITEMS.md': utf8ToBytes(manual),
    'policy-runner.mjs': new Uint8Array(runnerBytes), 'README.md': utf8ToBytes(readme),
  };
  for (const name of ['policy.json', 'fixtures.json', 'report.json'] as const) {
    if (entries[name].length > MAX_FILE_BYTES) return fail([makeError('export_too_large', `/${name}`, `${name} exceeds ${MAX_FILE_BYTES} UTF-8 bytes.`, MAX_FILE_BYTES)]);
  }
  const manifest = jsonBytes({ schema_version: 1, files: Object.fromEntries(Object.entries(entries).map(([name, bytes]) => [name, { sha256: hashBytes(bytes), bytes: bytes.length }])) });
  if (manifest.length > MAX_FILE_BYTES) return fail([makeError('export_too_large', '/bundle-manifest.json', 'Bundle manifest exceeds the shared byte cap.', MAX_FILE_BYTES)]);
  return ok({ files: { ...entries, 'bundle-manifest.json': manifest }, status: report.value.status });
}

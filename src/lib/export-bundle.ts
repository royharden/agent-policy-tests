import { zipSync } from 'fflate';
import type { ReviewSnapshot } from '../policyfix/approvals';
import { buildBundle } from '../policyfix/bundle';
import { fail, makeError, ok, type Result } from '../policyfix/errors';

export interface RunnerAssetResponse { readonly ok: boolean; readonly status: number; arrayBuffer(): Promise<ArrayBuffer> }
export type AssetFetch = (url: string, init: { readonly redirect: 'error'; readonly cache: 'no-store' }) => Promise<RunnerAssetResponse>;

export async function createBundleDownload(snapshot: ReviewSnapshot | (() => ReviewSnapshot | null), fetchAsset: AssetFetch, basePath = '/'): Promise<Result<{ readonly bytes: Uint8Array; readonly status: string }>> {
  try {
    // A path relative to Vite's configured base stays on the app origin; redirects are rejected.
    if (!basePath.startsWith('/') || basePath.startsWith('//') || basePath.includes('://')) return fail([makeError('invalid_value', '/runner', 'Runner base must be a same-origin path.')]);
    const response = await fetchAsset(`${basePath.endsWith('/') ? basePath : `${basePath}/`}policy-runner.mjs`, { redirect: 'error', cache: 'no-store' });
    if (!response.ok) return fail([makeError('required', '/runner', `Runner asset unavailable (HTTP ${response.status}); build the app before exporting.`)]);
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length === 0 || new TextDecoder().decode(bytes.subarray(0, 256)).trimStart().startsWith('<')) return fail([makeError('invalid_value', '/runner', 'Runner asset is empty or an HTML fallback; build the runner before exporting.')]);
    const current = typeof snapshot === 'function' ? snapshot() : snapshot;
    if (current === null) return fail([makeError('inconsistent', '/review', 'The review changed while the runner was loading. Compile and replay before exporting.')]);
    const built = buildBundle(current, bytes);
    return built.ok ? ok({ bytes: zipSync({ ...built.value.files }, { level: 6 }), status: built.value.status }) : built;
  } catch {
    return fail([makeError('invalid_value', '/export', 'Cannot fetch the same-origin runner or create the bundle. The built runner asset is required.')]);
  }
}

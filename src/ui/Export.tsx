import { type ReactElement, useRef, useState } from 'react';
import { createBundleDownload } from '../lib/export-bundle';
import type { ExportReadiness, ReviewSnapshot } from '../policyfix/approvals';
import type { Result } from '../policyfix/errors';
import { Errors } from './Errors';

/** M8 consumes snapshot and reruns exportReadiness at click time before building final bytes. */
export function Export({ snapshot, readiness }: { readonly snapshot: ReviewSnapshot | null; readonly readiness: Result<ExportReadiness> | null }): ReactElement {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const latest = useRef(snapshot); latest.current = snapshot;
  const download = async (): Promise<void> => {
    if (snapshot === null) return;
    setBusy(true); setMessage(null);
    try {
      const result = await createBundleDownload(() => latest.current, fetch, import.meta.env.BASE_URL);
      if (!result.ok) { setMessage(result.errors.map((error) => error.message).join(' ')); return; }
      const blob = new Blob([new Uint8Array(result.value.bytes)], { type: 'application/zip' });
      const url = URL.createObjectURL(blob); const link = document.createElement('a');
      link.href = url; link.download = 'policy-tests.zip'; link.click();
      setTimeout(() => { URL.revokeObjectURL(url); }, 1000);
      setMessage(`Downloaded current ${result.value.status} report and policy bundle. The runner recomputes all outcomes.`);
    } catch { setMessage('The browser could not save the bundle. Your current review remains available.'); }
    finally { setBusy(false); }
  };
  return <section aria-labelledby="export-heading"><h2 id="export-heading">Export readiness</h2>
    {snapshot === null || readiness === null ? <p>Compile a policy, generate fixtures and replay before exporting.</p> : !readiness.ok ? <Errors errors={readiness.errors} /> : <>
      <p role="status">{readiness.value.ready ? 'The current review meets the export requirements.' : 'This review is not ready to export.'}</p>
      <ul>{readiness.value.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
    </>}
    <button type="button" disabled={busy || snapshot === null || readiness === null || !readiness.ok || !readiness.value.ready} onClick={() => { void download(); }}>Download bundle</button>
    {message === null ? null : <p role="status">{message}</p>}
  </section>;
}

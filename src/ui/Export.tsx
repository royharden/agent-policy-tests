import type { ReactElement } from 'react';
import type { ExportReadiness, ReviewSnapshot } from '../policyfix/approvals';
import type { Result } from '../policyfix/errors';
import { Errors } from './Errors';

/** M8 consumes snapshot and reruns exportReadiness at click time before building final bytes. */
export function Export({ snapshot, readiness }: { readonly snapshot: ReviewSnapshot | null; readonly readiness: Result<ExportReadiness> | null }): ReactElement {
  return <section aria-labelledby="export-heading"><h2 id="export-heading">Export readiness</h2>
    {snapshot === null || readiness === null ? <p>Compile a policy, generate fixtures and replay before exporting.</p> : !readiness.ok ? <Errors errors={readiness.errors} /> : <>
      <p role="status">{readiness.value.ready ? 'The current review meets the export requirements.' : 'This review is not ready to export.'}</p>
      <ul>{readiness.value.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
    </>}
    <button type="button" disabled aria-describedby="download-pending">Download bundle</button>
    <p id="download-pending" className="hint">Bundle downloads are not available in this version yet. Your inputs can be copied from Draft JSON.</p>
  </section>;
}

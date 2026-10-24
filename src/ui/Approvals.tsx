import type { ReactElement } from 'react';
import { type ApprovalRecord, type ApprovalRequirement, isApproved } from '../policyfix/approvals';

export function Approvals({ requirements, records, onApprove, disabled }: {
  readonly requirements: readonly ApprovalRequirement[]; readonly records: readonly ApprovalRecord[];
  readonly onApprove: (requirement: ApprovalRequirement) => void; readonly disabled: boolean;
}): ReactElement {
  const required = requirements.filter((item) => item.required);
  return <section aria-labelledby="approvals-heading"><h2 id="approvals-heading">Approve and acknowledge</h2>
    <p>Approve every free-text rule and acknowledge each manual item. Manual acknowledgements retain their Gap. Changes to an item or its dependencies require a new decision.</p>
    {requirements.length === 0 ? <p className="empty">Compile the policy and generate fixtures before review.</p> : <>
      <p>{required.filter((item) => isApproved(item, records)).length}/{required.length} required decisions current.</p>
      {requirements.map((requirement) => {
        const approved = isApproved(requirement, records);
        const previous = records.some((record) => record.item_id === requirement.item_id);
        return <article className="approval" key={requirement.item_id}><p><strong>{requirement.kind === 'manual' ? 'Manual item' : 'Rule'}</strong> · <code>{requirement.item_id}</code> · {requirement.required ? 'Required for export' : 'Optional questionnaire review'}</p>
          <p>{requirement.label}</p><p role="status">{approved ? 'Current decision recorded' : previous ? 'Previous decision is stale' : 'Not yet reviewed'}</p>
          <button type="button" disabled={disabled || approved} onClick={() => { onApprove(requirement); }}>{requirement.kind === 'manual' ? 'Acknowledge manual Gap' : 'Approve rule'}: {requirement.item_id}</button>
        </article>;
      })}
    </>}
  </section>;
}

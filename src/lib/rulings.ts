// M6 owns approval semantics. This adapter intentionally re-exports the same type and helpers.
export { isApproved, recordApproval, type ApprovalRecord, type ApprovalRequirement } from '../policyfix/approvals';
import type { ApprovalRecord } from '../policyfix/approvals';

export function rulingsJsonl(records: readonly ApprovalRecord[]): string {
  return records.map((record) => `${JSON.stringify(record)}\n`).join('');
}

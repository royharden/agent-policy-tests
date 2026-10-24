import { z } from 'zod';
import { isValidId, parseImportText } from '../policyfix/action';
import type { ReviewInputs } from '../policyfix/approvals';
import type { FreeTextItem } from '../policyfix/compile';
import { fail, fromZodIssues, makeError, ok, type Result } from '../policyfix/errors';
import { canonicalJson } from '../policyfix/digest';
import { parseThresholdConfig } from '../policyfix/freetext/thresholds';
import { MAX_COMMAND_CHARS, MAX_LIST_ITEMS } from '../policyfix/limits';

const text = z.string().min(1).max(MAX_COMMAND_CHARS);
const list = z.array(text).max(MAX_LIST_ITEMS);
const ParamsSchema = z.object({
  command: text.optional(), fs_ops: z.array(z.enum(['write', 'delete'])).min(1).max(2).optional(),
  polarity: z.enum(['allow-list', 'block-list']).optional(), git_operation: z.enum(['push', 'delete', 'protect']).optional(),
  branch: text.optional(), host: text.optional(), hosts: list.optional(), domain: text.optional(),
  glob: text.optional(), path: text.optional(), except: list.optional(),
  limit_cents: z.number().finite().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(), currency: z.string().length(3).optional(),
}).strict();

/** Classifier labels never supply parameters: only M5 extraction or this explicit user editor can do so. */
export function acceptedItems(inputs: ReviewInputs): Result<readonly FreeTextItem[]> {
  const thresholdJson = parseImportText(inputs.thresholds_text);
  if (!thresholdJson.ok) return thresholdJson;
  const parsedThresholds = parseThresholdConfig(thresholdJson.value);
  const active = canonicalJson(inputs.thresholds); const rendered = canonicalJson(parsedThresholds);
  if (parsedThresholds === null || !active.ok || !rendered.ok || active.value !== rendered.value) return fail([makeError('invalid_value', '/thresholds', 'Invalid or inconsistent confidence threshold configuration.')]);
  const items: FreeTextItem[] = [];
  for (const line of inputs.lines) {
    if (!isValidId(line.id) || line.text.trim() === '' || line.text.length > 300) return fail([makeError('invalid_value', `/lines/${line.id}`, 'NOT lines must have a valid id and 1–300 characters.')]);
    const classified = line.classification;
    if (classified === null || classified.item.text !== line.text || classified.provider !== line.provider) return fail([makeError('inconsistent', `/lines/${line.id}`, 'Classify this line after its latest edit.')]);
    if (classified.item.label === 'manual') { items.push({ ...classified.item, text: line.text }); continue; }
    const json = parseImportText(line.params_text);
    if (!json.ok) return json;
    const params = ParamsSchema.safeParse(json.value);
    if (!params.success) return fail(fromZodIssues(params.error.issues, ['lines', line.id, 'params']));
    items.push({ ...classified.item, text: line.text, params: params.data });
  }
  return ok(items);
}

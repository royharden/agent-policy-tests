import { isFreeTextLabel } from '../../src/policyfix/freetext/labels';
import { LABEL_CRITERIA, LABEL_INSTRUCTIONS } from './jev';
import { anthropicJson, anthropicRequest, callOnce, fallback, metadataFor, observation, probability, record, responseObject, type LabelResult, type ProviderDeps, type ProviderRequest } from './types';

export const LLM_CLASSIFIER_MODEL = 'claude-haiku-4-5-20251001';

export function buildLlmRequest(line: string, model: string = LLM_CLASSIFIER_MODEL): ProviderRequest {
  if (line.trim().length === 0 || line.length > 300 || model.length === 0) throw new Error('Invalid classifier input/model.');
  return anthropicRequest({
    model, max_tokens: 128,
    system: `${LABEL_INSTRUCTIONS} Categories: ${JSON.stringify(LABEL_CRITERIA)} Return exactly JSON {"label":<category>,"confidence":<number 0..1>}. No other keys or text.`,
    messages: [{ role: 'user', content: JSON.stringify({ line }) }],
  });
}

export async function classifyLlm(line: string, deps: ProviderDeps, model: string = LLM_CLASSIFIER_MODEL): Promise<LabelResult> {
  const request = buildLlmRequest(line, model);
  const metadata = metadataFor('llm', model, request.body, [], 128, ['template']);
  const reply = await callOnce(request, metadata, deps);
  const body = responseObject(reply, model);
  if (body === null) return fallback(reply, metadata, reply.status === 'timeout' ? 'timeout' : 'provider_error');
  const parsed = anthropicJson(body);
  if (!record(parsed) || Object.keys(parsed).length !== 2 || !isFreeTextLabel(parsed['label']) || (parsed['confidence'] !== null && !probability(parsed['confidence']))) return fallback(reply, metadata, 'unparsable');
  return { ...observation(reply, metadata), kind: 'ok', label: parsed['label'], confidence: parsed['confidence'] };
}

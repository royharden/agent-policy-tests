// Framework-free orchestration. App/CLI inject remote label callbacks; this module cannot authenticate or network.
import type { FreeTextItem } from '../compile';
import type { EvaluationContext } from '../context';
import { TEMPLATES_BY_ID } from '../templates/index';
import { extractParams } from './extract';
import { classifyKeyword, isInjectionLike } from './keyword';
import { type FreeTextLabel, isFreeTextLabel } from './labels';
import { classifyMock } from './mock';
import { thresholdFor, UNCALIBRATED_THRESHOLDS, type ThresholdConfig } from './thresholds';

export type ClassifierProvider = 'keyword' | 'mock' | 'jev' | 'llm';
export type LabelReply =
  | { readonly kind: 'ok'; readonly label: FreeTextLabel; readonly confidence: number | null }
  | { readonly kind: 'fallback' | 'error'; readonly reason: string };
export interface ClassifyInput { readonly id: string; readonly line: string; readonly context: EvaluationContext; readonly provider?: ClassifierProvider }
export interface ClassifyDeps {
  readonly thresholds?: ThresholdConfig;
  /** Caller owns opt-in/auth/cost reservation. It returns labels only; extra fields cannot become parameters. */
  readonly remote?: (input: { readonly line: string; readonly provider: 'jev' | 'llm' }) => Promise<LabelReply>;
}
export interface Classification {
  readonly item: FreeTextItem;
  readonly raw_label: FreeTextLabel | null;
  readonly confidence: number | null;
  readonly provider: ClassifierProvider;
  readonly status: 'compiled-candidate' | 'manual' | 'fallback';
  readonly reason: string | null;
}

export async function classifyLine(input: ClassifyInput, deps: ClassifyDeps = {}): Promise<Classification> {
  const provider = input.provider ?? 'keyword';
  let rawLabel: FreeTextLabel | null = null; let confidence: number | null = null;
  const manual = (reason: string, fallback = false): Classification => ({
    item: { id: input.id, text: input.line, label: 'manual', reason }, raw_label: rawLabel, confidence, provider,
    status: fallback ? 'fallback' : 'manual', reason,
  });
  if (input.line.trim().length === 0 || input.line.length > 300) return manual('A NOT line must contain 1–300 characters.');
  if (isInjectionLike(input.line)) return manual('Instruction-like classifier manipulation requires manual review.');
  if (provider === 'keyword' || provider === 'mock') rawLabel = provider === 'keyword' ? classifyKeyword(input.line) : classifyMock(input.line);
  else {
    if (deps.remote === undefined) return manual('Remote classifier is not configured or opted in.', true);
    let reply: LabelReply;
    try { reply = await deps.remote({ line: input.line, provider }); } catch { return manual('Remote classifier failed.', true); }
    if (reply.kind !== 'ok') return manual(reply.reason, true);
    if (!isFreeTextLabel(reply.label)) return manual('Remote classifier returned an unsupported label.', true);
    rawLabel = reply.label; confidence = reply.confidence;
    const threshold = thresholdFor(provider, deps.thresholds ?? UNCALIBRATED_THRESHOLDS);
    if (threshold === null) return manual('Remote confidence threshold is uncalibrated; dev calibration is pending.');
    if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < threshold || confidence > 1) return manual('Remote confidence is missing, invalid or below the dev threshold.');
  }
  if (rawLabel === 'manual' || rawLabel === null) return manual('No executable template was selected.');
  const extraction = extractParams(input.line, rawLabel);
  if (!extraction.ok) return manual(extraction.reason);
  if (TEMPLATES_BY_ID[rawLabel].compileFreeText(input.id, input.line, extraction.params, input.context) === null) return manual('The requested scope cannot be preserved by one supported rule.');
  return { item: { id: input.id, text: input.line, label: rawLabel, params: extraction.params }, raw_label: rawLabel, confidence, provider, status: 'compiled-candidate', reason: null };
}

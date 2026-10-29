// Thresholds are evidence-bearing configuration, never inferred from confidence or cookbook examples.
export interface ThresholdConfig {
  readonly schema_version: 1;
  readonly provenance: { readonly status: 'uncalibrated' | 'dev-calibrated'; readonly split: 'dev'; readonly dataset_sha256: string | null };
  readonly jev: number | null;
  readonly llm: number | null;
}

export const UNCALIBRATED_THRESHOLDS: ThresholdConfig = {
  schema_version: 1,
  provenance: { status: 'uncalibrated', split: 'dev', dataset_sha256: null },
  jev: null, llm: null,
};

/** Decode imported JSON without a type assertion; invalid calibration records cannot enable remote candidates. */
export function parseThresholdConfig(value: unknown): ThresholdConfig | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const config = value as Record<string, unknown>; const provenance = config['provenance'];
  if (config['schema_version'] !== 1 || typeof provenance !== 'object' || provenance === null || Array.isArray(provenance)) return null;
  const source = provenance as Record<string, unknown>;
  if ((source['status'] !== 'uncalibrated' && source['status'] !== 'dev-calibrated') || source['split'] !== 'dev') return null;
  const digest = source['dataset_sha256'];
  if (digest !== null && (typeof digest !== 'string' || !/^[a-f0-9]{64}$/.test(digest))) return null;
  const jev = config['jev']; const llm = config['llm'];
  if ((jev !== null && (typeof jev !== 'number' || !Number.isFinite(jev) || jev < 0 || jev > 1)) ||
      (llm !== null && (typeof llm !== 'number' || !Number.isFinite(llm) || llm < 0 || llm > 1))) return null;
  if (source['status'] === 'dev-calibrated' && digest === null) return null;
  return { schema_version: 1, provenance: { status: source['status'], split: 'dev', dataset_sha256: digest }, jev, llm };
}

export function thresholdFor(provider: 'jev' | 'llm', config: ThresholdConfig): number | null {
  const value = config[provider];
  if (config.schema_version !== 1 || config.provenance.status !== 'dev-calibrated' || config.provenance.split !== 'dev' ||
      !/^[a-f0-9]{64}$/.test(config.provenance.dataset_sha256 ?? '') ||
      typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) return null;
  return value;
}

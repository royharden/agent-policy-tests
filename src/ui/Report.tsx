import type { ReactElement } from 'react';
import type { Ratio, ScoreReport } from '../policyfix/score';
import { formatRatio } from '../policyfix/score';

export interface BaselineComparison { readonly B1: Ratio; readonly B2: Ratio }

export function Report({ report, current, baselines }: { readonly report: ScoreReport | null; readonly current: boolean; readonly baselines: BaselineComparison | null }): ReactElement {
  return <section aria-labelledby="report-heading"><h2 id="report-heading">Review the report</h2>
    {report === null ? <p className="empty">Replay the fixtures to see Pass, Fail and Gap findings.</p> : <>
      <p role="status" className={current ? 'notice' : 'warning'}><strong>{report.status}</strong> · {current ? 'Current report' : 'Stale report — replay current inputs before export'}</p>
      <p>Generated fixtures check the self-consistency of the declared templates. These numbers are not held-out accuracy or proof that an agent enforces the policy.</p>
      <dl className="metrics">{Object.entries(report.metrics).map(([name, ratio]) => <div key={name}><dt>{name.replaceAll('_', ' ')}</dt><dd>{formatRatio(ratio)}</dd></div>)}</dl>
      <p>Silent drops: {report.silent_drops}. Untested rules: {report.untested_rule_ids.join(', ') || 'None'}. Shadowed rules: {report.shadowed_rule_ids.join(', ') || 'None'}.</p>
      {baselines === null ? null : <p>Exact verdict agreement on the same fixtures: B1 raw substring {formatRatio(baselines.B1)} · B2 raw prefix {formatRatio(baselines.B2)} · Guard {formatRatio(report.metrics.exact_verdict_accuracy)}. B1/B2 use questionnaire answers only; they do not compile free-text restrictions.</p>}
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Report by source"><table><caption>One status per questionnaire answer or NOT line</caption><thead><tr><th scope="col">Source</th><th scope="col">Status</th><th scope="col">Fixtures</th><th scope="col">Findings</th></tr></thead><tbody>{report.items.map((item) => <tr key={item.source_answer}><th scope="row">{item.source_answer}</th><td><strong>{item.status}</strong></td><td>{item.fixture_ids.length}</td><td>{item.findings.length === 0 ? 'No finding' : <ul>{item.findings.map((finding, index) => <li key={`${finding.code}:${index}`}>{finding.severity}: {finding.reason}{finding.rule_id === null ? '' : ` (${finding.rule_id})`}</li>)}</ul>}</td></tr>)}</tbody></table></div>
      <details><summary>Rule sensitivity and report bindings</summary><ul>{report.sensitivity.map((row) => <li key={row.rule_id}><code>{row.rule_id}</code>: {row.untested ? 'untested' : 'sensitive to removal'}{row.shadowed ? ', shadowed' : ''}</li>)}</ul>
        <dl className="hashes">{(['policy_sha', 'fixtures_sha', 'context_sha', 'engine_version'] as const).map((key) => <div key={key}><dt>{key}</dt><dd><code>{report[key]}</code></dd></div>)}</dl>
      </details>
    </>}
  </section>;
}

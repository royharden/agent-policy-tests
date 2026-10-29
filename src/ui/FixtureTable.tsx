import { type ReactElement, useState } from 'react';
import type { Fixture } from '../policyfix/action';
import type { ScoreReport } from '../policyfix/score';

export function FixtureTable({ fixtures, report, current, text, onTextChange, onApply }: {
  readonly fixtures: readonly Fixture[]; readonly report: ScoreReport | null; readonly current: boolean;
  readonly text: string; readonly onTextChange: (text: string) => void; readonly onApply: () => void;
}): ReactElement {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(fixtures.length / 25)); const activePage = Math.min(page, pages - 1);
  return <section aria-labelledby="fixtures-heading"><h2 id="fixtures-heading">Fixtures and fake replay</h2>
    <p>{fixtures.length} fixtures. Commands and tool calls are data; replay uses isolated fake tools.</p>
    <details><summary>Edit or paste fixture JSON</summary><p>Applying edits validates their shape and rule references. Editing immediately makes the report stale.</p>
      <label className="field"><span>Fixtures JSON</span><textarea rows={8} value={text} onChange={(event) => { onTextChange(event.currentTarget.value); }} /></label>
      <button type="button" onClick={onApply}>Apply fixture JSON</button>
    </details>
    {fixtures.length === 0 ? <p className="empty">Generate fixtures after compiling the policy.</p> : <>
      {!current && report !== null ? <p className="notice" role="status">Displayed replay observations belong to the previous report. Replay the current inputs to refresh them.</p> : null}
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Fixture results"><table><caption>Declared expectations and {current ? 'current' : 'previous'} replay observations</caption>
        <thead><tr><th scope="col">Fixture / action</th><th scope="col">Expected local / policy</th><th scope="col">Verdict / rule</th><th scope="col">Reason</th><th scope="col">Fake side effects</th></tr></thead>
        <tbody>{fixtures.slice(activePage * 25, activePage * 25 + 25).map((fixture) => {
          const row = report?.rows.find((candidate) => candidate.fixture_id === fixture.id);
          return <tr key={fixture.id}><th scope="row"><code>{fixture.id}</code><pre>{JSON.stringify(fixture.action, null, 2)}</pre>{fixture.conflict === undefined ? null : <p>Declared conflict: {fixture.conflict.owner_rule} · {fixture.conflict.reason}</p>}</th>
            <td>{fixture.expected_local} / {fixture.expected_policy ?? fixture.expected_local}</td><td>{row?.composed.verdict ?? 'Not replayed'}<div><code>{row?.composed.rule_id ?? '—'}</code></div>{row?.status}</td><td>{row?.composed.reason ?? 'Replay to see the evaluator reason.'}</td>
            <td>{row === undefined ? 'Not replayed' : row.effects.length === 0 ? 'Empty' : <pre>{JSON.stringify(row.effects, null, 2)}</pre>}</td></tr>;
        })}</tbody></table></div>
      <nav className="toolbar" aria-label="Fixture pages"><button type="button" disabled={activePage === 0} onClick={() => { setPage(activePage - 1); }}>Previous</button><span aria-live="polite">Page {activePage + 1} of {pages}</span><button type="button" disabled={activePage + 1 === pages} onClick={() => { setPage(activePage + 1); }}>Next</button></nav>
    </>}
  </section>;
}

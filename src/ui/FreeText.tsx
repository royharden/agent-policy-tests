import type { ReactElement } from 'react';
import type { ReviewLine } from '../policyfix/approvals';
import type { ClassifierProvider } from '../policyfix/freetext/classify';
import type { RemoteProvider } from '../providers/remote';

export interface FreeTextProps {
  readonly lines: readonly ReviewLine[];
  readonly onAdd: () => void;
  readonly onDemo: () => void;
  readonly onChange: (id: string, patch: Partial<Pick<ReviewLine, 'text' | 'provider' | 'params_text'>>) => void;
  readonly onRemove: (id: string) => void;
  readonly onClassify: (id: string) => void;
  readonly busyIds: readonly string[];
  readonly configured: boolean;
  readonly optedIn: Readonly<Record<RemoteProvider, boolean>>;
  readonly onOptIn: (provider: RemoteProvider, enabled: boolean) => void;
  readonly thresholdsText: string;
  readonly onThresholdsChange: (text: string) => void;
}

function provider(value: string): ClassifierProvider {
  return value === 'mock' || value === 'jev' || value === 'llm' ? value : 'keyword';
}

export function FreeText(props: FreeTextProps): ReactElement {
  return <section aria-labelledby="freetext-heading"><h2 id="freetext-heading">Add your NOT lines</h2>
    <p>Choose a classifier, review its suggested rule and extracted parameters, then compile. Unsupported restrictions remain manual items.</p>
    <div className="toolbar"><button type="button" onClick={props.onAdd}>Add a NOT line</button><button type="button" onClick={props.onDemo}>Add the three demo lines</button></div>
    <fieldset className="remote-options"><legend>Remote classifiers</legend>
      <p>Enabling a provider allows its Classify button to send that line for classification and may create an anonymous session. No line is sent automatically.</p>
      {(['jev', 'llm'] as const).map((id) => <label className="field field-inline" key={id}><input type="checkbox" disabled={!props.configured} checked={props.optedIn[id]} onChange={(event) => { props.onOptIn(id, event.currentTarget.checked); }} />Enable {id} for this tab</label>)}
      {!props.configured ? <p className="hint">Remote providers are unavailable without a configured connection. Keyword and mock remain available.</p> : null}
      <details><summary>Confidence threshold configuration</summary><p>Remote candidates require a dev-calibrated threshold record. Uncalibrated or low-confidence replies remain manual items.</p>
        <label className="field"><span>Threshold JSON</span><textarea rows={6} value={props.thresholdsText} onChange={(event) => { props.onThresholdsChange(event.currentTarget.value); }} /></label>
      </details>
    </fieldset>
    {props.lines.length === 0 ? <p className="empty">No free-text lines yet. The questionnaire can be used on its own.</p> : null}
    {props.lines.map((line, index) => {
      const busy = props.busyIds.includes(line.id); const classification = line.classification;
      const remote = line.provider === 'jev' || line.provider === 'llm';
      const enabled = !remote || (props.configured && props.optedIn[line.provider as RemoteProvider]);
      return <fieldset className="not-line" key={line.id}><legend>NOT line {index + 1}</legend>
        <label className="field"><span>Restriction (up to 300 characters)</span><textarea rows={2} maxLength={300} value={line.text} onChange={(event) => { props.onChange(line.id, { text: event.currentTarget.value }); }} /></label>
        <div className="toolbar"><label className="field"><span>Classifier</span><select value={line.provider} onChange={(event) => { props.onChange(line.id, { provider: provider(event.currentTarget.value) }); }}>
          <option value="keyword">Keyword · local</option><option value="mock">Mock · fixed demo labels</option><option value="jev">Jev · remote</option><option value="llm">LLM · remote</option>
        </select></label><button type="button" disabled={busy || !enabled || line.text.trim() === ''} onClick={() => { props.onClassify(line.id); }}>{busy ? 'Classifying…' : 'Classify line'}</button>
          <button type="button" onClick={() => { props.onRemove(line.id); }}>Remove line {index + 1}</button></div>
        {!enabled ? <p className="hint">Enable this provider above before classifying.</p> : null}
        {classification === null ? <p role="status">Not classified, or inputs changed. Classify this line before compiling.</p> : <div role="status">
          <p><strong>{classification.item.label === 'manual' ? 'Manual review' : classification.item.label}</strong> · {classification.provider} · confidence {classification.confidence === null ? 'N/A' : classification.confidence.toFixed(3)}</p>
          {classification.reason === null ? null : <p>{classification.reason}</p>}
          {classification.item.label === 'manual' ? <p>This item will remain a Gap, including after acknowledgement.</p> : <label className="field"><span>Extracted parameters (JSON; review before approval)</span><textarea rows={3} value={line.params_text} onChange={(event) => { props.onChange(line.id, { params_text: event.currentTarget.value }); }} /></label>}
        </div>}
      </fieldset>;
    })}
  </section>;
}

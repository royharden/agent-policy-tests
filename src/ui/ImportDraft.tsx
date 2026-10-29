import { type ReactElement, useState } from 'react';
import { type Draft, draftFromInputs, parseDraft } from '../lib/drafts';
import type { ReviewInputs } from '../policyfix/approvals';
import { makeError, type PolicyError } from '../policyfix/errors';
import { MAX_FILE_BYTES } from '../policyfix/limits';
import { Errors } from './Errors';

export function ImportDraft({ inputs, onImport }: { readonly inputs: ReviewInputs; readonly onImport: (draft: Draft) => void }): ReactElement {
  const [text, setText] = useState('');
  const [errors, setErrors] = useState<readonly PolicyError[]>([]);
  const [message, setMessage] = useState('');
  const importText = (value: string): void => {
    const parsed = parseDraft(value);
    if (!parsed.ok) { setErrors(parsed.errors); setMessage(''); return; }
    onImport(parsed.value); setErrors([]); setMessage('Draft loaded. Classify the NOT lines, then compile and replay to review it.');
  };
  const readFile = async (file: File): Promise<void> => {
    // Check File.size before allocating/reading its contents; parseDraft then checks UTF-8 size and depth again.
    if (file.size > MAX_FILE_BYTES) { setErrors([makeError('file_too_large', '', 'Draft file exceeds the import limit.', MAX_FILE_BYTES)]); return; }
    try { importText(await file.text()); }
    catch { setErrors([makeError('invalid_value', '', 'This file could not be read.')]); }
  };
  return <section aria-labelledby="draft-heading"><h2 id="draft-heading">Draft JSON</h2>
    <p>Drafts preserve questionnaire values, NOT lines, edited parameters and threshold configuration. Fixtures, reports and approvals stay in this tab. Loading a draft requires a fresh review; remote providers stay off.</p>
    <label className="field"><span>Import a draft file (up to 16 MiB)</span><input type="file" accept="application/json,.json" onChange={(event) => {
      const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; if (file !== undefined) void readFile(file);
    }} /></label>
    <label className="field"><span>Draft JSON to import or copy</span><textarea rows={6} value={text} onChange={(event) => { setText(event.currentTarget.value); setErrors([]); }} /></label>
    <div className="toolbar"><button type="button" onClick={() => { importText(text); }}>Import pasted JSON</button>
      <button type="button" onClick={() => {
        const draft = draftFromInputs(inputs); if (!draft.ok) { setErrors(draft.errors); return; }
        setText(JSON.stringify(draft.value, null, 2)); setErrors([]); setMessage('Current draft JSON is ready to select and copy.');
      }}>Show current draft JSON</button></div>
    <Errors errors={errors} /><p role="status">{message}</p>
  </section>;
}

import { type ReactElement, useEffect, useRef, useState } from 'react';
import referenceAnswersJson from '../../eval/gold/reference-answers.json';
import { type Draft, loadDraft, saveDraft } from '../lib/drafts';
import { acceptedItems } from '../lib/review';
import { isSupabaseConfigured, requestedClassifierMode, startupClassifierMode } from '../lib/supabase';
import { type Fixture, parseFixtures } from '../policyfix/action';
import { type ApprovalRecord, type ApprovalRequirement, approvalRequirements, bindReviewReport, exportReadiness, recordApproval, type ReviewInputs, reviewInputsSha, type ReviewReport, type ReviewSnapshot } from '../policyfix/approvals';
import { buildBaselines } from '../policyfix/baselines';
import { compile, type CompileOutput } from '../policyfix/compile';
import type { EvaluationContext } from '../policyfix/context';
import { digestOf, policySha } from '../policyfix/digest';
import { makeError, type PolicyError } from '../policyfix/errors';
import { generateFixtures } from '../policyfix/fixtures';
import { classifyLine } from '../policyfix/freetext/classify';
import { parseThresholdConfig, UNCALIBRATED_THRESHOLDS } from '../policyfix/freetext/thresholds';
import { parseImportText } from '../policyfix/action';
import { MAX_DISPOSITIONS } from '../policyfix/limits';
import { type Answers, type ContextKey, defaultAnswers, parseReferenceAnswers } from '../policyfix/questionnaire';
import { evaluatePolicy } from '../policyfix/score';
import { ENGINE_VERSION, GRAMMAR_VERSION } from '../policyfix/version';
import { classifyLineRemote, type RemoteProvider } from '../providers/remote';
import { Approvals } from './Approvals';
import { Errors } from './Errors';
import { Export } from './Export';
import { FixtureTable } from './FixtureTable';
import { FreeText } from './FreeText';
import { ImportDraft } from './ImportDraft';
import { ModeBanner } from './ModeBanner';
import { PolicyView } from './PolicyView';
import { Questionnaire } from './Questionnaire';
import { type BaselineComparison, Report } from './Report';

const FALLBACK_CONTEXT: EvaluationContext = { project_root: '/workspace/demo', cwd: '/workspace/demo', home: '/home/dev', path_flavor: 'posix', case_insensitive_fs: false, grammar_version: GRAMMAR_VERSION };

function inputsFromDraft(draft: Draft): ReviewInputs {
  return { answers: draft.answers, default_unmatched: draft.default_unmatched, lines: draft.lines.map((line) => ({ ...line, classification: null })), thresholds: draft.thresholds, thresholds_text: draft.thresholds_text, raw_answers: draft.raw_answers, revision: 0 };
}

function initialState(): { inputs: ReviewInputs; message: string } {
  const neutral: ReviewInputs = { answers: defaultAnswers(FALLBACK_CONTEXT), default_unmatched: 'allow', lines: [], thresholds: UNCALIBRATED_THRESHOLDS, thresholds_text: JSON.stringify(UNCALIBRATED_THRESHOLDS, null, 2), raw_answers: {}, revision: 0 };
  try {
    const stored = loadDraft(window.localStorage);
    if (!stored.ok) return { inputs: neutral, message: 'Saved draft could not be loaded. This tab still works without draft storage.' };
    return stored.value === null ? { inputs: neutral, message: 'Your inputs will be saved in this browser when storage is available.' } : { inputs: inputsFromDraft(stored.value), message: 'Draft restored. Classify any NOT lines and create a fresh report. Remote providers remain off.' };
  } catch { return { inputs: neutral, message: 'Draft storage is unavailable. You can continue in this tab.' }; }
}

export function App(): ReactElement {
  const [initial] = useState(initialState);
  const [inputs, setInputs] = useState<ReviewInputs>(initial.inputs);
  const latestInputs = useRef(inputs); latestInputs.current = inputs;
  const [storageMessage, setStorageMessage] = useState(initial.message);
  const [contextKey, setContextKey] = useState<ContextKey>('posix');
  const [formVersion, setFormVersion] = useState(0);
  const [compiled, setCompiled] = useState<{ readonly output: CompileOutput; readonly source_sha256: string; readonly answers: Answers; readonly freeText: readonly { readonly id: string; readonly text: string }[] } | null>(null);
  const [fixtures, setFixtures] = useState<readonly Fixture[]>([]);
  const [fixturePolicySha, setFixturePolicySha] = useState<string | null>(null);
  const [fixtureText, setFixtureText] = useState('');
  const [fixturesDirty, setFixturesDirty] = useState(false);
  const [report, setReport] = useState<ReviewReport | null>(null);
  const [baselines, setBaselines] = useState<BaselineComparison | null>(null);
  const [records, setRecords] = useState<readonly ApprovalRecord[]>([]);
  const [errors, setErrors] = useState<readonly PolicyError[]>([]);
  const [message, setMessage] = useState('');
  const [busyIds, setBusyIds] = useState<readonly string[]>([]);
  const [optedIn, setOptedIn] = useState<Readonly<Record<RemoteProvider, boolean>>>({ jev: false, llm: false });
  const latestOptIn = useRef(optedIn); latestOptIn.current = optedIn;
  const requests = useRef(new Map<string, symbol>());

  const edit = (change: (current: ReviewInputs) => Omit<ReviewInputs, 'revision'>): void => {
    const current = latestInputs.current;
    const next = { ...change(current), revision: current.revision + 1 };
    latestInputs.current = next; setInputs(next);
    setErrors([]); setMessage('Inputs changed. The previous report needs a fresh replay.');
  };

  useEffect(() => {
    // Storage APIs (including the localStorage getter) can throw. Do not overwrite a valid saved draft with invalid answers.
    try {
      const result = saveDraft(window.localStorage, inputs);
      setStorageMessage(result.ok ? 'Questionnaire and NOT-line inputs saved in this browser. Fixtures, reports and approvals are kept only in this tab.' : 'Draft not saved: inputs are invalid, or storage is full or blocked. Keep this tab open or copy valid Draft JSON.');
    } catch { setStorageMessage('Draft storage is unavailable. Keep this tab open or copy Draft JSON.'); }
  }, [inputs]);

  const source = reviewInputsSha(inputs);
  const compiledCurrent = compiled !== null && source.ok && source.value === compiled.source_sha256;
  const requirements = compiled === null ? null : approvalRequirements(compiled.output, fixtures, inputs);
  const snapshot: ReviewSnapshot | null = compiled === null || requirements === null || !requirements.ok ? null : {
    policy: compiled.output.policy, fixtures, inputs, provenance: compiled.output.provenance,
    compiled_source_sha256: compiled.source_sha256, requirements: requirements.value,
    report: report === null ? null : { ...report, approvals: records }, approvals: records,
  };
  const readiness = snapshot === null ? null : exportReadiness(snapshot);
  const reportCurrent = readiness?.ok === true && readiness.value.report_current && !fixturesDirty;
  const policyHash = compiled === null ? null : policySha(compiled.output.policy);
  const fixturesCurrent = policyHash?.ok === true && fixturePolicySha === policyHash.value && !fixturesDirty;

  const runCompile = (): void => {
    const current = latestInputs.current;
    const accepted = acceptedItems(current);
    if (!accepted.ok) { setErrors(accepted.errors); return; }
    const result = compile(current.answers, accepted.value, current.answers.Q01.context, { default_unmatched: current.default_unmatched });
    const hash = reviewInputsSha(current);
    if (!result.ok) { setErrors(result.errors); return; }
    if (!hash.ok) { setErrors(hash.errors); return; }
    setCompiled({ output: result.value, source_sha256: hash.value, answers: current.answers, freeText: current.lines.map(({ id, text }) => ({ id, text })) }); setErrors([]);
    setMessage('Policy compiled. Generate fixtures, then replay to review this version.');
  };

  const generate = (): void => {
    if (compiled === null || !compiledCurrent) return;
    const generated = generateFixtures(compiled.output, { dialects: ['posix', 'powershell', 'cmd'] });
    if (!generated.ok) { setErrors(generated.errors); return; }
    const hash = policySha(compiled.output.policy);
    if (!hash.ok) { setErrors(hash.errors); return; }
    setFixtures(generated.value.fixtures); setFixturePolicySha(hash.value);
    setFixtureText(JSON.stringify({ fixtures: generated.value.fixtures }, null, 2)); setFixturesDirty(false);
    setErrors([]); setMessage(`Generated ${generated.value.fixtures.length} fixtures across all three supported shell dialects. Replay to refresh the report.`);
    // Fixture changes are represented by fixtures_sha. Do not stale the just-compiled source snapshot.
  };

  const applyFixtures = (): void => {
    if (compiled === null || !compiledCurrent) { setErrors([makeError('inconsistent', '/fixtures', 'Compile the current inputs before applying fixture JSON.')]); return; }
    const parsed = parseFixtures(fixtureText, compiled.output.policy);
    if (!parsed.ok) { setErrors(parsed.errors); return; }
    const hash = policySha(compiled.output.policy);
    if (!hash.ok) { setErrors(hash.errors); return; }
    setFixtures(parsed.value.fixtures); setFixturePolicySha(hash.value); setFixturesDirty(false); setErrors([]);
    setMessage('Fixture edits applied. Replay the current fixtures to refresh the report.');
  };

  const runReplay = (): void => {
    if (compiled === null || !compiledCurrent || !fixturesCurrent) return;
    const scored = evaluatePolicy(compiled.output.policy, fixtures);
    if (!scored.ok) { setErrors(scored.errors); return; }
    const bound = bindReviewReport(scored.value, latestInputs.current, records);
    if (!bound.ok) { setErrors(bound.errors); return; }
    const comparison = buildBaselines(inputs.answers, inputs.answers.Q01.context, inputs.default_unmatched);
    const exact = (id: 'B1' | 'B2'): { k: number; n: number } => ({ k: fixtures.filter((fixture) => comparison[id].evaluate(fixture.action).verdict === (fixture.expected_policy ?? fixture.expected_local)).length, n: fixtures.length });
    setBaselines({ B1: exact('B1'), B2: exact('B2') }); setReport(bound.value); setErrors([]);
    setMessage(`Replay complete: ${bound.value.status}. Review the findings and required decisions.`);
  };

  const classify = async (id: string): Promise<void> => {
    const captured = latestInputs.current;
    const line = captured.lines.find((candidate) => candidate.id === id);
    if (line === undefined) return;
    const thresholdJson = parseImportText(captured.thresholds_text);
    if (!thresholdJson.ok || parseThresholdConfig(thresholdJson.value) === null) { setErrors([makeError('invalid_value', '/thresholds', 'Correct the threshold JSON before classifying.')]); return; }
    if ((line.provider === 'jev' || line.provider === 'llm') && !latestOptIn.current[line.provider]) return;
    const requestVersion = captured.revision; const token = Symbol(id); requests.current.set(id, token);
    setBusyIds((ids) => [...new Set([...ids, id])]);
    try {
      const classification = await classifyLine({ id, line: line.text, context: captured.answers.Q01.context, provider: line.provider }, {
        thresholds: captured.thresholds,
        remote: async ({ line: text, provider }) => {
          const reply = await classifyLineRemote({ line: text, provider, optedIn: latestOptIn.current[provider] });
          if (reply.kind === 'ok') return { kind: 'ok', label: reply.label, confidence: reply.confidence };
          return { kind: reply.kind === 'fallback' ? 'fallback' : 'error', reason: reply.kind === 'fallback' ? `Remote classifier fallback: ${reply.reason}.` : `Remote classification unavailable: ${reply.code}.` };
        },
      });
      if (latestInputs.current.revision !== requestVersion || requests.current.get(id) !== token || ((line.provider === 'jev' || line.provider === 'llm') && !latestOptIn.current[line.provider])) {
        setMessage('A classification reply was discarded because its inputs changed. Classify the current line again.'); return;
      }
      edit((current) => ({ ...current, lines: current.lines.map((candidate) => candidate.id === id ? { ...candidate, classification, params_text: candidate.params_text || JSON.stringify(classification.item.params ?? {}, null, 2) } : candidate) }));
      setMessage(classification.item.label === 'manual' ? 'Line retained as a manual item. It will remain a Gap.' : 'Suggested rule ready. Review the extracted parameters, then compile.');
    } catch {
      setErrors([makeError('invalid_value', `/lines/${id}`, 'Classification could not be completed. Your line has been retained; try classifying it again.')]);
    } finally {
      if (requests.current.get(id) === token) { requests.current.delete(id); setBusyIds((ids) => ids.filter((candidate) => candidate !== id)); }
    }
  };

  const addLines = (texts: readonly string[]): void => {
    if (inputs.lines.length + texts.length > MAX_DISPOSITIONS - 12) { setErrors([makeError('too_many', '/lines', 'Too many NOT lines.', MAX_DISPOSITIONS - 12)]); return; }
    const mode = startupClassifierMode(requestedClassifierMode);
    edit((current) => ({ ...current, lines: [...current.lines, ...texts.map((text) => ({ id: `line-${crypto.randomUUID()}`, text, provider: mode, classification: null, params_text: '' }))] }));
  };

  const importDraft = (draft: Draft): void => {
    const next = { ...inputsFromDraft(draft), revision: latestInputs.current.revision + 1 }; latestInputs.current = next; setInputs(next);
    // Avoid revision reuse with in-flight callbacks. Explicit import is always a new source version.
    requests.current.clear(); setBusyIds([]); setCompiled(null); setFixtures([]); setFixturePolicySha(null); setFixtureText(''); setFixturesDirty(false);
    setReport(null); setBaselines(null); setRecords([]); setErrors([]); setFormVersion((value) => value + 1);
    const off = { jev: false, llm: false }; latestOptIn.current = off; setOptedIn(off);
  };

  const approve = (requirement: ApprovalRequirement): void => {
    if (!compiledCurrent || !fixturesCurrent || !reportCurrent) return;
    setRecords((current) => [...current, recordApproval(requirement, new Date().toISOString())]);
  };

  return <div className="app"><header className="app-header"><p className="eyebrow">Agent policy workshop</p><h1>Agent NOT-List Builder</h1><p className="tagline">Turn your agent’s NOT list into reviewable policy tests.</p></header>
    <ModeBanner supabaseConfigured={isSupabaseConfigured} classifierMode={startupClassifierMode(requestedClassifierMode)} activeRemoteProviders={(['jev', 'llm'] as const).filter((id) => optedIn[id])} />
    <p className="notice">Source has been constructed but has not been run or validated in a browser. Replay checks this evaluator only; it is not a security boundary.</p>
    <nav aria-label="Build steps" className="step-nav"><a href="#questionnaire-heading">1. Answer</a><a href="#freetext-heading">2. Add NOT lines</a><a href="#policy-heading">3. Compile</a><a href="#fixtures-heading">4. Replay</a><a href="#report-heading">5. Review</a><a href="#export-heading">6. Export</a></nav>
    <main><Questionnaire answers={inputs.answers} onChange={(answers: Answers) => { edit((current) => ({ ...current, answers })); }} formVersion={formVersion} contextKey={contextKey} onContextKeyChange={setContextKey} defaultUnmatched={inputs.default_unmatched} onDefaultUnmatchedChange={(value) => { edit((current) => ({ ...current, default_unmatched: value })); }} onLoadSample={() => {
      const sample = parseReferenceAnswers(referenceAnswersJson as unknown, contextKey);
      if (!sample.ok) { setErrors(sample.errors); return; }
      edit((current) => ({ ...current, answers: sample.value.answers, default_unmatched: sample.value.default_unmatched, raw_answers: {} })); setFormVersion((value) => value + 1);
    }} onCompile={runCompile} sampleError={null} rawAnswers={inputs.raw_answers} onRawChange={(key, text) => { edit((current) => ({ ...current, raw_answers: { ...current.raw_answers, [key]: text } })); }} />
      <FreeText lines={inputs.lines} onAdd={() => { addLines(['']); }} onDemo={() => { addLines(['never run terraform destroy', 'never push to the hotfix branch', 'never be rude to customers']); }} onChange={(id, patch) => {
        edit((current) => ({ ...current, lines: current.lines.map((line) => line.id !== id ? line : { ...line, ...patch, ...(patch.text !== undefined || patch.provider !== undefined ? { classification: null, params_text: '' } : {}) }) }));
      }} onRemove={(id) => { edit((current) => ({ ...current, lines: current.lines.filter((line) => line.id !== id) })); }} onClassify={(id) => { void classify(id); }} busyIds={busyIds} configured={isSupabaseConfigured} optedIn={optedIn} onOptIn={(provider, enabled) => {
        const next = { ...latestOptIn.current, [provider]: enabled }; latestOptIn.current = next; setOptedIn(next);
        if (!enabled) {
          const cancelled = latestInputs.current.lines.filter((line) => line.provider === provider).map((line) => line.id);
          for (const id of cancelled) requests.current.delete(id);
          setBusyIds((ids) => ids.filter((id) => !cancelled.includes(id)));
        }
      }} thresholdsText={inputs.thresholds_text} onThresholdsChange={(text) => {
        const json = parseImportText(text); const thresholds = json.ok ? parseThresholdConfig(json.value) : null;
        edit((current) => ({ ...current, thresholds_text: text, thresholds: thresholds ?? current.thresholds,
          lines: current.lines.map((line) => {
            if (thresholds === null || (line.provider !== 'jev' && line.provider !== 'llm')) return line;
            const before = digestOf({ value: current.thresholds[line.provider], provenance: current.thresholds.provenance });
            const after = digestOf({ value: thresholds[line.provider], provenance: thresholds.provenance });
            return before.ok && after.ok && before.value === after.value ? line : { ...line, classification: null };
          }),
        }));
      }} />
      <section className="workflow-actions" aria-label="Policy actions"><div className="toolbar"><button type="button" onClick={runCompile}>Compile current policy</button><button type="button" disabled={!compiledCurrent} onClick={generate}>Generate fixtures</button><button type="button" disabled={!compiledCurrent || !fixturesCurrent} onClick={runReplay}>Replay with fake tools</button></div><p role="status">{message}</p><Errors errors={errors} />{requirements !== null && !requirements.ok ? <Errors errors={requirements.errors} /> : null}</section>
      {compiled === null ? <section id="policy-heading"><h2>Compiled policy</h2><p className="empty">Compile your answers and classified NOT lines to see rules and dispositions.</p></section> : <><p className={compiledCurrent ? 'hint' : 'warning'} role="status">{compiledCurrent ? 'Policy matches the current inputs.' : 'Policy below belongs to earlier inputs. Compile to refresh it.'}</p><PolicyView key={compiled.source_sha256} result={{ ok: true, value: compiled.output }} answers={compiled.answers} freeText={compiled.freeText} /></>}
      <FixtureTable fixtures={fixtures} report={report} current={reportCurrent} text={fixtureText} onTextChange={(text) => {
        setFixtureText(text); setFixturesDirty(true); edit((current) => ({ ...current }));
      }} onApply={applyFixtures} />
      <Report report={report} current={reportCurrent} baselines={baselines} />
      <Approvals requirements={requirements?.ok === true ? requirements.value : []} records={records} disabled={!compiledCurrent || !fixturesCurrent || !reportCurrent} onApprove={approve} />
      <Export snapshot={snapshot} readiness={readiness} />
      <p role="status" className="storage-status">{storageMessage}</p><ImportDraft inputs={inputs} onImport={importDraft} />
    </main><footer className="app-footer">Engine {ENGINE_VERSION} · grammar {GRAMMAR_VERSION} · Manual restrictions remain unexecutable. Acknowledgement never authorizes a real action.</footer></div>;
}

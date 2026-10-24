import { type ReactElement, useState } from 'react';
import referenceAnswersJson from '../../eval/gold/reference-answers.json';
import { isSupabaseConfigured, requestedClassifierMode, startupClassifierMode } from '../lib/supabase';
import type { DefaultUnmatched } from '../policyfix/action';
import { compile, type CompileOutput } from '../policyfix/compile';
import type { EvaluationContext } from '../policyfix/context';
import type { Result } from '../policyfix/errors';
import { type Answers, type ContextKey, defaultAnswers, parseReferenceAnswers } from '../policyfix/questionnaire';
import { ENGINE_VERSION, GRAMMAR_VERSION } from '../policyfix/version';
import { ModeBanner } from './ModeBanner';
import { PolicyView } from './PolicyView';
import { Questionnaire } from './Questionnaire';

/** The demo journey (Claude §1.3). M3 builds steps 1–2; later milestones replace each remaining placeholder. */
const JOURNEY_STEPS: readonly { readonly step: string; readonly built: boolean }[] = [
  { step: 'Answer the 12-question questionnaire (or load the sample answers)', built: true },
  { step: 'Compile the answers into policy rules', built: true },
  { step: 'Add free-text NOT lines', built: false },
  { step: 'Generate fixtures', built: false },
  { step: 'Replay fixtures through fake tools', built: false },
  { step: 'Review the Pass / Fail / Gap report', built: false },
  { step: 'Acknowledge, approve and export the bundle', built: false },
];

const FALLBACK_CONTEXT: EvaluationContext = {
  project_root: '/workspace/demo',
  cwd: '/workspace/demo',
  home: '/home/dev',
  path_flavor: 'posix',
  case_insensitive_fs: false,
  grammar_version: GRAMMAR_VERSION,
};

export function App(): ReactElement {
  const classifierMode = startupClassifierMode(requestedClassifierMode);
  const [contextKey, setContextKey] = useState<ContextKey>('posix');
  const [answers, setAnswers] = useState<Answers>(() => defaultAnswers(FALLBACK_CONTEXT));
  const [defaultUnmatched, setDefaultUnmatched] = useState<DefaultUnmatched>('allow');
  const [formVersion, setFormVersion] = useState(0);
  const [compiled, setCompiled] = useState<Result<CompileOutput> | null>(null);
  const [sampleError, setSampleError] = useState<string | null>(null);

  const loadSample = (): void => {
    // The same reference answers the published eval uses (eval/gold/reference-answers.json, CONTRACTS C3).
    const reference = parseReferenceAnswers(referenceAnswersJson as unknown, contextKey);
    if (!reference.ok) {
      setSampleError(`Sample answers are invalid: ${reference.errors.map((error) => error.message).join('; ')}`);
      return;
    }
    setSampleError(null);
    setAnswers(reference.value.answers);
    setDefaultUnmatched(reference.value.default_unmatched);
    setFormVersion((version) => version + 1);
    setCompiled(null);
  };

  const runCompile = (): void => {
    setCompiled(compile(answers, [], answers.Q01.context, { default_unmatched: defaultUnmatched }));
  };

  const changeAnswers = (next: Answers): void => {
    setAnswers(next);
    setCompiled(null); // a compiled view never shows rules for answers it was not built from
  };

  return (
    <div className="app">
      <header className="app-header">
        <h1>Agent NOT-List Builder</h1>
        <p className="tagline">Turn an agent&apos;s NOT list into executable policy tests.</p>
      </header>
      <ModeBanner supabaseConfigured={isSupabaseConfigured} classifierMode={classifierMode} />
      <main>
        <section aria-labelledby="journey-heading">
          <h2 id="journey-heading">Journey</h2>
          <ol className="journey">
            {JOURNEY_STEPS.map(({ step, built }) => (
              <li key={step}>
                {step} {built ? null : <span className="pending">(not built yet)</span>}
              </li>
            ))}
          </ol>
        </section>
        <Questionnaire
          answers={answers}
          onChange={changeAnswers}
          formVersion={formVersion}
          contextKey={contextKey}
          onContextKeyChange={setContextKey}
          defaultUnmatched={defaultUnmatched}
          onDefaultUnmatchedChange={(value) => {
            setDefaultUnmatched(value);
            setCompiled(null);
          }}
          onLoadSample={loadSample}
          onCompile={runCompile}
          sampleError={sampleError}
        />
        {compiled === null ? (
          <p className="hint">Compile the answers to see the policy.</p>
        ) : (
          <PolicyView result={compiled} answers={answers} />
        )}
      </main>
      <footer className="app-footer">
        Engine {ENGINE_VERSION} · grammar {GRAMMAR_VERSION} · Replay checks this evaluator only; it is not a security
        boundary and does not prove an agent enforces the policy.
      </footer>
    </div>
  );
}

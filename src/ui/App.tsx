import type { ReactElement } from 'react';
import { isSupabaseConfigured, requestedClassifierMode, startupClassifierMode } from '../lib/supabase';
import { ENGINE_VERSION, GRAMMAR_VERSION } from '../policyfix/version';
import { ModeBanner } from './ModeBanner';

/** The demo journey (Claude §1.3). M1 ships the shell only; later milestones replace each placeholder. */
const JOURNEY_STEPS: readonly string[] = [
  'Answer the 12-question questionnaire (or load the sample answers)',
  'Compile the answers into policy rules',
  'Add free-text NOT lines',
  'Generate fixtures',
  'Replay fixtures through fake tools',
  'Review the Pass / Fail / Gap report',
  'Acknowledge, approve and export the bundle',
];

export function App(): ReactElement {
  const classifierMode = startupClassifierMode(requestedClassifierMode);
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
          <p>
            Scaffold only. None of the steps below is built yet; each will appear here as its milestone lands.
          </p>
          <ol className="journey">
            {JOURNEY_STEPS.map((step) => (
              <li key={step}>
                {step} <span className="pending">(not built yet)</span>
              </li>
            ))}
          </ol>
        </section>
      </main>
      <footer className="app-footer">
        Engine {ENGINE_VERSION} · grammar {GRAMMAR_VERSION} · Replay checks this evaluator only; it is not a security
        boundary and does not prove an agent enforces the policy.
      </footer>
    </div>
  );
}

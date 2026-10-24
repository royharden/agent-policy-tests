import type { ReactElement } from 'react';
import type { ClassifierMode } from '../lib/supabase';

export interface ModeBannerProps {
  readonly supabaseConfigured: boolean;
  readonly classifierMode: ClassifierMode;
}

/** Always-visible mode banner (Claude §1.3 step 1): no click needed to learn that live classifiers are off. */
export function ModeBanner({ supabaseConfigured, classifierMode }: ModeBannerProps): ReactElement {
  if (!supabaseConfigured) {
    return (
      <div className="banner banner-mock" role="status" data-mode="mock">
        <strong>Mock mode</strong> — live classifiers disabled (no Supabase config). Classifier:{' '}
        <code>{classifierMode}</code>. Everything runs in this browser; this mode makes no network calls by design.
      </div>
    );
  }
  return (
    <div className="banner banner-local" role="status" data-mode="local">
      <strong>Local mode</strong> — Supabase is configured, but remote classifiers (Jev, LLM) stay off until you opt
      in. Classifier: <code>{classifierMode}</code>.
    </div>
  );
}

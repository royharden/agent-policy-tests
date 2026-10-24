import type { ReactElement } from 'react';
import type { ClassifierMode } from '../lib/supabase';

export interface ModeBannerProps {
  readonly supabaseConfigured: boolean;
  readonly classifierMode: ClassifierMode;
  readonly activeRemoteProviders?: readonly string[];
}

/** Always-visible mode banner (Claude §1.3 step 1): no click needed to learn that live classifiers are off. */
export function ModeBanner({ supabaseConfigured, classifierMode, activeRemoteProviders = [] }: ModeBannerProps): ReactElement {
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
      <strong>{activeRemoteProviders.length === 0 ? 'Local mode' : 'Remote providers enabled'}</strong> — {activeRemoteProviders.length === 0
        ? 'Remote classifiers stay off until you opt in.'
        : `${activeRemoteProviders.join(', ')} enabled for explicit Classify actions in this tab.`} Local default: <code>{classifierMode}</code>.
    </div>
  );
}

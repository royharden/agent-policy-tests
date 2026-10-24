import type { ReactElement } from 'react';
import type { PolicyError } from '../policyfix/errors';

export function Errors({ errors }: { readonly errors: readonly PolicyError[] }): ReactElement | null {
  if (errors.length === 0) return null;
  return <div className="error" role="alert"><ul>{errors.map((error, index) => <li key={`${error.pointer}:${error.code}:${index}`}>
    <code>{error.pointer || '/'} · {error.code}</code>: {error.message}{error.limit === undefined ? '' : ` (limit ${error.limit})`}
  </li>)}</ul></div>;
}

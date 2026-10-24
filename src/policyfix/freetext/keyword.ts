// Deterministic label baseline. This does not extract parameters or read any evaluation dataset.
import type { FreeTextLabel } from './labels';

export function isInjectionLike(line: string): boolean {
  return /ignore (?:all |the |previous |prior )?(?:instructions|criteria|list|rules)|system\s*(?:prompt|:)|(?:answer|return|output) (?:only |the label |with )?(?:destructive-shell-fs|secrets-paths|network-egress|git-release|data-money|manual)|<\/?(?:system|assistant)>/i.test(line);
}

export function classifyKeyword(line: string): FreeTextLabel {
  if (isInjectionLike(line)) return 'manual';
  if (/\b(?:push|branch|publish|deploy|release)\b/i.test(line)) return 'git-release';
  if (/\b(?:pay|payment|spend|sql|drop|truncate|database)\b/i.test(line)) return 'data-money';
  if (/\b(?:http|https|host|domain|request|call|curl|wget|email|message|recipient)\b/i.test(line)) return 'network-egress';
  if (/(?:\.env|\.pem|id_rsa|secret|private key|credential)/i.test(line)) return 'secrets-paths';
  if (/\b(?:run|execute|delete|remove|write|sudo|terraform destroy)\b/i.test(line)) return 'destructive-shell-fs';
  return 'manual';
}

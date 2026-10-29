// Fixed demo lookup, independently authored here. Never imports gold or keyword labels. Excluded from accuracy.
import type { FreeTextLabel } from './labels';
import { isInjectionLike } from './keyword';

export const MOCK_DEMO_LINES: Readonly<Record<string, FreeTextLabel>> = {
  'never run terraform destroy': 'destructive-shell-fs',
  'never run rm -rf build': 'destructive-shell-fs',
  'never write ./private': 'destructive-shell-fs',
  'never delete ./archive': 'destructive-shell-fs',
  'never push to the hotfix branch': 'git-release',
  'never delete the release/* branch': 'git-release',
  'never call telemetry.example.test': 'network-egress',
  'only call api.example.test': 'network-egress',
  'never touch .env': 'secrets-paths',
  'never pay more than 25 USD': 'data-money',
  'never be rude to customers': 'manual',
};

export function classifyMock(line: string): FreeTextLabel {
  if (isInjectionLike(line)) return 'manual';
  return MOCK_DEMO_LINES[line.trim().toLowerCase()] ?? 'manual';
}

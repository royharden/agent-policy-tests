// The five templates (spec item 2; PLAN M3). Order is the questionnaire order of the answers they own.
// Framework-free.
import type { TemplateId } from '../action';
import type { PolicyTemplate } from './common';
import { dataMoneyTemplate } from './data-money';
import { destructiveShellFsTemplate } from './destructive-shell-fs';
import { gitReleaseTemplate } from './git-release';
import { networkEgressTemplate } from './network-egress';
import { secretsPathsTemplate } from './secrets-paths';

export type {
  AnswerOutcome,
  CompiledRule,
  ConflictOwnership,
  DeclaredExample,
  ExampleKind,
  FreeTextParams,
  PolicyTemplate,
} from './common';

export const TEMPLATES: readonly PolicyTemplate[] = [
  destructiveShellFsTemplate,
  secretsPathsTemplate,
  networkEgressTemplate,
  gitReleaseTemplate,
  dataMoneyTemplate,
];

export const TEMPLATES_BY_ID: Readonly<Record<TemplateId, PolicyTemplate>> = {
  'destructive-shell-fs': destructiveShellFsTemplate,
  'secrets-paths': secretsPathsTemplate,
  'network-egress': networkEgressTemplate,
  'git-release': gitReleaseTemplate,
  'data-money': dataMoneyTemplate,
};

export function templateById(id: TemplateId): PolicyTemplate {
  return TEMPLATES_BY_ID[id];
}

/**
 * Conflict ownership lookup for M4 (Claude §2.8): may `owner` block a permitted near-miss of `template` with `effect`?
 */
export function isDeclaredConflict(template: TemplateId, owner: TemplateId, effect: 'deny' | 'ask'): boolean {
  return TEMPLATES_BY_ID[template].conflicts.some(
    (declaration) => declaration.owner_template === owner && declaration.effect === effect,
  );
}

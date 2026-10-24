// Frozen dev-only, bounded-effort comparator. Authored by reading actions.dev.jsonl, without executing/tuning it.
// This is deliberately separate from the regex-free policy matcher. Do not tune against held-out failures.
import type { Action, Verdict } from '../../src/policyfix/action';
import type { EvaluationContext } from '../../src/policyfix/context';
import type { Answers } from '../../src/policyfix/questionnaire';

export const B4_AUTHORING = { split: 'dev', started_at: '2026-10-24T22:34:52Z', frozen_at: '2026-10-24T22:38:16Z', effort_cap_minutes: 30, timing: 'Conservative enclosing clock interval includes other construction; exact active effort unmeasured.', frozen: true, evaluated: false } as const;
export const B4_RULES = [
  { question: 'Q04', effect: 'deny', pattern: '(^|[;&|]\\s*)(sudo|doas|runas)\\s', flags: 'i' },
  { question: 'Q03', effect: 'deny', pattern: '(^|[;&|]\\s*|\\\\)rm\\s+[^\\n]*(-[rfRF]|--recursive|--force)', flags: 'i' },
  { question: 'Q08', effect: 'deny', pattern: '^git\\s+push\\b[^\\n]*(--force|-f\\b|--mirror|\\s\\+)', flags: 'i' },
  { question: 'Q10', effect: 'deny', pattern: '(^|[;&|]\\s*)(npm\\s+publish|vercel[^\\n]*--prod|terraform\\s+apply|gh\\s+release\\s+create)\\b', flags: 'i' },
  { question: 'Q11', effect: 'deny', pattern: '^\\s*(DROP|TRUNCATE)\\b|^\\s*(DELETE|UPDATE)\\b(?![^;]*\\bWHERE\\b)', flags: 'i' },
  { question: 'opaque', effect: 'ask', pattern: '(^|[;&|]\\s*)(eval|source|iex|Invoke-Expression)\\b|\\|\\s*(sh|bash)\\b|python[0-9]*\\s+-c\\b|\\$[A-Za-z_][A-Za-z0-9_]*', flags: 'i' },
] as const;

function escape(text: string): string { return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

export function evaluateB4(action: Action, answers: Answers, context: EvaluationContext): Verdict {
  const raw = action.kind === 'shell' ? action.command : action.kind === 'sql' ? action.statement : action.kind === 'git' ? `git ${action.args.join(' ')}` : action.kind === 'fs' ? action.path : JSON.stringify(action);
  const effects: Verdict[] = [];
  for (const rule of B4_RULES) {
    const enabled = rule.question === 'opaque' || (rule.question === 'Q04' && answers.Q04.block) || (rule.question === 'Q03' && answers.Q03.block) || (rule.question === 'Q08' && answers.Q08.block) || (rule.question === 'Q10' && answers.Q10.mode !== 'none') || (rule.question === 'Q11' && answers.Q11.block);
    if (!enabled || !new RegExp(rule.pattern, rule.flags).test(raw)) continue;
    if (rule.question === 'Q03' && answers.Q03.except.some((item) => raw.includes(item))) continue;
    if (rule.question === 'Q10' && /\bnpm\s+publish\b.*--dry-run\b/i.test(raw)) continue;
    effects.push(rule.question === 'Q10' && answers.Q10.mode === 'ask' ? 'ask' : rule.effect);
  }
  if (action.kind === 'fs' && answers.Q02.block && ['write', 'delete'].includes(action.op)) {
    const absolute = action.path.startsWith('/') || /^[A-Za-z]:/.test(action.path) || action.path.startsWith('~');
    if ((absolute && !new RegExp(`^${escape(context.project_root)}(?:[/\\\\]|$)`, context.case_insensitive_fs ? 'i' : '').test(action.path)) || action.path.startsWith('..')) effects.push('deny');
  }
  const secretText = action.kind === 'fs' ? action.path : raw;
  if ((action.kind === 'fs' && action.op !== 'list') || action.kind === 'shell') {
    const hit = answers.Q05.secret_globs.some((glob) => new RegExp(escape(glob).replaceAll('\\*', '[^ ]*'), 'i').test(secretText));
    if (hit && !answers.Q05.exceptions.some((item) => secretText.includes(item))) effects.push('deny');
  }
  if (action.kind === 'http' && answers.Q06.enabled) {
    const allowed = answers.Q06.hosts.some((host) => new RegExp(`^https?://${escape(host).replaceAll('\\*', '[^/@]+')}(?=[:/?#]|$)`, 'i').test(action.url));
    effects.push(allowed ? (action.url.includes('@') ? 'ask' : 'allow') : 'deny');
  }
  if (action.kind === 'message' && answers.Q07.enabled) effects.push(answers.Q07.domains.some((domain) => new RegExp(`@${escape(domain)}$`, 'i').test(action.to)) ? 'allow' : action.to.includes('@') ? 'deny' : 'ask');
  if (action.kind === 'git' && action.args[0] === 'push' && answers.Q09.branches.length > 0) {
    if (action.args.length < 3) effects.push('ask');
    if (answers.Q09.branches.some((branch) => new RegExp(`(^|:|\\s)${escape(branch).replaceAll('\\*', '[^/ ]+')}$`).test(action.args.join(' ')))) effects.push('deny');
  }
  if (action.kind === 'payment' && answers.Q12.limit_cents !== null) effects.push(action.currency !== answers.Q12.currency ? 'ask' : action.amount_cents > answers.Q12.limit_cents ? 'deny' : 'allow');
  return effects.includes('deny') ? 'deny' : effects.includes('ask') ? 'ask' : 'allow';
}

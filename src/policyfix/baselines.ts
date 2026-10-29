// Intentionally naive comparison baselines. They consume the same typed answers/context, but never import or call
// the scanner, normalizer, matcher or guard. B1 searches raw substrings; B2 checks raw prefixes. Neither is enforcement.
import type { Action, DefaultUnmatched, RuleEffect } from './action';
import type { EvaluationContext } from './context';
import type { GuardResult } from './guard';
import type { Answers } from './questionnaire';

export interface NaiveBaseline {
  readonly id: 'B1' | 'B2';
  readonly label: string;
  evaluate(action: Action): GuardResult;
}

function rawText(action: Action): string {
  switch (action.kind) {
    case 'shell': return action.command.trim();
    case 'fs': return `${action.op} ${action.path}`;
    case 'http': return action.url;
    case 'sql': return action.statement;
    case 'git': return `git ${action.args.join(' ')}`;
    case 'payment': return `payment ${action.amount_cents} ${action.currency}`;
    case 'message': return action.to;
  }
}

function buildBaseline(id: 'B1' | 'B2', answers: Answers, context: EvaluationContext, defaultUnmatched: DefaultUnmatched): NaiveBaseline {
  return {
    id,
    label: id === 'B1' ? 'Raw substring deny-list' : 'Raw prefix deny-list',
    evaluate(action: Action): GuardResult {
      const raw = rawText(action);
      const text = raw.toLowerCase();
      const hits: { id: string; effect: RuleEffect }[] = [];
      const has = (needle: string): boolean => id === 'B1' ? text.includes(needle.toLowerCase()) : text.startsWith(needle.toLowerCase());
      const add = (question: string, effect: RuleEffect, condition: boolean): void => { if (condition) hits.push({ id: `${id.toLowerCase()}-${question}`, effect }); };
      const shellDelete = action.kind === 'shell' && ['rm -rf ', 'rm -fr ', 'rm -r ', 'rm -f '].some(has);
      const outsideFs = action.kind === 'fs' && ['write', 'delete'].includes(action.op) && !action.path.startsWith(context.project_root) && !(!action.path.startsWith('/') && !action.path.includes(':') && !action.path.startsWith('~') && !action.path.startsWith('..'));
      add('q02', 'deny', answers.Q02.block && (outsideFs || (action.kind === 'shell' && ['rm -rf /', 'rm -f /', 'rm -r /', 'rm -rf ~', 'tee ../', 'touch ../'].some(has))));
      add('q03', 'deny', answers.Q03.block && (shellDelete || (action.kind === 'fs' && action.op === 'delete' && action.recursive === true)) && !answers.Q03.except.some((exception) => text.includes(exception.toLowerCase())));
      add('q04', 'deny', answers.Q04.block && ['sudo ', 'doas ', 'runas ', 'start-process '].some(has));
      const secrets = answers.Q05.secret_globs.map((glob) => glob.split('*').join('').split('?').join('')).filter((needle) => needle !== '');
      add('q05', 'deny', secrets.some(has) && !answers.Q05.exceptions.some(has));
      // These deliberately compare unparsed strings: userinfo, suffix lookalikes and wildcard apexes can fool them.
      if (answers.Q06.enabled && (action.kind === 'http' || (action.kind === 'shell' && ['curl ', 'wget '].some(has)))) {
        const allowed = answers.Q06.hosts.some((host) => {
          const needle = host.replaceAll('*.', '').toLowerCase();
          return id === 'B1' ? text.includes(needle) : ['http://', 'https://', 'curl http://', 'curl https://', 'wget http://', 'wget https://'].some((prefix) => text.startsWith(prefix + needle));
        });
        add('q06', 'deny', !allowed);
      }
      if (answers.Q07.enabled && action.kind === 'message') add('q07', 'deny', !answers.Q07.domains.some((domain) => id === 'B1' ? text.includes(domain.toLowerCase()) : text.startsWith(domain.toLowerCase())));
      add('q08', 'deny', answers.Q08.block && ['git push --force', 'git push -f'].some(has));
      add('q09', 'deny', answers.Q09.branches.some((branch) => [`git push origin ${branch}`, `git push --delete origin ${branch}`, `git branch -D ${branch}`].some(has)));
      if (answers.Q10.mode !== 'none') add('q10', answers.Q10.mode, ['npm publish', 'vercel --prod', 'terraform apply', 'gh release create'].some(has));
      add('q11', 'deny', answers.Q11.block && (['drop ', 'truncate '].some(has) || (['delete ', 'update '].some(has) && !text.includes(' where '))));
      if (action.kind === 'payment' && answers.Q12.limit_cents !== null) {
        add('q12-currency', 'ask', action.currency !== answers.Q12.currency);
        add('q12-limit', 'deny', action.currency === answers.Q12.currency && action.amount_cents > answers.Q12.limit_cents);
      }
      hits.sort((a, b) => (a.effect === b.effect ? (a.id < b.id ? -1 : a.id > b.id ? 1 : 0) : a.effect === 'deny' ? -1 : 1));
      const winner = hits[0];
      return { verdict: winner?.effect ?? defaultUnmatched, rule_id: winner?.id ?? null, reason: winner === undefined ? `${id}: unmatched raw text (${defaultUnmatched}).` : `${id}: naive match for ${winner.id}.`, matched_rule_ids: [...new Set(hits.map((hit) => hit.id))].sort() };
    },
  };
}

export function buildBaselines(
  answers: Answers,
  context: EvaluationContext,
  defaultUnmatched: DefaultUnmatched = 'allow',
): Readonly<Record<'B1' | 'B2', NaiveBaseline>> {
  return { B1: buildBaseline('B1', answers, context, defaultUnmatched), B2: buildBaseline('B2', answers, context, defaultUnmatched) };
}

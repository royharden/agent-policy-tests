// Template data-money (Q11 destructive SQL, Q12 payment limit; free text: a payment limit). RUBRIC §3 Q11/Q12.
//   - DROP (any object) and TRUNCATE are denied; DELETE/UPDATE without a top-level WHERE, or with exactly `1=1` / `true`,
//     are denied; comments become spaces, string literals are data, statements split on top-level `;`;
//   - payments: integer cents; amount > limit in the answer currency → deny (via the derived field
//     payment.amount_exceeds with `arg` = limit); any other currency → ask; amount ≤ limit → allow.
// Framework-free.
import { isCurrencyCode, type Rule } from '../action';
import type { EvaluationContext } from '../context';
import type { Answers } from '../questionnaire';
import {
  type AnswerOutcome,
  type CompiledRule,
  type FreeTextParams,
  payment,
  permitted,
  type PolicyTemplate,
  prohibited,
  sh,
  slug,
  sqlAction,
} from './common';

const TEMPLATE = 'data-money' as const;

export const DATA_MONEY_FIELDS = {
  'sql.verb': ['in'],
  'sql.statement': ['sql_without_where'],
  'payment.currency': ['eq'],
  'payment.amount_exceeds': ['eq'],
} as const;

function q11Rules(): CompiledRule[] {
  return [
    {
      rule: {
        id: 'q11-drop-truncate',
        source_answer: 'Q11',
        template: TEMPLATE,
        effect: 'deny',
        match: [{ op: 'in', field: 'sql.verb', values: ['DROP', 'TRUNCATE'] }],
        intent: 'Never DROP or TRUNCATE.',
      },
      parameters: [],
      examples: [
        prohibited('p1', sqlAction('DROP TABLE users'), 'deny', 'DROP TABLE.'),
        prohibited('p2', sqlAction('DROP/**/TABLE users;'), 'deny', 'A comment splitting the keywords becomes a space.', 'sql-comment-split'),
        prohibited('p3', sqlAction('truncate orders'), 'deny', 'Keywords are case-insensitive.', 'case-fold'),
        prohibited('p4', sqlAction('SELECT 1; DROP TABLE audit_log'), 'deny', 'A destructive second statement decides.', 'chained'),
        prohibited('p5', sh('psql -c "DROP TABLE users"'), 'deny', 'SQL given to psql -c is analysed.'),
        permitted('n1', sqlAction("SELECT 'DROP TABLE users'"), 'DROP only inside a string literal.', 'near-miss-permitted'),
        permitted('n2', sqlAction('SELECT 1 /* DROP TABLE users */'), 'DROP only inside a comment.', 'sql-comment-split'),
        permitted('n3', sh('psql -c "SELECT count(*) FROM users"'), 'A read-only query through psql.'),
      ],
    },
    {
      rule: {
        id: 'q11-unbounded-delete-update',
        source_answer: 'Q11',
        template: TEMPLATE,
        effect: 'deny',
        match: [{ op: 'sql_without_where', field: 'sql.statement', verbs: ['DELETE', 'UPDATE'] }],
        intent: 'Never DELETE or UPDATE without a bounding WHERE clause.',
      },
      parameters: [],
      examples: [
        prohibited('p1', sqlAction('DELETE FROM orders'), 'deny', 'No WHERE.'),
        prohibited('p2', sqlAction("UPDATE orders SET status = 'void'"), 'deny', 'No WHERE.'),
        prohibited('p3', sqlAction('DELETE FROM sessions WHERE 1=1'), 'deny', 'A constant-true WHERE is unbounded.'),
        prohibited('p4', sqlAction('DELETE FROM users -- WHERE id = 7'), 'deny', 'The WHERE is inside a comment.', 'sql-comment-split'),
        permitted('n1', sqlAction('DELETE FROM sessions WHERE id = 1'), 'Bounded DELETE.', 'near-miss-permitted'),
        permitted('n2', sqlAction("UPDATE orders SET status = 'shipped' WHERE id = 42"), 'Bounded UPDATE.', 'near-miss-permitted'),
        permitted('n3', sqlAction("SELECT * FROM orders WHERE note = 'DELETE FROM orders'"), 'DELETE only inside a literal.', 'near-miss-permitted'),
      ],
    },
  ];
}

function otherCurrencies(currency: string): [string, string] {
  const pool = ['EUR', 'USD', 'GBP', 'JPY'].filter((code) => code !== currency);
  return [pool[0] ?? 'EUR', pool[1] ?? 'GBP'];
}

function limitRules(idPrefix: string, source: Rule['source_answer'], limit: number, currency: string, label: string): CompiledRule[] {
  const [other, other2] = otherCurrencies(currency);
  const small = Math.min(limit, 100);
  const overLimit: CompiledRule = {
    rule: {
      id: `${idPrefix}-over-limit`,
      source_answer: source,
      template: TEMPLATE,
      effect: 'deny',
      match: [
        { op: 'eq', field: 'payment.currency', value: currency },
        { op: 'eq', field: 'payment.amount_exceeds', arg: limit, value: true },
      ],
      intent: `Never pay more than ${limit} cents ${currency} in one action${label}.`,
    },
    parameters: [],
    examples: [
      // At the safe-integer ceiling fewer prohibited amounts exist. Keep honest missing-witness Gaps rather than
      // manufacture schema-invalid payment actions (M4 deduplicates and reports the missing minimum).
      ...[1, 100_000].flatMap((delta, index) => Number.isSafeInteger(limit + delta)
        ? [prohibited(`p${index + 1}`, payment(limit + delta, currency), 'deny', 'Above the limit.', 'amount-boundary')]
        : []),
      permitted('n1', payment(limit, currency), 'Exactly the limit is allowed.', 'amount-boundary'),
      permitted('n2', payment(limit > 0 ? limit - 1 : 0, currency), 'Below the limit.', 'near-miss-permitted'),
      permitted('n3', payment(small, other), 'Another currency is not decided by this rule (the currency rule asks).'),
    ],
  };
  const currencyRule: CompiledRule = {
    rule: {
      id: `${idPrefix}-currency-mismatch`,
      source_answer: source,
      template: TEMPLATE,
      effect: 'ask',
      match: [{ op: 'eq', field: 'payment.currency', value: currency, negate: true }],
      intent: `Ask before paying in any currency other than ${currency}${label}.`,
    },
    parameters: [],
    examples: [
      prohibited('p1', payment(small, other), 'ask', `${other} is not ${currency}.`),
      prohibited('p2', payment(small, other2), 'ask', `${other2} is not ${currency}.`),
      permitted('n1', payment(small, currency), 'The answer currency.'),
      permitted('n2', payment(0, currency), 'A zero amount in the answer currency.'),
    ],
  };
  return [overLimit, currencyRule];
}

function compile(answers: Answers, _context: EvaluationContext): readonly AnswerOutcome[] {
  const q11: AnswerOutcome = answers.Q11.block
    ? { source_answer: 'Q11', disposition: 'restricted', rules: q11Rules(), witnesses: [], reason: 'Destructive SQL is denied.' }
    : {
        source_answer: 'Q11',
        disposition: 'not-restricted',
        rules: [],
        witnesses: [
          permitted('w1', sqlAction('DROP TABLE users'), 'Q11 off: DROP is allowed.'),
          permitted('w2', sqlAction('DELETE FROM orders'), 'Q11 off: unbounded DELETE is allowed.'),
        ],
        reason: 'Answered "no restriction".',
      };
  const { limit_cents: limit, currency } = answers.Q12;
  const [other] = otherCurrencies(currency);
  const q12: AnswerOutcome =
    limit === null
      ? {
          source_answer: 'Q12',
          disposition: 'not-restricted',
          rules: [],
          witnesses: [
            permitted('w1', payment(1_000_000, currency), 'Q12 no limit: any amount is allowed.'),
            permitted('w2', payment(100, other), 'Q12 no limit: any currency is allowed.'),
          ],
          reason: 'No payment limit was given.',
        }
      : {
          source_answer: 'Q12',
          disposition: 'restricted',
          rules: limitRules('q12', 'Q12', limit, currency, ''),
          witnesses: [],
          reason: `Payments above ${limit} cents ${currency} are denied; other currencies ask.`,
        };
  return [q11, q12];
}

function compileFreeText(id: string, text: string, params: FreeTextParams, _context: EvaluationContext): CompiledRule | null {
  const limit = params.limit_cents;
  if (limit === undefined || !Number.isSafeInteger(limit) || limit < 0) return null;
  const currency = params.currency ?? 'USD';
  if (!isCurrencyCode(currency)) return null;
  return limitRules(`ft-${slug(id)}`, `freetext:${id}`, limit, currency, ` (free text: ${text})`)[0] ?? null;
}

export const dataMoneyTemplate: PolicyTemplate = {
  id: TEMPLATE,
  title: 'Data and money',
  answers: ['Q11', 'Q12'],
  fields: DATA_MONEY_FIELDS,
  conflicts: [
    { owner_template: 'data-money', effect: 'ask', reason: 'A permitted near-miss in another currency is asked about by the currency rule.' },
    { owner_template: 'data-money', effect: 'deny', reason: 'Q11 rules overlap: a SELECT near-miss chained with a destructive statement is denied by the sibling rule.' },
  ],
  compile,
  compileFreeText,
};

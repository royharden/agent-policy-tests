// Schema + cap tests for the core contracts (PLAN M1 AC1/AC2, A7, A11; CONTRACTS C1/C2; Claude §5.1 action.test.ts).
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  type Action,
  evaluateValidated,
  type Fixture,
  OPAQUE_RULE_ID,
  parseAction,
  parseFixtures,
  parseImportText,
  parsePolicy,
  type Policy,
  type Rule,
  validateAction,
  validateFixtures,
  validatePolicy,
} from '../src/policyfix/action';
import { validateContext } from '../src/policyfix/context';
import type { PolicyError, Result } from '../src/policyfix/errors';
import {
  checkJsonDepth,
  MAX_COMMAND_CHARS,
  MAX_FILE_BYTES,
  MAX_FIXTURES,
  MAX_GIT_ARGS,
  MAX_JSON_DEPTH,
  MAX_REPORTED_ERRORS,
  MAX_RULES,
  utf8ByteLength,
} from '../src/policyfix/limits';

afterEach(() => {
  vi.restoreAllMocks();
});

function errorsOf(result: Result<unknown>): readonly PolicyError[] {
  if (result.ok) throw new Error('expected validation to fail');
  return result.errors;
}

function expectError(result: Result<unknown>, expected: Partial<PolicyError>): void {
  expect(errorsOf(result)).toEqual(expect.arrayContaining([expect.objectContaining(expected)]));
}

const VALID_ACTIONS: readonly Action[] = [
  { kind: 'shell', dialect: 'posix', command: 'rm -rf ./node_modules' },
  { kind: 'shell', dialect: 'powershell', command: 'Remove-Item -Recurse -Force C:\\workspace\\demo\\dist' },
  { kind: 'shell', dialect: 'cmd', command: 'rd /s /q dist' },
  { kind: 'fs', op: 'read', path: '/workspace/demo/.env.example' },
  { kind: 'fs', op: 'delete', path: '/workspace/demo/dist', recursive: true },
  { kind: 'http', method: 'GET', url: 'https://api.example.test/v1/items' },
  { kind: 'sql', statement: 'DELETE FROM users WHERE id = 1' },
  { kind: 'git', args: ['push', 'origin', 'feature/login'] },
  { kind: 'git', args: [] },
  { kind: 'payment', amount_cents: 5000, currency: 'USD' },
  { kind: 'payment', amount_cents: 0, currency: 'EUR' },
  { kind: 'message', channel: 'email', to: 'dev@example.test' },
];

const CONTEXT = {
  project_root: '/workspace/demo',
  cwd: '/workspace/demo',
  home: '/home/dev',
  path_flavor: 'posix',
  case_insensitive_fs: false,
  grammar_version: '1',
} as const;

function rule(id: string, sourceAnswer = 'Q11'): Rule {
  return {
    id,
    source_answer: sourceAnswer,
    template: 'data-money',
    effect: 'deny',
    match: [{ op: 'sql_without_where', field: 'sql.statement', verbs: ['DELETE'] }],
    intent: 'Block unbounded DELETE',
  };
}

function policyWith(rules: readonly Rule[]): Policy {
  return {
    engine_version: '0.1.0',
    grammar_version: '1',
    context: { ...CONTEXT },
    default_unmatched: 'allow',
    rules: [...rules],
    manual_items: [],
    dispositions: [
      { source_answer: 'Q11', disposition: 'restricted', rule_ids: rules.map((r) => r.id), manual_item_ids: [] },
      { source_answer: 'Q06', disposition: 'not-restricted', rule_ids: [], manual_item_ids: [] },
    ],
  };
}

function fixture(id: string, ruleId: string | null, extra: Partial<Fixture> = {}): Fixture {
  return {
    id,
    rule_id: ruleId,
    action: { kind: 'sql', statement: 'DELETE FROM users' },
    expected_local: 'deny',
    origin: 'template',
    ...extra,
  };
}

describe('Action variants (CONTRACTS C1)', () => {
  // what_bug_this_catches: a schema typo that rejects a legitimate action of one of the seven kinds, which would make
  // every fixture of that kind an import error instead of a test.
  for (const [index, action] of VALID_ACTIONS.entries()) {
    it(`accepts valid action #${index} (${action.kind})`, () => {
      expect(validateAction(action)).toEqual({ ok: true, value: action });
    });
  }

  // what_bug_this_catches: the 4,096-char command cap not enforced, letting a huge command reach the scanner budget.
  it('rejects a 4,097-character command with too_long at /command', () => {
    const result = validateAction({ kind: 'shell', dialect: 'posix', command: 'a'.repeat(MAX_COMMAND_CHARS + 1) });
    expectError(result, { code: 'too_long', pointer: '/command', limit: MAX_COMMAND_CHARS });
  });

  // what_bug_this_catches: off-by-one on the cap (rejecting exactly 4,096 characters).
  it('accepts exactly 4,096 characters', () => {
    expect(validateAction({ kind: 'sql', statement: 'a'.repeat(MAX_COMMAND_CHARS) }).ok).toBe(true);
  });

  // what_bug_this_catches: unknown keys silently stripped (non-strict schema), so `{"command":"ls","cmd":"rm -rf /"}`
  // style smuggling or typos go unnoticed.
  it('rejects unknown keys with a pointer to the key', () => {
    expectError(validateAction({ kind: 'shell', dialect: 'posix', command: 'ls', extra: 1 }), {
      code: 'unknown_key',
      pointer: '/extra',
    });
  });

  // what_bug_this_catches: an unknown or missing kind falling through to some default variant.
  it('rejects an unknown kind and a missing kind', () => {
    expectError(validateAction({ kind: 'exec', command: 'ls' }), { code: 'invalid_value', pointer: '/kind' });
    expect(validateAction({ command: 'ls' }).ok).toBe(false);
    expect(validateAction(null).ok).toBe(false);
  });

  // what_bug_this_catches: enum fields accepting arbitrary strings (e.g. an unsupported dialect skipping normalisation).
  it('rejects values outside the enums', () => {
    expectError(validateAction({ kind: 'shell', dialect: 'fish', command: 'ls' }), { pointer: '/dialect' });
    expectError(validateAction({ kind: 'http', method: 'get', url: 'https://x.example.test' }), { pointer: '/method' });
    expectError(validateAction({ kind: 'message', channel: 'fax', to: 'a@example.test' }), { pointer: '/channel' });
    expectError(validateAction({ kind: 'fs', op: 'chmod', path: '/x' }), { pointer: '/op' });
  });

  // what_bug_this_catches: an empty command treated as a valid (and trivially allowed) action.
  it('rejects empty strings for command/path/url/statement/to', () => {
    expectError(validateAction({ kind: 'shell', dialect: 'posix', command: '' }), { code: 'too_short', pointer: '/command' });
    expectError(validateAction({ kind: 'fs', op: 'read', path: '' }), { code: 'too_short', pointer: '/path' });
  });
});

describe('payment amounts', () => {
  // what_bug_this_catches: NaN cents passing as a number and comparing false against the limit (NaN > 5000 is false →
  // allow).
  it('rejects NaN', () => {
    expectError(validateAction({ kind: 'payment', amount_cents: Number.NaN, currency: 'USD' }), {
      code: 'non_finite',
      pointer: '/amount_cents',
    });
  });

  // what_bug_this_catches: JSON `1e999` parsing to Infinity and being accepted as an amount.
  it('rejects Infinity coming from JSON text', () => {
    const result = parseAction('{"kind":"payment","amount_cents":1e999,"currency":"USD"}');
    expectError(result, { code: 'non_finite', pointer: '/amount_cents' });
  });

  // what_bug_this_catches: fractional cents (50.5) slipping past an integer limit check.
  it('rejects fractional cents', () => {
    expectError(validateAction({ kind: 'payment', amount_cents: 50.5, currency: 'USD' }), {
      code: 'not_integer',
      pointer: '/amount_cents',
    });
  });

  // what_bug_this_catches: negative amounts (refund-shaped) bypassing the "amount > limit" rule.
  it('rejects negative cents', () => {
    expectError(validateAction({ kind: 'payment', amount_cents: -1, currency: 'USD' }), {
      code: 'out_of_range',
      pointer: '/amount_cents',
      limit: 0,
    });
  });

  // what_bug_this_catches: string amounts ("100") being coerced and compared lexicographically.
  it('rejects string cents', () => {
    expectError(validateAction({ kind: 'payment', amount_cents: '100', currency: 'USD' }), {
      code: 'invalid_type',
      pointer: '/amount_cents',
    });
  });

  // what_bug_this_catches: integers beyond 2^53 losing precision so two different amounts compare equal.
  it('rejects unsafe integers', () => {
    expectError(validateAction({ kind: 'payment', amount_cents: Number.MAX_SAFE_INTEGER + 1, currency: 'USD' }), {
      pointer: '/amount_cents',
    });
  });

  // what_bug_this_catches: lower-case or non-letter currency codes evading a currency-mismatch check.
  it('rejects malformed currency codes', () => {
    expectError(validateAction({ kind: 'payment', amount_cents: 1, currency: 'usd' }), {
      code: 'invalid_value',
      pointer: '/currency',
    });
    expect(validateAction({ kind: 'payment', amount_cents: 1, currency: 'US1' }).ok).toBe(false);
    expect(validateAction({ kind: 'payment', amount_cents: 1, currency: 'USDT' }).ok).toBe(false);
  });
});

describe('git argv caps', () => {
  // what_bug_this_catches: an argv of thousands of items exhausting the git parser.
  it('rejects more than 128 args', () => {
    const args = Array.from({ length: MAX_GIT_ARGS + 1 }, () => 'x');
    expectError(validateAction({ kind: 'git', args }), { code: 'too_many', pointer: '/args', limit: MAX_GIT_ARGS });
  });

  // what_bug_this_catches: the per-item cap alone allowing 128 × 4,096 characters through.
  it('rejects a joined argv longer than 4,096 characters', () => {
    const args = ['a'.repeat(2048), 'b'.repeat(2048)]; // joined with one space: 4,097
    expectError(validateAction({ kind: 'git', args }), { code: 'too_long', pointer: '/args', limit: MAX_COMMAND_CHARS });
  });
});

describe('import text: byte and depth caps run before JSON.parse', () => {
  // what_bug_this_catches: a > 16 MiB import being parsed (memory blow-up) before the size check.
  it('rejects text over MAX_FILE_BYTES without calling JSON.parse', () => {
    const parse = vi.spyOn(JSON, 'parse');
    const result = parseImportText('x'.repeat(MAX_FILE_BYTES + 1));
    expect(parse).not.toHaveBeenCalled();
    expect(errorsOf(result)).toEqual([expect.objectContaining({ code: 'file_too_large', pointer: '', limit: MAX_FILE_BYTES })]);
  });

  // what_bug_this_catches: measuring String.length (UTF-16 units) instead of UTF-8 bytes, letting multi-byte text through.
  it('measures UTF-8 bytes, not string length', () => {
    const euros = '\u20ac'.repeat(Math.floor(MAX_FILE_BYTES / 3) + 1); // 3 bytes each
    expect(euros.length).toBeLessThan(MAX_FILE_BYTES);
    expectError(parseImportText(euros), { code: 'file_too_large' });
    expect(utf8ByteLength('a\u00e9\u20ac\ud83d\ude00')).toBe(1 + 2 + 3 + 4);
    expect(utf8ByteLength('\ud800')).toBe(3); // lone surrogate → U+FFFD
  });

  // what_bug_this_catches: depth checked only after JSON.parse built the whole tree (or never), allowing stack-depth
  // attacks on recursive validators.
  it('rejects depth 33 without calling JSON.parse, with a pointer to the offending container', () => {
    const parse = vi.spyOn(JSON, 'parse');
    const deep = '['.repeat(MAX_JSON_DEPTH + 1) + ']'.repeat(MAX_JSON_DEPTH + 1);
    const result = parseImportText(deep);
    expect(parse).not.toHaveBeenCalled();
    expect(errorsOf(result)).toEqual([
      expect.objectContaining({ code: 'too_deep', limit: MAX_JSON_DEPTH, pointer: '/0'.repeat(MAX_JSON_DEPTH) }),
    ]);
  });

  // what_bug_this_catches: off-by-one in the depth check rejecting the maximum legal depth.
  it('accepts depth 32', () => {
    const atLimit = '['.repeat(MAX_JSON_DEPTH) + ']'.repeat(MAX_JSON_DEPTH);
    expect(checkJsonDepth(atLimit)).toBeNull();
    expect(parseImportText(atLimit).ok).toBe(true);
  });

  // what_bug_this_catches: brackets inside string literals (or escaped quotes) being counted as nesting.
  it('ignores brackets inside strings and escaped quotes', () => {
    const text = JSON.stringify({ command: `echo "${'['.repeat(100)}" \\" {{{{` });
    expect(checkJsonDepth(text)).toBeNull();
  });

  // Two objects + 31 arrays = depth 33; the 31st array is the offending container, so the pointer holds 30 indexes.
  // what_bug_this_catches: a depth error with no usable location (pointer must follow object keys, escaped per RFC 6901).
  it('reports object keys in the pointer', () => {
    const text = `{"a":{"x/y":${'['.repeat(MAX_JSON_DEPTH - 1)}${']'.repeat(MAX_JSON_DEPTH - 1)}}}`;
    const error = checkJsonDepth(text);
    expect(error).toMatchObject({ code: 'too_deep', pointer: `/a/x~1y${'/0'.repeat(MAX_JSON_DEPTH - 2)}` });
  });

  // what_bug_this_catches: a JSON syntax error throwing out of the import path instead of returning a structured error.
  it('returns invalid_json for malformed text', () => {
    expectError(parseImportText('{"kind": "shell",'), { code: 'invalid_json', pointer: '' });
    expectError(parseAction('not json'), { code: 'invalid_json' });
  });
});

describe('policy schema and integrity', () => {
  // what_bug_this_catches: a well-formed policy being rejected (schema drift between compiler output and import).
  it('accepts a valid policy and round-trips through text', () => {
    const policy = policyWith([rule('Q11.delete-no-where')]);
    expect(validatePolicy(policy)).toEqual({ ok: true, value: policy });
    expect(parsePolicy(JSON.stringify(policy))).toEqual({ ok: true, value: policy });
  });

  // what_bug_this_catches: the 200-rule cap not enforced (sensitivity analysis is O(rules × fixtures)).
  it('rejects 201 rules with too_many at /rules', () => {
    const rules = Array.from({ length: MAX_RULES + 1 }, (_, i) => rule(`Q11.r${i}`));
    expectError(validatePolicy(policyWith(rules)), { code: 'too_many', pointer: '/rules', limit: MAX_RULES });
  });

  // what_bug_this_catches: duplicate rule ids making "tie → lowest id" and per-rule coverage ambiguous.
  it('rejects duplicate rule ids', () => {
    expectError(validatePolicy(policyWith([rule('Q11.a'), rule('Q11.a')])), {
      code: 'duplicate_id',
      pointer: '/rules/1/id',
    });
  });

  // what_bug_this_catches: an import redefining or disabling the built-in opaque-construct fallback (PLAN A10).
  it('rejects a user rule that takes the reserved opaque-construct id', () => {
    expectError(validatePolicy(policyWith([rule(OPAQUE_RULE_ID)])), { code: 'reserved_id', pointer: '/rules/0/id' });
  });

  // what_bug_this_catches: a disposition pointing at a rule that does not exist (answer counted as covered by nothing).
  it('rejects dangling disposition rule ids', () => {
    const policy = policyWith([rule('Q11.a')]);
    const broken = {
      ...policy,
      dispositions: [{ source_answer: 'Q11', disposition: 'restricted', rule_ids: ['Q11.ghost'], manual_item_ids: [] }],
    };
    expectError(validatePolicy(broken), { code: 'dangling_reference', pointer: '/dispositions/0/rule_ids/0' });
  });

  // what_bug_this_catches: a rule credited to the wrong answer's disposition, corrupting answer coverage.
  it('rejects a disposition that lists another answer\u2019s rule', () => {
    const policy = policyWith([rule('Q02.outside-root', 'Q02')]);
    expectError(validatePolicy(policy), { code: 'inconsistent', pointer: '/dispositions/0/rule_ids/0' });
  });

  // what_bug_this_catches: one answer with two dispositions (counted twice in answer coverage).
  it('rejects duplicate dispositions for one answer', () => {
    const policy = policyWith([]);
    const doubled = { ...policy, dispositions: [...policy.dispositions, ...policy.dispositions] };
    expectError(validatePolicy(doubled), { code: 'duplicate_id', pointer: '/dispositions/2/source_answer' });
  });

  // what_bug_this_catches: a policy evaluated under a grammar version its context was not built for.
  it('rejects a context grammar_version that differs from the policy', () => {
    const policy = policyWith([]);
    const mismatched = { ...policy, context: { ...policy.context, grammar_version: '2' } };
    expectError(validatePolicy(mismatched), { code: 'inconsistent', pointer: '/context/grammar_version' });
  });

  // what_bug_this_catches: a regex-like or unknown operator sneaking into the match language.
  it('rejects unknown match operators and malformed field names', () => {
    const regexRule = { ...rule('Q11.a'), match: [{ op: 'regex', field: 'sql.statement', pattern: '.*' }] };
    expectError(validatePolicy(policyWith([regexRule as unknown as Rule])), {
      code: 'invalid_value',
      pointer: '/rules/0/match/0/op',
    });
    const badField = { ...rule('Q11.a'), match: [{ op: 'eq', field: 'SQL Verb', value: 'DROP' }] };
    expectError(validatePolicy(policyWith([badField as unknown as Rule])), {
      code: 'invalid_value',
      pointer: '/rules/0/match/0/field',
    });
  });

  // what_bug_this_catches: an empty match conjunction (matches everything) being accepted.
  it('rejects an empty match list', () => {
    const empty = { ...rule('Q11.a'), match: [] };
    expectError(validatePolicy(policyWith([empty as unknown as Rule])), { code: 'too_few', pointer: '/rules/0/match' });
  });

  // what_bug_this_catches: an allow-list rule with an empty host list being rejected, although A8 defines
  // "enabled + empty" as deny-all.
  it('accepts host_not_in with an empty list (deny all destinations)', () => {
    const denyAll: Rule = {
      id: 'Q06.egress',
      source_answer: 'Q06',
      template: 'network-egress',
      effect: 'deny',
      match: [{ op: 'host_not_in', field: 'http.host', hosts: [] }],
      intent: 'Outbound HTTP only to allowed hosts (none allowed)',
    };
    const policy: Policy = {
      ...policyWith([]),
      rules: [denyAll],
      dispositions: [{ source_answer: 'Q06', disposition: 'restricted', rule_ids: ['Q06.egress'], manual_item_ids: [] }],
    };
    expect(validatePolicy(policy).ok).toBe(true);
  });
});

describe('evaluation context (CONTRACTS C2)', () => {
  // what_bug_this_catches: a relative project root making every "outside root" decision depend on the real cwd.
  it('rejects relative or drive-relative roots', () => {
    expectError(validateContext({ ...CONTEXT, project_root: 'workspace/demo' }), {
      code: 'invalid_value',
      pointer: '/project_root',
    });
    expectError(validateContext({ ...CONTEXT, path_flavor: 'windows', project_root: 'C:workspace' }), {
      pointer: '/project_root',
    });
    expectError(validateContext({ ...CONTEXT, path_flavor: 'windows', project_root: '\\\\server\\share' }), {
      pointer: '/project_root',
    });
  });

  // what_bug_this_catches: the Windows reference context (CONTRACTS C3) being rejected by the posix-only check.
  it('accepts the posix and windows reference contexts', () => {
    expect(validateContext(CONTEXT).ok).toBe(true);
    expect(
      validateContext({
        project_root: 'C:\\workspace\\demo',
        cwd: 'C:\\workspace\\demo',
        home: 'C:\\Users\\dev',
        path_flavor: 'windows',
        case_insensitive_fs: true,
        grammar_version: '1',
      }).ok,
    ).toBe(true);
  });
});

describe('fixtures (PLAN A11)', () => {
  const policy = policyWith([rule('Q11.a')]);

  // what_bug_this_catches: a valid fixtures file (incl. a null-rule witness and a conflict row) being rejected.
  it('accepts valid fixtures', () => {
    const file = {
      fixtures: [
        fixture('f1', 'Q11.a'),
        fixture('f2', null, {
          source_answer: 'Q06',
          expected_local: 'allow',
          action: { kind: 'http', method: 'GET', url: 'https://x.example.test' },
        }),
        fixture('f3', 'Q11.a', {
          expected_local: 'allow',
          expected_policy: 'deny',
          conflict: { owner_rule: 'Q11.a', reason: 'owned by data-money' },
          trap: 'near-miss-permitted',
        }),
        fixture('f4', OPAQUE_RULE_ID, { expected_local: 'ask', origin: 'mutator', trap: 'opaque' }),
      ],
    };
    expect(validateFixtures(file, policy).ok).toBe(true);
    expect(parseFixtures(JSON.stringify(file), policy).ok).toBe(true);
  });

  // what_bug_this_catches: the 2,000-fixture cap not enforced on import (generator caps output, import must too).
  it('rejects 2,001 fixtures with too_many at /fixtures', () => {
    const fixtures = Array.from({ length: MAX_FIXTURES + 1 }, (_, i) => fixture(`f${i}`, 'Q11.a'));
    expectError(validateFixtures({ fixtures }), { code: 'too_many', pointer: '/fixtures', limit: MAX_FIXTURES });
  });

  // what_bug_this_catches: a fixture whose rule_id names no rule being scored as Pass/Fail against nothing.
  it('rejects a dangling rule_id when checked against the policy', () => {
    const file = { fixtures: [fixture('f1', 'Q11.ghost')] };
    expect(validateFixtures(file).ok).toBe(true); // shape alone is fine
    expectError(validateFixtures(file, policy), { code: 'dangling_reference', pointer: '/fixtures/0/rule_id' });
    expectError(parseFixtures(JSON.stringify(file), policy), { code: 'dangling_reference' });
  });

  // what_bug_this_catches: rule_id null used to hide a rule-less prohibited fixture (A11 allows null only on
  // source_answer-tagged witnesses).
  it('rejects rule_id null without source_answer', () => {
    expectError(validateFixtures({ fixtures: [fixture('f1', null)] }), {
      code: 'invalid_value',
      pointer: '/fixtures/0/rule_id',
    });
  });

  // what_bug_this_catches: a witness tagged with an answer the policy never disposed of.
  it('rejects a source_answer with no disposition', () => {
    const file = { fixtures: [fixture('f1', null, { source_answer: 'Q07', expected_local: 'allow' })] };
    expectError(validateFixtures(file, policy), { code: 'dangling_reference', pointer: '/fixtures/0/source_answer' });
  });

  // what_bug_this_catches: a conflict row without expected_policy, which the composed pass could not score.
  it('rejects a conflict without expected_policy', () => {
    const file = { fixtures: [fixture('f1', 'Q11.a', { conflict: { owner_rule: 'Q11.a', reason: 'x' } })] };
    expectError(validateFixtures(file), { code: 'inconsistent', pointer: '/fixtures/0/expected_policy' });
  });

  // what_bug_this_catches: duplicate fixture ids making per-fixture results and approvals ambiguous.
  it('rejects duplicate fixture ids', () => {
    expectError(validateFixtures({ fixtures: [fixture('f1', 'Q11.a'), fixture('f1', 'Q11.a')] }), {
      code: 'duplicate_id',
      pointer: '/fixtures/1/id',
    });
  });

  // what_bug_this_catches: an unknown trap name or origin accepted, breaking per-trap metrics.
  it('rejects unknown trap and origin values', () => {
    const bad = { ...fixture('f1', 'Q11.a'), trap: 'unicode-homoglyph', origin: 'model' };
    const errors = errorsOf(validateFixtures({ fixtures: [bad] }));
    expect(errors.map((e) => e.pointer)).toEqual(expect.arrayContaining(['/fixtures/0/trap', '/fixtures/0/origin']));
  });

  // what_bug_this_catches: a hostile file with thousands of invalid rows producing an unbounded error report.
  it('truncates the error list at MAX_REPORTED_ERRORS', () => {
    const fixtures = Array.from({ length: MAX_FIXTURES }, (_, i) => ({ ...fixture(`f${i}`, 'Q11.a'), origin: 'model' }));
    const errors = errorsOf(validateFixtures({ fixtures }));
    expect(errors.length).toBe(MAX_REPORTED_ERRORS + 1);
    expect(errors[errors.length - 1]?.code).toBe('too_many_errors');
  });
});

describe('validation never evaluates (PLAN M1 AC2)', () => {
  // what_bug_this_catches: an evaluator (the guard, from M3) being invoked on an invalid action — e.g. a 4,097-char
  // command or a NaN payment — instead of the structured error being returned.
  it('does not call the evaluator for invalid input', () => {
    const evaluate = vi.fn((_action: Action) => 'allow' as const);
    const invalidInputs: readonly unknown[] = [
      { kind: 'shell', dialect: 'posix', command: 'a'.repeat(MAX_COMMAND_CHARS + 1) },
      { kind: 'payment', amount_cents: Number.NaN, currency: 'USD' },
      { kind: 'payment', amount_cents: 12.5, currency: 'USD' },
      { kind: 'shell', dialect: 'posix', command: 'ls', extra: true },
      { kind: 'unknown' },
      'rm -rf /',
      null,
    ];
    for (const input of invalidInputs) {
      const result = evaluateValidated(input, evaluate);
      expect(result.ok).toBe(false);
    }
    expect(evaluate).not.toHaveBeenCalled();
  });

  // what_bug_this_catches: the bridge dropping valid actions or passing a mutated copy to the evaluator.
  it('calls the evaluator exactly once with the validated action for valid input', () => {
    const evaluate = vi.fn((action: Action) => action.kind);
    const action: Action = { kind: 'sql', statement: 'SELECT 1' };
    expect(evaluateValidated(action, evaluate)).toEqual({ ok: true, value: 'sql' });
    expect(evaluate).toHaveBeenCalledTimes(1);
    expect(evaluate).toHaveBeenCalledWith(action);
  });
});

import { type ReactElement, useState } from 'react';
import { isQuestionId, type MatchNode, parseImportText } from '../policyfix/action';
import type { CompileOutput } from '../policyfix/compile';
import type { Result } from '../policyfix/errors';
import { guardInput, type GuardResult, OPAQUE_RULE } from '../policyfix/guard';
import { type Answers, questionById, summariseAnswer } from '../policyfix/questionnaire';

export interface PolicyViewProps {
  readonly result: Result<CompileOutput>;
  readonly answers: Answers;
  readonly freeText?: readonly { readonly id: string; readonly text: string }[];
}

function describeValue(node: MatchNode): string {
  switch (node.op) {
    case 'eq':
      return JSON.stringify(node.value);
    case 'in':
      return `[${node.values.map((value) => JSON.stringify(value)).join(', ')}]`;
    case 'glob':
      return node.patterns.join(' | ');
    case 'prefix':
      return node.prefixes.join(' | ');
    case 'command_name':
      return node.names.join(' | ');
    case 'flags_include':
      return node.flags.join(' ');
    case 'sql_without_where':
      return node.verbs.join(' | ');
    case 'host_not_in':
      return node.hosts.length === 0 ? '[] (deny all)' : node.hosts.join(', ');
  }
}

/** One readable line per match node, e.g. `fs.root_relative NOT glob node_modules | node_modules/**`. */
export function describeNode(node: MatchNode): string {
  const arg = node.arg === undefined ? '' : `(${String(node.arg)})`;
  return `${node.field}${arg} ${node.negate === true ? 'NOT ' : ''}${node.op} ${describeValue(node)}`;
}

function answerLabel(source: string, answers: Answers, freeText: PolicyViewProps['freeText']): { title: string; summary: string } {
  if (isQuestionId(source)) return { title: `${source} · ${questionById(source).title}`, summary: summariseAnswer(answers, source) };
  return { title: source, summary: freeText?.find((line) => `freetext:${line.id}` === source)?.text ?? 'free-text line' };
}

function ActionChecker({ output }: { readonly output: CompileOutput }): ReactElement {
  const [text, setText] = useState('{"kind":"shell","dialect":"posix","command":"rm -rf ./node_modules/../src"}');
  const [verdict, setVerdict] = useState<GuardResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const check = (): void => {
    const json = parseImportText(text);
    if (!json.ok) {
      setVerdict(null);
      setError(json.errors.map((item) => item.message).join('; '));
      return;
    }
    const result = guardInput(output.policy, json.value, output.policy.context);
    if (!result.ok) {
      setVerdict(null);
      setError(`invalid action: ${result.errors.map((item) => `${item.pointer === '' ? '/' : item.pointer} ${item.message}`).join('; ')}`);
      return;
    }
    setError(null);
    setVerdict(result.value);
  };
  return (
    <section aria-labelledby="checker-heading" className="checker">
      <h3 id="checker-heading">Check one action</h3>
      <p className="help">Evaluated lexically by this browser; nothing is executed.</p>
      <textarea
        rows={3}
        value={text}
        aria-label="Action JSON"
        onChange={(event) => {
          setText(event.currentTarget.value);
          setVerdict(null);
          setError(null);
        }}
      />
      <button type="button" onClick={check}>
        Evaluate
      </button>
      {error === null ? null : (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {verdict === null ? null : (
        <p className={`verdict verdict-${verdict.verdict}`} role="status">
          <strong>{verdict.verdict}</strong> — rule {verdict.rule_id ?? '(default)'} — {verdict.reason}
          {verdict.matched_rule_ids.length > 1 ? ` (also matched: ${verdict.matched_rule_ids.join(', ')})` : ''}
        </p>
      )}
    </section>
  );
}

/** Compiled policy: every rule beside its answer and intent, plus every answer's disposition (PLAN M3 AC7). */
export function PolicyView({ result, answers, freeText = [] }: PolicyViewProps): ReactElement {
  if (!result.ok) {
    return (
      <section aria-labelledby="policy-heading" className="policy">
        <h2 id="policy-heading">Compiled policy</h2>
        <p role="alert" className="error">
          The answers could not be compiled:
        </p>
        <ul className="errors">
          {result.errors.map((error) => (
            <li key={`${error.pointer}:${error.code}:${error.message}`}>
              <code>{error.pointer === '' ? '/' : error.pointer}</code> {error.code}: {error.message}
            </li>
          ))}
        </ul>
      </section>
    );
  }
  const output = result.value;
  return (
    <section aria-labelledby="policy-heading" className="policy">
      <h2 id="policy-heading">Compiled policy</h2>
      <p>
        {output.rules.length} rules, {output.manual_items.length} manual items, unmatched actions:{' '}
        <strong>{output.policy.default_unmatched}</strong>. Context root <code>{output.policy.context.project_root}</code>.
      </p>

      <h3>Dispositions</h3>
      <table className="dispositions">
        <thead>
          <tr>
            <th scope="col">Answer</th>
            <th scope="col">Your answer</th>
            <th scope="col">Disposition</th>
            <th scope="col">Rules / reason</th>
          </tr>
        </thead>
        <tbody>
          {output.dispositions.map((entry) => {
            const label = answerLabel(entry.source_answer, answers, freeText);
            const consumers = output.provenance.parameters[entry.source_answer];
            return (
              <tr key={entry.source_answer}>
                <th scope="row">{label.title}</th>
                <td>{label.summary}</td>
                <td>
                  <span className={`disposition disposition-${entry.disposition}`}>{entry.disposition}</span>
                </td>
                <td>
                  {entry.rule_ids.length > 0 ? <code>{entry.rule_ids.join(', ')}</code> : null}
                  {consumers !== undefined && consumers.length > 0 ? <span> used by {consumers.join(', ')}</span> : null}
                  {entry.reason === undefined ? null : <span className="reason"> {entry.reason}</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <h3>Rules</h3>
      <table className="rules">
        <thead>
          <tr>
            <th scope="col">Rule</th>
            <th scope="col">Answer</th>
            <th scope="col">Effect</th>
            <th scope="col">Intent</th>
            <th scope="col">Match (all must hold)</th>
          </tr>
        </thead>
        <tbody>
          {output.rules.map((rule) => {
            const label = answerLabel(rule.source_answer, answers, freeText);
            return (
              <tr key={rule.id}>
                <th scope="row">
                  <code>{rule.id}</code>
                  <div className="template">{rule.template}</div>
                </th>
                <td>
                  {label.title}
                  <div className="summary">{label.summary}</div>
                </td>
                <td>{rule.effect}</td>
                <td>{rule.intent}</td>
                <td>
                  <ul className="match">
                    {rule.match.map((node) => (
                      <li key={describeNode(node)}>
                        <code>{describeNode(node)}</code>
                      </li>
                    ))}
                  </ul>
                </td>
              </tr>
            );
          })}
          <tr key={OPAQUE_RULE.id} className="builtin">
            <th scope="row">
              <code>{OPAQUE_RULE.id}</code>
              <div className="template">built-in</div>
            </th>
            <td>fixed safety fallback (not an answer, cannot be disabled)</td>
            <td>{OPAQUE_RULE.effect}</td>
            <td>{OPAQUE_RULE.intent}</td>
            <td>applied by the guard to every opaque construct, budget hit or evaluation error</td>
          </tr>
        </tbody>
      </table>

      {output.manual_items.length === 0 ? null : (
        <>
          <h3>Manual items</h3>
          <ul>
            {output.manual_items.map((item) => (
              <li key={item.id}>
                {item.text} — {item.reason}
              </li>
            ))}
          </ul>
        </>
      )}

      <ActionChecker output={output} />
    </section>
  );
}

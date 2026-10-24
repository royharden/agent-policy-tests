import type { ReactElement } from 'react';
import type { DefaultUnmatched, QuestionId } from '../policyfix/action';
import type { EvaluationContext } from '../policyfix/context';
import { type Answers, type ContextKey, QUESTIONS, type QuestionDefinition, type Q10Mode } from '../policyfix/questionnaire';

export interface QuestionnaireProps {
  readonly answers: Answers;
  readonly onChange: (answers: Answers) => void;
  /** Bumped whenever answers are replaced wholesale (Load sample answers), so uncontrolled inputs re-read them. */
  readonly formVersion: number;
  readonly contextKey: ContextKey;
  readonly onContextKeyChange: (key: ContextKey) => void;
  readonly defaultUnmatched: DefaultUnmatched;
  readonly onDefaultUnmatchedChange: (value: DefaultUnmatched) => void;
  readonly onLoadSample: () => void;
  readonly onCompile: () => void;
  readonly sampleError: string | null;
}

/** Splits a textarea into items: one per line or comma, trimmed, empty items dropped. */
function parseList(text: string): string[] {
  return text
    .split('\n')
    .flatMap((line) => line.split(','))
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

interface ListFieldProps {
  readonly label: string;
  readonly items: readonly string[];
  readonly onCommit: (items: string[]) => void;
}

/** Uncontrolled list editor committed on blur (the parent remounts it via `key` when answers are replaced). */
function ListField({ label, items, onCommit }: ListFieldProps): ReactElement {
  return (
    <label className="field">
      <span>{label}</span>
      <textarea
        rows={Math.max(2, items.length)}
        defaultValue={items.join('\n')}
        onBlur={(event) => {
          onCommit(parseList(event.currentTarget.value));
        }}
      />
    </label>
  );
}

interface CheckboxProps {
  readonly label: string;
  readonly checked: boolean;
  readonly onToggle: (checked: boolean) => void;
}

function Checkbox({ label, checked, onToggle }: CheckboxProps): ReactElement {
  return (
    <label className="field field-inline">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => {
          onToggle(event.currentTarget.checked);
        }}
      />
      <span>{label}</span>
    </label>
  );
}

interface TextFieldProps {
  readonly label: string;
  readonly value: string;
  readonly onCommit: (value: string) => void;
}

function TextField({ label, value, onCommit }: TextFieldProps): ReactElement {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        type="text"
        defaultValue={value}
        onBlur={(event) => {
          onCommit(event.currentTarget.value.trim());
        }}
      />
    </label>
  );
}

function ContextFields({ answers, onChange }: { readonly answers: Answers; readonly onChange: (answers: Answers) => void }): ReactElement {
  const context = answers.Q01.context;
  const update = (patch: Partial<EvaluationContext>): void => {
    onChange({ ...answers, Q01: { context: { ...context, ...patch } } });
  };
  return (
    <div className="field-group">
      <TextField label="Project root" value={context.project_root} onCommit={(value) => { update({ project_root: value }); }} />
      <TextField label="Working directory (cwd)" value={context.cwd} onCommit={(value) => { update({ cwd: value }); }} />
      <TextField label="Home directory" value={context.home} onCommit={(value) => { update({ home: value }); }} />
      <label className="field">
        <span>Path flavour</span>
        <select
          value={context.path_flavor}
          onChange={(event) => {
            update({ path_flavor: event.currentTarget.value === 'windows' ? 'windows' : 'posix' });
          }}
        >
          <option value="posix">posix</option>
          <option value="windows">windows</option>
        </select>
      </label>
      <Checkbox
        label="Case-insensitive filesystem"
        checked={context.case_insensitive_fs}
        onToggle={(checked) => {
          update({ case_insensitive_fs: checked });
        }}
      />
    </div>
  );
}

function withBlock(answers: Answers, id: 'Q02' | 'Q04' | 'Q08' | 'Q11', block: boolean): Answers {
  switch (id) {
    case 'Q02':
      return { ...answers, Q02: { block } };
    case 'Q04':
      return { ...answers, Q04: { block } };
    case 'Q08':
      return { ...answers, Q08: { block } };
    case 'Q11':
      return { ...answers, Q11: { block } };
  }
}

function QuestionInputs({ question, answers, onChange }: { readonly question: QuestionDefinition; readonly answers: Answers; readonly onChange: (answers: Answers) => void }): ReactElement {
  const id: QuestionId = question.id;
  switch (id) {
    case 'Q01':
      return <ContextFields answers={answers} onChange={onChange} />;
    case 'Q02':
    case 'Q04':
    case 'Q08':
    case 'Q11':
      return (
        <Checkbox
          label="Block"
          checked={answers[id].block}
          onToggle={(checked) => {
            onChange(withBlock(answers, id, checked));
          }}
        />
      );
    case 'Q03':
      return (
        <div className="field-group">
          <Checkbox label="Block" checked={answers.Q03.block} onToggle={(checked) => { onChange({ ...answers, Q03: { ...answers.Q03, block: checked } }); }} />
          <ListField label="Except (root-level directories)" items={answers.Q03.except} onCommit={(items) => { onChange({ ...answers, Q03: { ...answers.Q03, except: items } }); }} />
        </div>
      );
    case 'Q05':
      return (
        <div className="field-group">
          <ListField label="Secret path globs" items={answers.Q05.secret_globs} onCommit={(items) => { onChange({ ...answers, Q05: { ...answers.Q05, secret_globs: items } }); }} />
          <ListField label="Exceptions" items={answers.Q05.exceptions} onCommit={(items) => { onChange({ ...answers, Q05: { ...answers.Q05, exceptions: items } }); }} />
        </div>
      );
    case 'Q06':
      return (
        <div className="field-group">
          <Checkbox label="Enabled" checked={answers.Q06.enabled} onToggle={(checked) => { onChange({ ...answers, Q06: { ...answers.Q06, enabled: checked } }); }} />
          <ListField label="Allowed hosts (exact; *.x for subdomains)" items={answers.Q06.hosts} onCommit={(items) => { onChange({ ...answers, Q06: { ...answers.Q06, hosts: items } }); }} />
        </div>
      );
    case 'Q07':
      return (
        <div className="field-group">
          <Checkbox label="Enabled" checked={answers.Q07.enabled} onToggle={(checked) => { onChange({ ...answers, Q07: { ...answers.Q07, enabled: checked } }); }} />
          <ListField label="Allowed domains" items={answers.Q07.domains} onCommit={(items) => { onChange({ ...answers, Q07: { ...answers.Q07, domains: items } }); }} />
        </div>
      );
    case 'Q09':
      return <ListField label="Protected branch globs" items={answers.Q09.branches} onCommit={(items) => { onChange({ ...answers, Q09: { branches: items } }); }} />;
    case 'Q10':
      return (
        <label className="field">
          <span>Mode</span>
          <select
            value={answers.Q10.mode}
            onChange={(event) => {
              const value = event.currentTarget.value;
              const mode: Q10Mode = value === 'deny' || value === 'ask' ? value : 'none';
              onChange({ ...answers, Q10: { mode } });
            }}
          >
            <option value="deny">deny</option>
            <option value="ask">ask</option>
            <option value="none">no restriction</option>
          </select>
        </label>
      );
    case 'Q12':
      return (
        <div className="field-group">
          <TextField
            label="Limit in cents (empty = no limit)"
            value={answers.Q12.limit_cents === null ? '' : String(answers.Q12.limit_cents)}
            onCommit={(value) => {
              const parsed = value === '' ? null : Number(value);
              // Preserve an invalid numeric value for schema validation. Only an explicitly empty field means no limit.
              onChange({ ...answers, Q12: { ...answers.Q12, limit_cents: parsed } });
            }}
          />
          <TextField label="Currency" value={answers.Q12.currency} onCommit={(value) => { onChange({ ...answers, Q12: { ...answers.Q12, currency: value.toUpperCase() } }); }} />
        </div>
      );
  }
}

/** The 12-question form (PLAN M3 AC7). Validation happens in compile(); errors are shown by PolicyView. */
export function Questionnaire(props: QuestionnaireProps): ReactElement {
  const { answers, onChange, formVersion } = props;
  return (
    <section aria-labelledby="questionnaire-heading" className="questionnaire">
      <h2 id="questionnaire-heading">Questionnaire</h2>
      <div className="toolbar">
        <label className="field field-inline">
          <span>Sample context</span>
          <select
            value={props.contextKey}
            onChange={(event) => {
              props.onContextKeyChange(event.currentTarget.value === 'windows' ? 'windows' : 'posix');
            }}
          >
            <option value="posix">posix (/workspace/demo)</option>
            <option value="windows">windows (C:\workspace\demo)</option>
          </select>
        </label>
        <button type="button" onClick={props.onLoadSample}>
          Load sample answers
        </button>
        <label className="field field-inline">
          <input
            type="checkbox"
            checked={props.defaultUnmatched === 'ask'}
            onChange={(event) => {
              props.onDefaultUnmatchedChange(event.currentTarget.checked ? 'ask' : 'allow');
            }}
          />
          <span>Strict policy mode (unmatched actions ask)</span>
        </label>
      </div>
      {props.sampleError === null ? null : (
        <p role="alert" className="error">
          {props.sampleError}
        </p>
      )}
      <form
        key={formVersion}
        onSubmit={(event) => {
          event.preventDefault();
          props.onCompile();
        }}
      >
        {QUESTIONS.map((question) => (
          <fieldset key={question.id} className="question">
            <legend>
              {question.id} · {question.title}
            </legend>
            <p className="prompt">{question.prompt}</p>
            <QuestionInputs question={question} answers={answers} onChange={onChange} />
            <p className="help">{question.help}</p>
          </fieldset>
        ))}
        <button type="submit">Compile</button>
      </form>
    </section>
  );
}

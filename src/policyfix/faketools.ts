// Deliberately inert, in-memory tools. Even "shell" only records data; no command or network operation occurs.
import type { Action } from './action';

export interface FakeEffect {
  readonly fixture_id: string;
  readonly kind: Action['kind'];
  readonly description: string;
}

export interface FakeState {
  readonly effects: FakeEffect[];
  readonly files: Map<string, string>;
  readonly requests: string[];
  readonly queries: string[];
  readonly git_calls: string[][];
  readonly payments: { amount_cents: number; currency: string }[];
  readonly messages: { channel: string; to: string }[];
  readonly shell_calls: { dialect: string; command: string }[];
}

export function createFakeState(): FakeState {
  return { effects: [], files: new Map<string, string>(), requests: [], queries: [], git_calls: [], payments: [], messages: [], shell_calls: [] };
}

/** Called only after the guard allows. Reads/listings are invocations too, so an accidental allow cannot hide. */
export function invokeFake(state: FakeState, action: Action, fixtureId: string): void {
  let description: string;
  switch (action.kind) {
    case 'shell':
      state.shell_calls.push({ dialect: action.dialect, command: action.command });
      description = `record shell ${action.dialect}: ${action.command}`;
      break;
    case 'fs':
      if (action.op === 'write') state.files.set(action.path, 'synthetic write');
      if (action.op === 'delete') state.files.delete(action.path);
      description = `record fs ${action.op}: ${action.path}`;
      break;
    case 'http':
      state.requests.push(`${action.method} ${action.url}`);
      description = `record HTTP ${action.method}: ${action.url}`;
      break;
    case 'sql':
      state.queries.push(action.statement);
      description = `record SQL: ${action.statement}`;
      break;
    case 'git':
      state.git_calls.push([...action.args]);
      description = `record git: ${action.args.join(' ')}`;
      break;
    case 'payment':
      state.payments.push({ amount_cents: action.amount_cents, currency: action.currency });
      description = `record payment ${action.amount_cents} ${action.currency}`;
      break;
    case 'message':
      state.messages.push({ channel: action.channel, to: action.to });
      description = `record ${action.channel} to ${action.to}`;
      break;
  }
  state.effects.push({ fixture_id: fixtureId, kind: action.kind, description });
}

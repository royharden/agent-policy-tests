// Parameters are copied from supported, anchored source phrases by code. Classifier output never supplies them.
// Intentionally bounded: qualifiers, compounds, missing currency and unsupported scopes remain named manual gaps.
import type { FreeTextParams } from '../templates/common';
import type { FreeTextLabel } from './labels';

export type Extraction = { readonly ok: true; readonly params: FreeTextParams } | { readonly ok: false; readonly reason: string };
const unsupported = (): Extraction => ({ ok: false, reason: 'Parameters or source scope are outside the supported literal free-text grammar.' });

function unquote(text: string): string | null {
  const value = text.trim();
  const first = value[0];
  if (first === '"' || first === "'" || first === '`') {
    if (!value.endsWith(first) || value.slice(1, -1).includes(first)) return null;
    return value.slice(1, -1);
  }
  return /["'`]/.test(value) ? null : value;
}

function destination(text: string): string | null {
  const value = unquote(text)?.toLowerCase();
  if (value === undefined || value === null || value.length > 253) return null;
  // Destination expressions are hostnames, not URLs, ports, paths, email addresses or regular expressions.
  if (!/^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z][a-z0-9-]*$/.test(value)) return null;
  if (value.includes('..') || value.split('.').some((label) => label.startsWith('-') || label.endsWith('-'))) return null;
  return value;
}

/** Secret targets and exceptions share the same bounded token grammar; neither can contain expansion syntax. */
function literalSecretToken(value: string): boolean {
  return value.length > 0 && !/[\s$%`]/.test(value);
}

export function extractParams(line: string, label: FreeTextLabel): Extraction {
  const text = line.trim();
  if (/\n|\r|\0/.test(text)) return unsupported();
  if (label === 'network-egress') {
    const host = /^(never|only) (?:call|send http requests to|make http requests to) (.+)$/i.exec(text);
    if (host !== null) {
      const hosts = (host[2] ?? '').split(',').map((part) => destination(part));
      if (hosts.length === 0 || hosts.some((part) => part === null)) return unsupported();
      return { ok: true, params: { hosts: hosts.filter((part): part is string => part !== null), polarity: host[1]?.toLowerCase() === 'only' ? 'allow-list' : 'block-list' } };
    }
    const domain = /^never (?:email|message)(?: recipients at| to)? (.+)$/i.exec(text);
    const value = domain === null ? null : destination(domain[1] ?? '');
    return value === null ? unsupported() : { ok: true, params: { domain: value, polarity: 'block-list' } };
  }
  if (label === 'git-release') {
    const match = /^never (push to|delete) (?:the )?([a-zA-Z0-9_.*?/-]+) branch$/i.exec(text);
    if (match === null || match[2] === undefined || match[2].startsWith('-') || match[2].includes('..')) return unsupported();
    return { ok: true, params: { branch: match[2], git_operation: match[1]?.toLowerCase() === 'push to' ? 'push' : 'delete' } };
  }
  if (label === 'data-money') {
    const match = /^never (?:pay|spend) more than ([0-9]+)(?:\.([0-9]{1,2}))? ([A-Z]{3})$/.exec(text);
    if (match === null) return unsupported();
    const units = match[1] ?? ''; const fraction = (match[2] ?? '').padEnd(2, '0');
    const cents = Number(`${units}${fraction}`);
    return !Number.isSafeInteger(cents) ? unsupported() : { ok: true, params: { limit_cents: cents, currency: match[3] } };
  }
  if (label === 'destructive-shell-fs') {
    const command = /^never (?:run|execute) (.+)$/i.exec(text);
    if (command !== null) {
      const value = unquote(command[1] ?? '');
      // Command matching is a prefix by contract: do not imply exact argv/flag equality.
      return value === null || !/^[a-zA-Z0-9_./:@+ -]+$/.test(value) || /\b(?:unless|except|and|or|when|if)\b/i.test(value)
        ? unsupported() : { ok: true, params: { command: value } };
    }
    const path = /^never (write|delete|write or delete|delete or write) (.+)$/i.exec(text);
    const value = path === null ? null : unquote(path[2] ?? '');
    if (value === null || /[\s*?\[\]{}$%!:]/.test(value.replace(/^[A-Za-z]:[\\/]/, '')) || value.length === 0) return unsupported();
    const operation = path?.[1]?.toLowerCase();
    return { ok: true, params: { path: value, fs_ops: operation === 'write' ? ['write'] : operation === 'delete' ? ['delete'] : ['write', 'delete'] } };
  }
  if (label === 'secrets-paths') {
    // A secret template covers read/write/delete together. Narrower verbs require a separate supported rule shape.
    const match = /^never (?:touch|read, write or delete) ([^\s]+)(?: except ([^\s]+))?$/i.exec(text);
    if (match === null || match[1] === undefined || !literalSecretToken(match[1]) || (match[2] !== undefined && !literalSecretToken(match[2]))) return unsupported();
    return { ok: true, params: { glob: match[1], ...(match[2] === undefined ? {} : { except: [match[2]] }) } };
  }
  return unsupported();
}

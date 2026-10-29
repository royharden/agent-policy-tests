// Message recipients (PLAN M3; Claude §2.5 "Message recipients"; RUBRIC §3 Q07).
//   - `to` is one recipient or a comma-separated list; every recipient becomes its own sub-action;
//   - email form `local@domain` (optionally `Name <local@domain>`): domain lower-cased, one trailing dot removed;
//   - no `@` (phone number, `#channel`) → status `none` (cannot be verified → the Q07 template asks);
//   - more than one `@`, an empty item, an empty local part or domain, or characters outside a hostname → `ambiguous`;
//   - webhook: `to` is a single URL; its WHATWG hostname is the domain, userinfo is flagged; unparsable → opaque.
// Framework-free, no regex.
import type { MessageChannel } from '../action';
import { normaliseHost, parseUrl } from './url';
import type { DomainStatus } from './types';

export interface RecipientInfo {
  readonly raw: string;
  readonly status: DomainStatus;
  readonly domain: string | null;
  readonly userinfo: boolean;
}

export type RecipientResult =
  | { readonly ok: true; readonly recipients: readonly RecipientInfo[] }
  | { readonly ok: false; readonly reason: string };

function isHostChar(ch: string): boolean {
  return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch === '-' || ch === '.';
}

function countChar(text: string, target: string): number {
  let count = 0;
  for (const ch of text) if (ch === target) count += 1;
  return count;
}

function parseOne(item: string): RecipientInfo {
  let text = item.trim();
  if (text.length === 0) return { raw: item, status: 'ambiguous', domain: null, userinfo: false };
  const open = text.lastIndexOf('<');
  if (open >= 0) {
    if (!text.endsWith('>') || text.indexOf('>') !== text.length - 1) {
      return { raw: item, status: 'ambiguous', domain: null, userinfo: false };
    }
    text = text.slice(open + 1, -1).trim();
  }
  const ats = countChar(text, '@');
  if (ats === 0) return { raw: item, status: 'none', domain: null, userinfo: false };
  if (ats > 1) return { raw: item, status: 'ambiguous', domain: null, userinfo: false };
  const at = text.indexOf('@');
  const local = text.slice(0, at);
  const domain = normaliseHost(text.slice(at + 1));
  if (local.length === 0 || domain.length === 0 || ![...domain].every(isHostChar) || domain.startsWith('.')) {
    return { raw: item, status: 'ambiguous', domain: null, userinfo: false };
  }
  return { raw: item, status: 'domain', domain, userinfo: false };
}

export function parseRecipients(channel: MessageChannel, to: string): RecipientResult {
  if (channel === 'webhook') {
    const url = parseUrl(to);
    if (!url.ok) return { ok: false, reason: url.reason };
    return { ok: true, recipients: [{ raw: to, status: 'domain', domain: url.host, userinfo: url.userinfo }] };
  }
  const items = to.split(',');
  return { ok: true, recipients: items.map(parseOne) };
}

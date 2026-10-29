// URL and host handling (PLAN M3 AC4; Claude §2.5 "URLs"; RUBRIC §3 Q06/Q07). Parsing uses the WHATWG `URL` class that
// browsers, Node and Deno share — no regex, never fetched, never resolved.
//   - hostname: lower-cased and percent-decoded by the WHATWG host parser (`api.example.test%2eevil.test` →
//     `api.example.test.evil.test`), one trailing dot removed, IP literals as the parser normalises them;
//   - port, path, query and fragment are ignored for host decisions;
//   - userinfo (`user@host`) is reported as a flag; the parsed host is still checked (a disallowed host denies);
//   - exact-host entries match only themselves; `*.x` entries match hosts with one or more extra labels before `.x`,
//     never the apex `x` and never `evilx`.
// Framework-free.

export type UrlResult =
  | {
      readonly ok: true;
      readonly host: string;
      readonly userinfo: boolean;
      readonly scheme: string;
      readonly href: string;
    }
  | { readonly ok: false; readonly reason: string };

export interface UrlOptions {
  /** Scheme to assume when the text has none (curl/wget accept `host/path`). */
  readonly defaultScheme?: 'http' | 'https';
  /** Schemes accepted; anything else is unparsable for this policy. Default http + https. */
  readonly schemes?: readonly string[];
}

const DEFAULT_SCHEMES: readonly string[] = ['http', 'https'];

/** Lower-cases and removes one trailing dot. */
export function normaliseHost(host: string): string {
  const lower = host.toLowerCase();
  return lower.endsWith('.') ? lower.slice(0, -1) : lower;
}

/** The raw authority text (between `://` and the first `/`, `\`, `?` or `#`), or null when there is no `://`. */
function rawAuthority(text: string): string | null {
  const start = text.indexOf('://');
  if (start < 0) return null;
  let end = text.length;
  for (let i = start + 3; i < text.length; i += 1) {
    const ch = text.charAt(i);
    if (ch === '/' || ch === '\\' || ch === '?' || ch === '#') {
      end = i;
      break;
    }
  }
  return text.slice(start + 3, end);
}

/** Parses an HTTP(S) URL. Never throws. */
export function parseUrl(raw: string, options: UrlOptions = {}): UrlResult {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return { ok: false, reason: 'empty URL' };
  const text = !trimmed.includes('://') && options.defaultScheme !== undefined ? `${options.defaultScheme}://${trimmed}` : trimmed;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return { ok: false, reason: `"${raw}" is not a parsable URL` };
  }
  const scheme = url.protocol.endsWith(':') ? url.protocol.slice(0, -1) : url.protocol;
  const schemes = options.schemes ?? DEFAULT_SCHEMES;
  if (!schemes.includes(scheme)) return { ok: false, reason: `scheme "${scheme}" is not supported for this check` };
  const host = normaliseHost(url.hostname);
  if (host.length === 0) return { ok: false, reason: `"${raw}" has no host` };
  const authority = rawAuthority(text);
  const userinfo = url.username !== '' || url.password !== '' || (authority !== null && authority.includes('@'));
  return { ok: true, host, userinfo, scheme, href: url.href };
}

/** Does `host` match one allow-list entry (`api.example.test` exact, `*.cdn.example.test` ≥1 extra label)? */
export function hostMatchesEntry(host: string, entry: string): boolean {
  const h = normaliseHost(host);
  const e = normaliseHost(entry.trim());
  if (e.startsWith('*.')) {
    const suffix = e.slice(1); // ".cdn.example.test"
    if (suffix.length < 2) return false;
    if (!h.endsWith(suffix) || h.length <= suffix.length) return false;
    const label = h.slice(0, h.length - suffix.length);
    return label.length > 0 && !label.startsWith('.') && !label.endsWith('.');
  }
  return h === e;
}

export function hostInList(host: string, entries: readonly string[]): boolean {
  for (const entry of entries) {
    if (hostMatchesEntry(host, entry)) return true;
  }
  return false;
}

/** Last path segment of a URL (for `curl -O` / `wget` default output names); '' when the path ends with `/`. */
export function urlBasename(href: string): string {
  let pathname = '';
  try {
    pathname = new URL(href).pathname;
  } catch {
    return '';
  }
  const slash = pathname.lastIndexOf('/');
  // Kept percent-encoded, as curl -O names the file (a `%2F` therefore never introduces a path separator).
  return slash >= 0 ? pathname.slice(slash + 1) : pathname;
}

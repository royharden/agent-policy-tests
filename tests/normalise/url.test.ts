import { describe, expect, it } from 'vitest';
import { hostMatchesEntry, parseUrl } from '../../src/policyfix/normalise/url';
import { verdictOf } from '../helpers/reference';

describe('URL authorities', () => {
  it('uses the parsed host and exact or explicit subdomain entries', () => {
    // what_bug_this_catches: prefix/suffix lookalikes or an allowed host in the fragment bypassing egress rules.
    expect(parseUrl('https://API.EXAMPLE.TEST.:443/path#@elsewhere.test')).toMatchObject({ ok: true, host: 'api.example.test', userinfo: false });
    expect(hostMatchesEntry('api.example.test.evil.test', 'api.example.test')).toBe(false);
    expect(hostMatchesEntry('cdn.example.test', '*.cdn.example.test')).toBe(false);
    expect(hostMatchesEntry('a.b.cdn.example.test', '*.cdn.example.test')).toBe(true);
    expect(hostMatchesEntry('evilcdn.example.test', '*.cdn.example.test')).toBe(false);
  });

  it('asks for allowed-host userinfo and denies a foreign parsed host despite allowed userinfo', () => {
    // what_bug_this_catches: stripping userinfo or comparing the entire URL string hides the actual destination.
    expect(verdictOf('posix', { kind: 'http', method: 'GET', url: 'https://deploy@api.example.test/' }).verdict).toBe('ask');
    expect(verdictOf('posix', { kind: 'http', method: 'GET', url: 'https://api.example.test@evil.test/' }).verdict).toBe('deny');
    expect(verdictOf('posix', { kind: 'http', method: 'GET', url: 'https://api.example.test%2eevil.test/' }).verdict).toBe('deny');
    expect(verdictOf('posix', { kind: 'http', method: 'GET', url: 'not a url' }).verdict).toBe('ask');
  });
});

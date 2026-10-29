import { describe, expect, it } from 'vitest';
import { normaliseAction } from '../../src/policyfix/normalise/index';
import { createBudget } from '../../src/policyfix/normalise/opaque';
import { reference, verdictOf } from '../helpers/reference';

describe('bounded PowerShell literals', () => {
  it.each([
    'Remove-Item -Recurse -Force -Path src', 'RI src -Recurse -Force',
    'rM -rec -fo -LiteralP src', '& "Remove-Item" -Recurse -Force src',
    'Write-Output ok; Remove-Item -Recurse src', 'Write-Output ok | Remove-Item -Force src',
    'pwsh -Command "Remove-Item -Recurse -Force src"', 'Get-Content -LiteralPath .env',
    'Start-Process -FilePath tool -Verb RunAs',
  ])('finds the restricted operation: %s', (command) => {
    // what_bug_this_catches: case/alias/parameter-prefix/wrapper/output spelling bypassing normalized policy effects.
    expect(verdictOf('windows', { kind: 'shell', dialect: 'powershell', command }).verdict).toBe('deny');
  });

  it.each(['Remove-Item -Recurse -Force -LiteralPath node_modules', 'Write-Output "Remove-Item -Recurse src"', 'Get-Content -Path .env.example'])('preserves permitted literals: %s', (command) => {
    // what_bug_this_catches: command names as data or the declared root-level deletion exception becoming false blocks.
    expect(verdictOf('windows', { kind: 'shell', dialect: 'powershell', command }).verdict).toBe('allow');
  });

  it.each([
    { url: 'https://api.example.test/', host: 'api.example.test', userinfo: false, verdict: 'allow', rule_id: null },
    { url: 'https://reader@api.example.test/', host: 'api.example.test', userinfo: true, verdict: 'ask', rule_id: 'q06-userinfo' },
    { url: 'https://api.example.test@evil.test/', host: 'evil.test', userinfo: true, verdict: 'deny', rule_id: 'q06-host-not-allowed' },
  ])('parses the actual destination of an unquoted URL: $url', ({ url, host, userinfo, verdict, rule_id }) => {
    // what_bug_this_catches: treating embedded @ as PowerShell expression syntax discards the HTTP action and hides
    // disallowed-host deny behind opaque ask; allowed-host userinfo must still ask via the actual userinfo rule.
    const action = { kind: 'shell', dialect: 'powershell', command: `Invoke-WebRequest ${url}` } as const;
    const normalised = normaliseAction(action, reference('windows').context);
    expect(normalised.opaque).toEqual([]);
    expect(normalised.subs.filter((sub) => sub.kind === 'http')).toMatchObject([{ host, userinfo }]);
    const result = verdictOf('windows', action);
    expect(result).toMatchObject({ verdict, rule_id });
    if (userinfo) expect(result.matched_rule_ids).toContain('q06-userinfo');
    expect(result.matched_rule_ids).not.toContain('opaque-construct');
  });

  it.each(['Invoke-WebRequest @request', "Invoke-WebRequest @('https://api.example.test/')", "Invoke-WebRequest @{Uri='https://api.example.test/'}"])(
    'keeps token-boundary splats and expressions opaque: %s', (command) => {
      // what_bug_this_catches: admitting embedded literal @ must not accept a splat/array/hashtable as literal URI data.
      const result = verdictOf('windows', { kind: 'shell', dialect: 'powershell', command });
      expect(result.verdict).toBe('ask');
      expect(result.matched_rule_ids).toContain('opaque-construct');
    },
  );

  it.each(['iex "Remove-Item src"', 'Invoke-Expression $payload', 'pwsh -EncodedCommand ZGF0YQ==', '& $tool src', 'Remove-Item -f src', 'Remove-Item -Path "$TARGET"', 'Remove-Item -WhatIf src', 'Remove-Item -Path a,b', 'Set-Location ../other; Remove-Item -Recurse dist', 'Write-Output "unterminated'])('asks for unsupported semantics: %s', (command) => {
    // what_bug_this_catches: ambiguous binding, dynamic execution, cwd changes or malformed syntax receiving allow.
    expect(verdictOf('windows', { kind: 'shell', dialect: 'powershell', command }).verdict).toBe('ask');
  });

  it('keeps prior completed restrictions and shared budget failures', () => {
    // what_bug_this_catches: a later parse/budget failure discarding an already emitted delete.
    expect(verdictOf('windows', { kind: 'shell', dialect: 'powershell', command: 'Remove-Item -Recurse src; Write-Output "unfinished' }).verdict).toBe('deny');
    const context = reference('windows').context;
    expect(normaliseAction({ kind: 'shell', dialect: 'powershell', command: 'Write-Output hello' }, context, createBudget(2)).opaque.some((finding) => finding.code === 'step-budget')).toBe(true);
    expect(normaliseAction({ kind: 'shell', dialect: 'powershell', command: 'Write-Output ok;'.repeat(129) }, context).opaque.some((finding) => finding.code === 'node-budget')).toBe(true);
  });

  it('distinguishes wildcard Path from literal wildcard spelling', () => {
    // what_bug_this_catches: treating PowerShell quoted -Path wildcards as literals or -LiteralPath as an expansion.
    const context = reference('windows').context;
    const result = normaliseAction({ kind: 'shell', dialect: 'powershell', command: "Get-Content -Path 'docs/*.md'" }, context);
    expect(result.opaque.some((finding) => finding.code === 'wildcard-operand')).toBe(true);
    const literal = normaliseAction({ kind: 'shell', dialect: 'powershell', command: "Get-Content -LiteralPath 'docs/[a].md'" }, context);
    expect(literal.opaque).toEqual([]);
    expect(literal.subs.some((sub) => sub.kind === 'fs' && sub.path.root_relative === 'docs/[a].md')).toBe(true);
  });
});

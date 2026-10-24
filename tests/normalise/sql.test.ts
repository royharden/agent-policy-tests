import { describe, expect, it } from 'vitest';
import { analyseSql } from '../../src/policyfix/normalise/sql';
import { createBudget } from '../../src/policyfix/normalise/opaque';
import { normaliseAction } from '../../src/policyfix/normalise/index';
import { reference, verdictOf } from '../helpers/reference';

describe('bounded SQL scanner', () => {
  it.each(['DROP/**/TABLE demo', 'DELETE FROM demo -- WHERE id = 7', 'DELETE FROM demo WHERE 1 = 1', 'UPDATE demo SET x=1 WHERE TRUE', 'SELECT 1; TRUNCATE demo'])('finds destructive SQL: %s', (statement) => {
    // what_bug_this_catches: comments, tautologies and later statements hiding destructive operations.
    expect(verdictOf('posix', { kind: 'sql', statement }).verdict).toBe('deny');
  });

  it.each(["SELECT 'DROP TABLE demo; DELETE FROM demo'", 'SELECT 1 /* DROP TABLE demo */', 'DELETE FROM demo WHERE id=7', "WITH ids AS (SELECT id FROM demo WHERE active=true) DELETE FROM demo WHERE id IN (SELECT id FROM ids)"])('permits quoted data or bounded operations: %s', (statement) => {
    // what_bug_this_catches: keywords inside literals/CTEs being mistaken for the main destructive verb or WHERE.
    expect(verdictOf('posix', { kind: 'sql', statement }).verdict).toBe('allow');
  });

  it('splits only top-level semicolons and rejects malformed or dynamic SQL', () => {
    // what_bug_this_catches: splitting a nested expression as a top-level statement or silently accepting unmatched syntax.
    const analysed = analyseSql('SELECT (1;2); SELECT 3', createBudget());
    expect(analysed.statements).toHaveLength(2);
    for (const statement of ["EXECUTE 'DROP TABLE demo'", "SELECT 'unterminated", 'SELECT (1', 'DELETE FROM demo WHERE id=1)', 'WITH wiped AS (DELETE FROM demo RETURNING *) SELECT * FROM wiped']) {
      expect(verdictOf('posix', { kind: 'sql', statement }).verdict).toBe('ask');
    }
  });

  it.each(["SELECT 'unterminated", 'SELECT /* unterminated', 'SELECT "unterminated', 'SELECT $tag$unterminated', 'SELECT (1', 'SELECT 1)'])('keeps completed destructive statements before a later parse failure: %s', (suffix) => {
    // what_bug_this_catches: tokenizing the entire input before emission used to discard a completed DROP when a
    // later statement was malformed, reducing a visible deny to opaque ask.
    const statement = `SELECT 1; DROP TABLE demo; ${suffix}`;
    const analysed = analyseSql(statement, createBudget());
    expect(analysed.statements.map((item) => item.verb)).toEqual(['SELECT', 'DROP']);
    expect(analysed.opaque.map((finding) => finding.code)).toContain('sql-syntax');
    const decision = verdictOf('posix', { kind: 'sql', statement });
    expect(decision.verdict).toBe('deny');
    expect(decision.rule_id).toBe('q11-drop-truncate');
    expect(decision.matched_rule_ids).toContain('opaque-construct');
  });

  it('aggregates dynamic findings with later syntax errors while keeping earlier destructive statements', () => {
    // what_bug_this_catches: syntax failure must not erase either completed SQL facts or earlier opaque findings.
    const analysed = analyseSql("DROP TABLE demo; EXECUTE 'SELECT 1'; SELECT 'unterminated", createBudget());
    expect(analysed.statements.map((item) => item.verb)).toEqual(['DROP']);
    expect(analysed.opaque.map((finding) => finding.code)).toEqual(expect.arrayContaining(['dynamic-sql', 'sql-syntax']));
    expect(verdictOf('posix', { kind: 'sql', statement: "SELECT 1; SELECT 'unterminated" }).verdict).toBe('ask');
    expect(verdictOf('posix', { kind: 'sql', statement: "DROP TABLE demo SELECT 'unterminated" }).verdict).toBe('ask');
  });

  it('preserves completed SQL sub-actions on later budget exhaustion', () => {
    // what_bug_this_catches: a budget exception thrown before emitSql returns must not discard completed statements.
    const statement = `DROP TABLE demo; SELECT '${'x'.repeat(100)}'`;
    const analysed = analyseSql(statement, createBudget(24));
    expect(analysed.statements.map((item) => item.verb)).toEqual(['DROP']);
    expect(analysed.opaque.map((finding) => finding.code)).toEqual(['step-budget']);
    const normalised = normaliseAction({ kind: 'sql', statement }, reference('posix').context, createBudget(24));
    expect(normalised.subs.filter((sub) => sub.kind === 'sql').map((sub) => sub.verb)).toEqual(['DROP']);
    expect(normalised.opaque.map((finding) => finding.code)).toEqual(['step-budget']);
  });
});

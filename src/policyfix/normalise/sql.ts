// SQL statement analysis (PLAN M3 AC4; Claude §2.5 "SQL"; RUBRIC §3 Q11). A hand-written tokenizer — no regex, no parser
// generator, no database.
//   - string literals ('…' with '' doubling, E'…' with backslash escapes, $tag$…$tag$), quoted identifiers ("…", `…`)
//     are respected: keywords inside them are data (`SELECT 'DROP TABLE users'` is a SELECT);
//   - comments (`-- …`, nested `/* … */`) are replaced by a space (`DROP/**/TABLE` → `DROP TABLE`;
//     `DELETE FROM users -- WHERE id = 7` has no WHERE);
//   - statements split on top-level `;`; every statement becomes one sub-action;
//     completed statements are retained if a later statement has malformed syntax or exhausts the budget;
//   - verb = first keyword (for `WITH …` the first top-level SELECT/INSERT/UPDATE/DELETE/MERGE after the CTEs);
//   - bounded = a top-level WHERE exists and its clause is not a constant tautology. The tautology set is exactly
//     {`1=1`, `true`} after removing whitespace and case-folding (RUBRIC Q11, STATUS OD4);
//   - dynamic SQL (EXEC, EXECUTE, DO, PREPARE) and unterminated literals/comments are opaque → ask.
// Framework-free.
import { AnalysisLimitError, type OpaqueFinding, opaqueFinding, type StepBudget, spendOrThrow } from './opaque';

export interface SqlStatementInfo {
  readonly verb: string;
  readonly bounded: boolean;
  readonly text: string;
}

export interface SqlAnalysis {
  readonly statements: readonly SqlStatementInfo[];
  readonly opaque: readonly OpaqueFinding[];
}

type TokenType = 'word' | 'number' | 'string' | 'ident' | 'punct';

interface Token {
  readonly type: TokenType;
  /** Upper-cased for words; the literal text otherwise. */
  readonly text: string;
}

const DYNAMIC_VERBS: readonly string[] = ['EXEC', 'EXECUTE', 'DO', 'PREPARE'];
const MAIN_VERBS_AFTER_WITH: readonly string[] = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MERGE'];
const WHERE_CLAUSE_END: readonly string[] = ['RETURNING', 'ORDER', 'LIMIT', 'GROUP', 'OPTION', 'OFFSET', 'FETCH'];
/** Exactly the RUBRIC Q11 tautology set, compared after whitespace removal and lower-casing. */
export const SQL_TAUTOLOGIES: readonly string[] = ['1=1', 'true'];

function isWordStart(ch: string): boolean {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_' || ch > '\u007f';
}

function isWordChar(ch: string): boolean {
  return isWordStart(ch) || (ch >= '0' && ch <= '9') || ch === '$';
}

function isDigit(ch: string): boolean {
  return ch >= '0' && ch <= '9';
}

function isBlank(ch: string): boolean {
  return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v';
}

class SqlSyntaxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SqlSyntaxError';
  }
}

interface Tokenised {
  /** Statements as token lists, in order (empty statements dropped). */
  readonly statements: Token[][];
  /** Comment-free text per statement, for reasons. */
  readonly texts: string[];
}

function tokenise(text: string, budget: StepBudget, completed: Tokenised): void {
  const { statements, texts } = completed;
  let current: Token[] = [];
  let currentText = '';
  let parenDepth = 0;
  const flush = (): void => {
    if (current.length > 0) {
      statements.push(current);
      texts.push(currentText.trim());
    }
    current = [];
    currentText = '';
  };
  let i = 0;
  while (i < text.length) {
    spendOrThrow(budget);
    const ch = text.charAt(i);
    const next = text.charAt(i + 1);
    if (isBlank(ch)) {
      currentText += ' ';
      i += 1;
      continue;
    }
    if (ch === '-' && next === '-') {
      const end = text.indexOf('\n', i);
      spendOrThrow(budget, (end < 0 ? text.length : end) - i);
      i = end < 0 ? text.length : end + 1;
      currentText += ' ';
      continue;
    }
    if (ch === '/' && next === '*') {
      let depth = 1;
      let j = i + 2;
      while (j < text.length && depth > 0) {
        spendOrThrow(budget);
        if (text.charAt(j) === '/' && text.charAt(j + 1) === '*') {
          depth += 1;
          j += 2;
        } else if (text.charAt(j) === '*' && text.charAt(j + 1) === '/') {
          depth -= 1;
          j += 2;
        } else {
          j += 1;
        }
      }
      if (depth > 0) throw new SqlSyntaxError('unterminated /* comment');
      i = j;
      currentText += ' ';
      continue;
    }
    if (ch === ';' && parenDepth === 0) {
      flush();
      i += 1;
      continue;
    }
    if (ch === "'") {
      // E'…' (PostgreSQL escape string): the E must touch the quote.
      const previous = current[current.length - 1];
      const before = text.charAt(i - 1);
      const escapeMode =
        previous !== undefined && previous.type === 'word' && previous.text === 'E' && (before === 'E' || before === 'e');
      let j = i + 1;
      let closed = false;
      while (j < text.length) {
        spendOrThrow(budget);
        const c = text.charAt(j);
        if (escapeMode && c === '\\') {
          j += 2;
          continue;
        }
        if (c === "'") {
          if (text.charAt(j + 1) === "'") {
            j += 2;
            continue;
          }
          closed = true;
          break;
        }
        j += 1;
      }
      if (!closed) throw new SqlSyntaxError('unterminated string literal');
      current.push({ type: 'string', text: text.slice(i, j + 1) });
      currentText += text.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (ch === '"' || ch === '`') {
      let j = i + 1;
      let closed = false;
      while (j < text.length) {
        spendOrThrow(budget);
        if (text.charAt(j) === ch) {
          if (text.charAt(j + 1) === ch) {
            j += 2;
            continue;
          }
          closed = true;
          break;
        }
        j += 1;
      }
      if (!closed) throw new SqlSyntaxError('unterminated quoted identifier');
      current.push({ type: 'ident', text: text.slice(i, j + 1) });
      currentText += text.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (ch === '$' && (next === '$' || isWordStart(next))) {
      // Dollar quoting: $$…$$ or $tag$…$tag$. `$name` without a closing `$` is a parameter-like word.
      let j = i + 1;
      while (j < text.length && isWordChar(text.charAt(j)) && text.charAt(j) !== '$') j += 1;
      if (text.charAt(j) === '$') {
        const tag = text.slice(i, j + 1);
        const close = text.indexOf(tag, j + 1);
        if (close < 0) throw new SqlSyntaxError('unterminated dollar-quoted string');
        spendOrThrow(budget, close - i);
        current.push({ type: 'string', text: text.slice(i, close + tag.length) });
        currentText += text.slice(i, close + tag.length);
        i = close + tag.length;
        continue;
      }
    }
    if (isWordStart(ch)) {
      let j = i + 1;
      while (j < text.length && isWordChar(text.charAt(j))) j += 1;
      const word = text.slice(i, j);
      current.push({ type: 'word', text: word.toUpperCase() });
      currentText += word;
      i = j;
      continue;
    }
    if (isDigit(ch)) {
      let j = i + 1;
      while (j < text.length && (isDigit(text.charAt(j)) || text.charAt(j) === '.')) j += 1;
      current.push({ type: 'number', text: text.slice(i, j) });
      currentText += text.slice(i, j);
      i = j;
      continue;
    }
    if (ch === '(') parenDepth += 1;
    if (ch === ')') {
      if (parenDepth === 0) throw new SqlSyntaxError('unbalanced closing parenthesis');
      parenDepth -= 1;
    }
    current.push({ type: 'punct', text: ch });
    currentText += ch;
    i += 1;
  }
  if (parenDepth !== 0) throw new SqlSyntaxError('unbalanced opening parenthesis');
  flush();
}

/** Index of the first word token at parenthesis depth 0 at or after `from` satisfying `pred`, or -1. */
function findTopLevelWord(tokens: readonly Token[], from: number, pred: (word: string) => boolean): number {
  let depth = 0;
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token === undefined) continue;
    if (token.type === 'punct' && token.text === '(') depth += 1;
    else if (token.type === 'punct' && token.text === ')') depth = Math.max(0, depth - 1);
    else if (i >= from && depth === 0 && token.type === 'word' && pred(token.text)) return i;
  }
  return -1;
}

function analyseStatement(tokens: readonly Token[], text: string): SqlStatementInfo | OpaqueFinding {
  const verbIndex = tokens.findIndex((token) => token.type === 'word');
  const firstWord = verbIndex >= 0 ? tokens[verbIndex] : undefined;
  if (firstWord === undefined) return { verb: '', bounded: true, text };
  let verb = firstWord.text;
  let mainIndex = verbIndex;
  if (DYNAMIC_VERBS.includes(verb)) {
    return opaqueFinding('dynamic-sql', `dynamic SQL (${verb}) cannot be analysed`);
  }
  if (verb === 'WITH') {
    const found = findTopLevelWord(tokens, verbIndex + 1, (word) => MAIN_VERBS_AFTER_WITH.includes(word));
    const main = found >= 0 ? tokens[found] : undefined;
    if (main === undefined) return opaqueFinding('sql-syntax', 'WITH clause without a recognised main statement');
    if (tokens.slice(verbIndex + 1, found).some((token) => token.type === 'word' && ['INSERT', 'UPDATE', 'DELETE', 'MERGE'].includes(token.text))) {
      return opaqueFinding('dynamic-sql', 'data-changing CTE bodies are outside the supported SQL subset');
    }
    verb = main.text;
    mainIndex = found;
  }
  const whereIndex = findTopLevelWord(tokens, mainIndex + 1, (word) => word === 'WHERE');
  if (whereIndex < 0) return { verb, bounded: false, text };
  const clauseEnd = findTopLevelWord(tokens, whereIndex + 1, (word) => WHERE_CLAUSE_END.includes(word));
  const clause = tokens
    .slice(whereIndex + 1, clauseEnd < 0 ? tokens.length : clauseEnd)
    .map((token) => token.text)
    .join('')
    .toLowerCase();
  if (clause.length === 0) return { verb, bounded: false, text };
  return { verb, bounded: !SQL_TAUTOLOGIES.includes(clause), text };
}

function isOpaque(value: SqlStatementInfo | OpaqueFinding): value is OpaqueFinding {
  return 'code' in value;
}

/** Completed statements survive a later syntax/budget failure; the unfinished suffix contributes only an opaque ask. */
export function analyseSql(text: string, budget: StepBudget): SqlAnalysis {
  const tokenised: Tokenised = { statements: [], texts: [] };
  const opaque: OpaqueFinding[] = [];
  try {
    tokenise(text, budget, tokenised);
  } catch (error: unknown) {
    if (error instanceof SqlSyntaxError) {
      opaque.push(opaqueFinding('sql-syntax', error.message));
    } else if (error instanceof AnalysisLimitError) {
      opaque.push(opaqueFinding(error.code, error.message));
    } else throw error;
  }
  const statements: SqlStatementInfo[] = [];
  tokenised.statements.forEach((tokens, index) => {
    const result = analyseStatement(tokens, tokenised.texts[index] ?? '');
    if (isOpaque(result)) opaque.push(result);
    else if (result.verb !== '') statements.push(result);
  });
  return { statements, opaque };
}

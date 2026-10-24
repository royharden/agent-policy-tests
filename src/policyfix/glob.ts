// The app's own glob matcher (PLAN M3 AC2, A6, A23). No regular expressions (ESLint-enforced for this file); every
// comparison spends one step from the per-action budget shared with the scanner, and an exhausted budget returns
// `budget-exceeded`, which the guard turns into an `ask` via opaque-construct.
//
// Syntax:
//   *        any run of characters except the separator (in separator mode)
//   ?        one character except the separator
//   [abc] [a-z] [!x] [^x]   character class (an unterminated `[` is a literal)
//   \x       literal x
//   **       as a whole segment (separator mode): zero or more segments. `a/**` matches `a` and everything below it;
//            `**/x` matches `x` at any depth. `**` inside a segment behaves like `*`.
// Options: `fold` compares case-insensitively; `separator: '/'` enables segment semantics (paths, branches), `null`
// makes the text one segment where `*` matches anything (hosts, names).
// Framework-free.
import { spend, type StepBudget } from './normalise/opaque';

export type GlobOutcome = 'match' | 'no-match' | 'budget-exceeded';

export interface GlobOptions {
  readonly fold: boolean;
  readonly separator: '/' | null;
}

interface ClassRange {
  readonly lo: string;
  readonly hi: string;
}

type Token =
  | { readonly t: 'lit'; readonly ch: string }
  | { readonly t: 'any' }
  | { readonly t: 'star' }
  | { readonly t: 'class'; readonly negated: boolean; readonly ranges: readonly ClassRange[] };

/** Tokenises one pattern segment. Consecutive stars collapse into one. */
function tokenise(pattern: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < pattern.length) {
    const c = pattern.charAt(i);
    if (c === '\\') {
      const next = pattern.charAt(i + 1);
      tokens.push({ t: 'lit', ch: next === '' ? '\\' : next });
      i += next === '' ? 1 : 2;
      continue;
    }
    if (c === '*') {
      if (tokens[tokens.length - 1]?.t !== 'star') tokens.push({ t: 'star' });
      i += 1;
      continue;
    }
    if (c === '?') {
      tokens.push({ t: 'any' });
      i += 1;
      continue;
    }
    if (c === '[') {
      let j = i + 1;
      let negated = false;
      if (pattern.charAt(j) === '!' || pattern.charAt(j) === '^') {
        negated = true;
        j += 1;
      }
      const ranges: ClassRange[] = [];
      let first = true;
      let closed = false;
      while (j < pattern.length) {
        const m = pattern.charAt(j);
        if (m === ']' && !first) {
          closed = true;
          break;
        }
        first = false;
        if (pattern.charAt(j + 1) === '-' && pattern.charAt(j + 2) !== ']' && j + 2 < pattern.length) {
          ranges.push({ lo: m, hi: pattern.charAt(j + 2) });
          j += 3;
        } else {
          ranges.push({ lo: m, hi: m });
          j += 1;
        }
      }
      if (closed) {
        tokens.push({ t: 'class', negated, ranges });
        i = j + 1;
        continue;
      }
      tokens.push({ t: 'lit', ch: '[' });
      i += 1;
      continue;
    }
    tokens.push({ t: 'lit', ch: c });
    i += 1;
  }
  return tokens;
}

function tokenMatches(token: Token, ch: string, budget: StepBudget): boolean | null {
  switch (token.t) {
    case 'lit':
      return token.ch === ch;
    case 'any':
      return true;
    case 'star':
      return false;
    case 'class': {
      let inClass = false;
      for (const range of token.ranges) {
        if (!spend(budget)) return null;
        if (ch >= range.lo && ch <= range.hi) {
          inClass = true;
          break;
        }
      }
      return token.negated ? !inClass : inClass;
    }
  }
}

/** Two-pointer wildcard match with single star backtracking: O(text × pattern) steps. null = budget exhausted. */
function matchTokens(tokens: readonly Token[], text: string, budget: StepBudget): boolean | null {
  let p = 0;
  let t = 0;
  let starP = -1;
  let starT = 0;
  while (t < text.length) {
    if (!spend(budget)) return null;
    const token = tokens[p];
    const matches = token === undefined || token.t === 'star' ? false : tokenMatches(token, text.charAt(t), budget);
    if (matches === null) return null;
    if (matches) {
      p += 1;
      t += 1;
      continue;
    }
    if (token !== undefined && token.t === 'star') {
      starP = p;
      starT = t;
      p += 1;
      continue;
    }
    if (starP >= 0) {
      p = starP + 1;
      starT += 1;
      t = starT;
      continue;
    }
    return false;
  }
  while (tokens[p]?.t === 'star') p += 1;
  return p === tokens.length;
}

/** Segment matching with `**`; recursion is bounded by the step budget. */
function matchSegments(
  patterns: readonly (readonly Token[] | 'globstar')[],
  pi: number,
  segments: readonly string[],
  si: number,
  budget: StepBudget,
): boolean | null {
  if (!spend(budget)) return null;
  if (pi === patterns.length) return si === segments.length;
  const pattern = patterns[pi];
  if (pattern === undefined) return false;
  if (pattern === 'globstar') {
    for (let k = si; k <= segments.length; k += 1) {
      const result = matchSegments(patterns, pi + 1, segments, k, budget);
      if (result === null) return null;
      if (result) return true;
    }
    return false;
  }
  const segment = segments[si];
  if (segment === undefined) return false;
  const here = matchTokens(pattern, segment, budget);
  if (here === null) return null;
  if (!here) return false;
  return matchSegments(patterns, pi + 1, segments, si + 1, budget);
}

/** Matches `text` against `pattern`, spending steps from `budget`. */
export function globMatch(pattern: string, text: string, budget: StepBudget, options: GlobOptions): GlobOutcome {
  // Charge tokenisation/folding too: a long pattern against an empty value must not be free.
  if (!spend(budget, pattern.length + text.length + 1)) return 'budget-exceeded';
  const p = options.fold ? pattern.toLowerCase() : pattern;
  const t = options.fold ? text.toLowerCase() : text;
  let result: boolean | null;
  if (options.separator === null) {
    result = matchTokens(tokenise(p), t, budget);
  } else {
    const patterns = p.split(options.separator).map((segment) => (segment === '**' ? ('globstar' as const) : tokenise(segment)));
    result = matchSegments(patterns, 0, t.split(options.separator), 0, budget);
  }
  if (result === null) return 'budget-exceeded';
  return result ? 'match' : 'no-match';
}

/** Matches against any of `patterns`; `budget-exceeded` wins over `no-match` but not over an earlier `match`. */
export function globMatchAny(
  patterns: readonly string[],
  text: string,
  budget: StepBudget,
  options: GlobOptions,
): GlobOutcome {
  for (const pattern of patterns) {
    const outcome = globMatch(pattern, text, budget, options);
    if (outcome !== 'no-match') return outcome;
  }
  return 'no-match';
}

/**
 * Instantiates a glob into one concrete string that the glob matches (used by templates to build declared example
 * actions): `*` and `**` → `fill`, `?` → `x`, a class → its first member (or `z` when negated).
 */
export function instantiateGlob(pattern: string, fill: string): string {
  let out = '';
  for (const token of tokenise(pattern)) {
    switch (token.t) {
      case 'lit':
        out += token.ch;
        break;
      case 'any':
        out += 'x';
        break;
      case 'star':
        out += fill;
        break;
      case 'class':
        out += token.negated ? 'z' : (token.ranges[0]?.lo ?? 'x');
        break;
    }
  }
  return out;
}

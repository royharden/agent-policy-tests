// Argument / flag expansion (PLAN M3 AC3; RUBRIC §4 "Flags may be combined, split, long, reordered, placed after
// operands, abbreviated"). Shared by the posix normaliser now and the PowerShell/cmd normalisers in M5.
//   - `--` ends options; a lone `-` is an operand;
//   - `--name=value` → flag `--name` with value; `--name=false|0|no|off` → flag `--no-name` (so `--dry-run=false` is
//     not mistaken for `--dry-run`);
//   - GNU long-option abbreviations resolve against a command's known long options (`rm --recur` → `--recursive`);
//     an ambiguous abbreviation keeps its spelling and is reported;
//   - short clusters expand (`-rf` → `-r`, `-f`); a value-taking short flag consumes the rest of the cluster or the
//     next word (`-ofile`, `-o file`);
//   - single-dash long options (`-chdir=infra`) are recognised when the command declares them or contain `=`;
//   - GNU permutation: flags may follow operands unless the spec says options stop at the first operand;
//   - a dynamic word (`$X`) is a flag only when its literal text starts with `-`.
// Framework-free, no regex.
import type { ArgWord } from './types';

export interface ArgSpec {
  /** Flags (short `-o` or long `--output`) that take a value. */
  readonly valueFlags?: readonly string[];
  /** Known long options, for GNU unique-prefix abbreviation. */
  readonly longFlags?: readonly string[];
  /** Single-dash multi-letter options (`-chdir`, `-name`) that must not be split into a short cluster. */
  readonly singleDashLong?: readonly string[];
  /** Every single-dash word is one option, never a short cluster (terraform `-auto-approve`, sqlite3 `-cmd`). */
  readonly singleDashIsLong?: boolean;
  /** Short flags whose value may only be attached (`sed -i.bak`), never taken from the next word. */
  readonly attachedValueFlags?: readonly string[];
  /** POSIX strict: options end at the first operand (`sudo`, `env`, `bash`, `timeout`). */
  readonly stopAtFirstOperand?: boolean;
}

export interface FlagValue<W extends ArgWord> {
  readonly flag: string;
  /** The value as a word (attached values are synthesised from the flag word). */
  readonly value: W | ArgWord;
}

export interface ParsedArgs<W extends ArgWord> {
  readonly flags: readonly string[];
  readonly operands: readonly W[];
  readonly values: readonly FlagValue<W>[];
  /** Index (into the input) of the first operand, or the input length when there is none. */
  readonly firstOperandIndex: number;
  /** Abbreviations that matched more than one known long option. */
  readonly ambiguous: readonly string[];
}

const FALSY_VALUES: readonly string[] = ['false', '0', 'no', 'off'];

/** Resolves a GNU long-option abbreviation. Exact match wins; else a unique prefix; else ambiguous or unknown. */
export function expandLongPrefix(
  name: string,
  known: readonly string[],
): { readonly kind: 'exact' | 'prefix'; readonly name: string } | { readonly kind: 'ambiguous'; readonly candidates: readonly string[] } | { readonly kind: 'unknown' } {
  if (known.includes(name)) return { kind: 'exact', name };
  if (name.length < 3) return { kind: 'unknown' };
  const candidates = known.filter((option) => option.startsWith(name));
  if (candidates.length === 1) {
    const only = candidates[0];
    if (only !== undefined) return { kind: 'prefix', name: only };
  }
  if (candidates.length > 1) return { kind: 'ambiguous', candidates };
  return { kind: 'unknown' };
}

function literalWord(text: string): ArgWord {
  return { text, dynamic: false, wildcard: false };
}

function isFlagWord(word: ArgWord): boolean {
  return word.text.startsWith('-') && word.text !== '-';
}

/** Parses posix-style arguments (everything after the program name). */
export function parsePosixArgs<W extends ArgWord>(words: readonly W[], spec: ArgSpec = {}): ParsedArgs<W> {
  const valueFlags = spec.valueFlags ?? [];
  const longFlags = spec.longFlags ?? [];
  const singleDashLong = spec.singleDashLong ?? [];
  const attached = spec.attachedValueFlags ?? [];
  const flags: string[] = [];
  const operands: W[] = [];
  const values: FlagValue<W>[] = [];
  const ambiguous: string[] = [];
  let firstOperandIndex = words.length;
  let endOfOptions = false;
  const addFlag = (flag: string): void => {
    if (!flags.includes(flag)) flags.push(flag);
  };

  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    if (word === undefined) continue;
    if (endOfOptions || !isFlagWord(word)) {
      if (firstOperandIndex === words.length) firstOperandIndex = i;
      operands.push(word);
      if (spec.stopAtFirstOperand === true) endOfOptions = true;
      continue;
    }
    const text = word.text;
    if (text === '--') {
      endOfOptions = true;
      continue;
    }
    if (text.startsWith('--')) {
      const eq = text.indexOf('=');
      const rawName = eq >= 0 ? text.slice(0, eq) : text;
      const resolved = longFlags.length > 0 ? expandLongPrefix(rawName, longFlags) : ({ kind: 'exact', name: rawName } as const);
      let name = rawName;
      if (resolved.kind === 'exact' || resolved.kind === 'prefix') name = resolved.name;
      else if (resolved.kind === 'ambiguous') ambiguous.push(rawName);
      if (eq >= 0) {
        const value = text.slice(eq + 1);
        if (FALSY_VALUES.includes(value.toLowerCase())) addFlag(`--no-${name.slice(2)}`);
        else addFlag(name);
        values.push({ flag: name, value: { text: value, dynamic: word.dynamic, wildcard: word.wildcard } });
        continue;
      }
      addFlag(name);
      if (valueFlags.includes(name)) {
        const next = words[i + 1];
        if (next !== undefined) {
          values.push({ flag: name, value: next });
          i += 1;
        }
      }
      continue;
    }
    // Single dash.
    const eq = text.indexOf('=');
    const bareName = eq >= 0 ? text.slice(0, eq) : text;
    if (spec.singleDashIsLong === true || singleDashLong.includes(bareName) || (eq >= 0 && bareName.length > 2)) {
      addFlag(bareName);
      if (eq >= 0) {
        values.push({ flag: bareName, value: { text: text.slice(eq + 1), dynamic: word.dynamic, wildcard: word.wildcard } });
      } else if (valueFlags.includes(bareName)) {
        const next = words[i + 1];
        if (next !== undefined) {
          values.push({ flag: bareName, value: next });
          i += 1;
        }
      }
      continue;
    }
    for (let j = 1; j < text.length; j += 1) {
      const flag = `-${text.charAt(j)}`;
      addFlag(flag);
      if (attached.includes(flag)) {
        const rest = text.slice(j + 1);
        if (rest.length > 0) values.push({ flag, value: literalWord(rest) });
        break;
      }
      if (valueFlags.includes(flag)) {
        const rest = text.slice(j + 1);
        if (rest.length > 0) {
          values.push({ flag, value: { text: rest, dynamic: word.dynamic, wildcard: word.wildcard } });
        } else {
          const next = words[i + 1];
          if (next !== undefined) {
            values.push({ flag, value: next });
            i += 1;
          }
        }
        break;
      }
    }
  }
  return { flags, operands, values, firstOperandIndex, ambiguous };
}

/** All values given for any of `names`. */
export function valuesOf<W extends ArgWord>(parsed: ParsedArgs<W>, names: readonly string[]): (W | ArgWord)[] {
  return parsed.values.filter((entry) => names.includes(entry.flag)).map((entry) => entry.value);
}

export function hasAnyFlag(parsed: ParsedArgs<ArgWord>, names: readonly string[]): boolean {
  return parsed.flags.some((flag) => names.includes(flag));
}

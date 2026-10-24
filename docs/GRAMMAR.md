# Supported policy grammar

Construction status: source written and inspected in Dirty Mode. Tests, type checking, lint and browser behavior have
not run. This document describes the implemented lexical subset; it does not claim shell, SQL or filesystem equivalence.
The normalizer never runs commands or reads the real filesystem, environment, repository state or DNS.

## Inputs and decisions

The seven action kinds are `shell`, `fs`, `http`, `sql`, `git`, `payment` and `message`. Strict input schemas reject
unknown keys, invalid enums and invalid amounts before evaluation. Strings are capped at 4,096 characters; payment
amounts are nonnegative safe integer cents with three uppercase ASCII currency letters.

One action becomes a flat list of sub-actions and opaque findings. Every rule applies to every compatible sub-action.
Control flow is ignored: `true || rm -rf /` includes the delete. Decisions combine as `deny > ask > allow`; equal
effects choose the lowest rule id in code-unit order, and all matching ids are returned. Unmatched actions use
`policy.default_unmatched` (`allow` or `ask`). Opaque findings, unsupported constructs and evaluator errors ask through
the fixed `opaque-construct` rule, which cannot be disabled. A visible deny elsewhere in the action still wins.

## Structured match language

A match is a nonempty conjunction on one sub-action kind. `negate` inverts a predicate, including a false predicate on
a null field; a field from another kind never matches. `src/policyfix/match.ts` defines the global field table and each
template's `fields` table narrows it. Imports using an incompatible field/operator combination ask.

| Operator | Meaning |
|---|---|
| `eq` | Scalar equality; selected fields fold case. Numeric `arg` supplies the limit for `payment.amount_exceeds`. |
| `in` | Scalar equals one listed value. |
| `glob` | Matches any listed pattern using the bounded matcher below. |
| `prefix` | String prefix, or a whole-token prefix for `command.words`. |
| `command_name` | Exact normalized program name in the listed names. |
| `flags_include` | Every listed flag is present after flag expansion. |
| `sql_without_where` | Listed DELETE/UPDATE verb without a modeled bounding WHERE clause. |
| `host_not_in` | Parsed host is outside the allow-list; empty list denies all hosts. |

Globs support `*`, `?`, `[abc]`, `[a-z]`, `[!x]`, `[^x]` and backslash literal escapes. An unterminated `[` is literal.
For path and branch fields, `*` and `?` do not cross `/`; a whole `**` segment matches zero or more segments.
`secrets/**` includes `secrets` itself and descendants; `**/.env` also matches `.env` at the root. Inside a segment,
repeated stars behave as one star. Case folding follows the field: secret names always fold, paths follow context,
posix commands retain case. There is no regex operator and the matcher uses no regex.

## POSIX shell

The scanner understands single/double quotes, concatenated quoted words, backslash escapes and line continuations,
comments at word boundaries, `;`, newline, `&&`, `||`, `|`, `|&`, background `&`, subshell parentheses, `$(...)` and
backtick substitutions. Substitution bodies are analyzed as commands; their output remains unknown. Literal `~`,
`$HOME` and `${HOME}` resolve from `context.home`; other variables stay dynamic. Unquoted file globs/brace expansions
are marked opaque because their expansion depends on the filesystem, while any visible literal prohibition remains.

Leading `NAME=value` assignments are skipped. Transparent wrappers include `sudo`, `doas`, `env`, `command`, `nohup`,
`exec`, `time`, `nice`, `timeout`, `stdbuf` and `npx`. Elevation wrappers emit their own command before unwrapping.
`command -v/-V` are lookups. `env -S`, `npx -c`, `su -c`, `eval`, `source`, `.`, `xargs`, `parallel` and `find` execution
actions ask. `cd`, `pushd`, `popd`, `env -C/--chdir` and `sudo -D/--chdir` ask because the context is fixed.
This subset does not emulate assignment effects or shell startup/configuration files.

Literal `sh`/`bash`/`zsh` family `-c` strings (including `-lc`) are recursively scanned. Inline interpreter programs,
dynamic command words and shells/interpreters reading programs from stdin ask. Running a script file is judged only
by its command line; the file's contents are unknown. Loops that bind variables, function definitions, here-documents,
arithmetic containing nested commands, and unbalanced quotes/parentheses ask.

Flags can occur after operands, except for wrappers whose options stop at the first operand. `--` ends options;
short clusters expand (`-fr`), known value flags consume their values and known GNU long-option prefixes resolve
uniquely. Command-specific flag tables live in `shell-posix.ts` and `flags.ts`.
The normalized `rm` command flags use `-r` for `-r`/`-R`/`--recursive` and `-f` for `-f`/`--force`; filesystem-delete
mode still derives from the parsed options. This keeps free-text flag predicates aligned with evaluated commands.

Recognized filesystem effects include `rm`/`rmdir`/`unlink`, sources and destinations of `cp`/`mv`/`install`, `ln`
destinations, `touch`/`mkdir`/`tee`/`truncate`, `dd if=/of=`, common file readers, `grep`/`rg` file operands after the
pattern, and modeled `sed` in-place writes. This is a bounded list; arbitrary executables' filesystem effects are
not inferred. `curl`/`wget` URLs and known upload/config/output file flags are analyzed. Package managers and git
are not generic HTTP egress actions. SQL passed literally to modeled `psql`/`mysql`/`sqlite3` flags is analyzed.

Redirections `>`, `>>`, `>|`, `2>`, `&>`, `&>>`, `>&file`, `<` and `<>` emit file sub-actions. FD duplication and close
forms such as `2>&1` and `>&-` touch no modeled file. Dynamic targets, here-strings and here-documents ask. Standard
POSIX stream/device targets `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/stdin`, `/dev/tty`, `/dev/zero`,
`/dev/random`, `/dev/urandom` and numeric `/dev/fd/N` are intentionally excluded from filesystem-write checks.

## PowerShell and cmd

M5 supplies bounded literal scanners for both dialects. Each shares the action's 20,000-step scanner/glob budget,
128-command node cap and wrapper depth of three. Completed commands emit immediately; a malformed later suffix
adds an opaque finding without erasing their effects. Unrecognized programs and binding syntax ask. This is a
lexical subset, not PowerShell or cmd emulation. Structured non-shell Windows actions use the same path logic.

PowerShell supports case-insensitive cmdlets and common aliases: `Remove-Item` (`rm`, `ri`, `del`, `erase`, `rd`,
`rmdir`), `Get-Content` (`cat`, `gc`, `type`), `Get-ChildItem` (`ls`, `dir`, `gci`), `Set-Content` (`sc`),
`Add-Content` (`ac`), `Out-File`, `Write-Output` (`echo`, `write`), `Invoke-WebRequest` (`iwr`),
`Invoke-RestMethod` (`irm`) and literal `git` argv. Only unique parameter prefixes within the documented per-command
table are accepted; ambiguous `Remove-Item -f` asks. `-Path` and `-LiteralPath` accept literal paths;
quoted `-Path` wildcards still ask, while `-LiteralPath` suppresses wildcard expansion. Literal `-Recurse`/`-Force`
produce delete modes. Single/double quotes, doubled single quotes, ordinary backtick escapes, semicolons, newlines,
pipes and `&&`/`||` chains are scanned. Quoted command names require a literal `&` invocation. `$HOME`/`${HOME}`
come from context; all other variables and expressions remain opaque. Literal `pwsh|powershell -Command|-c` is
unwrapped within the depth cap. Native redirects `>`, `>>`, numbered output streams, `*>`, `*>>` and stream
duplication share fs emission with output cmdlets and their explicit path parameters. HTTP cmdlets inspect literal
URI, method and InFile/OutFile effects. `Start-Process -Verb RunAs` exposes an elevation marker and an opaque
payload. `Invoke-Expression`/`iex`, scripts, encoded commands, dynamic `& $var`, scriptblocks/arrays/grouping,
parameter expressions, filters and WhatIf ask. PowerShell input redirection is unsupported. Literal comma-separated
path arrays are outside this version's subset and ask; no real wildcard expansion occurs.
An unquoted `@` inside a token is literal data, including URL userinfo: an allowed actual host with userinfo asks,
and a disallowed actual host still denies. Token-boundary `@` splatting, arrays and expression forms remain opaque.

cmd supports double-quoted words, caret escapes, newline/`&`/`&&`/`||`/pipe chains, case-insensitive
`del|erase /s /q /f`, `rd|rmdir /s /q`, literal `type`/`dir`, `echo`, `rem`, `ver` and git argv. Switches are separate
words, may follow operands, and retain explicit mode semantics (`/s` recursive; `/f` force on `del`/`erase`). `/q`
only suppresses prompts and is neither recursive nor force; quiet-only in-root deletions remain plain. Literal
`cmd [/d] [/s] /c` unwraps within the shared cap; complex nested quote
reconstruction asks. Redirects `<`, `>`, `>>`, numbered streams and `2>&1` use common fs effects; `NUL`/`NUL:`
are documented null targets. `%VAR%` and delayed `!VAR!` expansions are never read from the environment; command
position and operand expansion ask. Batch/control commands, batch files, groups, context changes and unknown
switches ask. These dialects analyze literal effect data only; no fixture action is executed.

## Free-text subset and classifier boundary

`keyword` is the deterministic default. `mock` is an independent fixed demo lookup with manual fallback, excluded
from accuracy claims. Neither reads gold. Injection-like directives are screened before all providers. The maximum
line length is 300 characters. Classifiers supply only one of five template labels or `manual`; code extracts all
values. Raw labels remain available separately from manual routing for label-accuracy evaluation.

Anchored literal phrases include `never run <command>`, `never push to the <branch> branch`,
`never delete the <branch> branch`, `never write|delete|write or delete <path>`, `never touch <secret glob>`,
`never call <host>`, `only call <host>`, `never message recipients at <domain>` and
`never pay more than <amount> <explicit currency>`. Host lists may be comma-separated, with exact hosts or
`*.suffix` meaning subdomains only. `polarity` is code-extracted as `block-list` or `allow-list`; missing polarity
stays manual. A push phrase restricts git push destinations, including remote deletion, but permits local branch
deletion. Path phrases scope their operations explicitly and cover the literal target plus descendants. Payment
phrases restrict amounts only in the explicitly named currency; no unstated currency policy is added. Decimals are
converted to safe integer cents by code. Literal command restrictions use token-prefix matching, not exact argv.
Secret targets and optional `except` tokens share the same bounded literal grammar; `$`/`%` variable references
and backtick substitution syntax in either token require manual review rather than becoming literal exemptions.

Qualifiers, mixed clauses, ambiguous currencies/amounts, narrow secret-operation phrases and message allow-lists
requiring an additional unverifiable-recipient rule stay manual. The single-rule free-text compiler never returns
one sibling while silently dropping another. Remote thresholds are committed as null with `uncalibrated`
provenance. Remote candidates remain manual until a separate dev-only calibration records a dataset digest and
threshold; null/missing/invalid confidence also stays manual. No cutoff has been measured in this construction.

Local eval provider adapters have no default network transport. `deps.call(request, metadata)` is a single injected
call boundary for M8's explicit live gate, shell-env key resolution, timeout, cache, pre-call cost reservation and
logging. Jev uses pinned `jev-1.13.0`, Choice over six permutable criteria and state `{line}` only. LLM classification
uses strict label/confidence JSON. B3 is a separate evaluation-only verdict comparator. Exact option order is
included in cache metadata; B3 run/row/repeat identity prevents three independent trials sharing one cache draw.
Missing token counts stay null and raw usage is retained. Model availability, usage/cost and all provider calls
remain unverified; model identifiers live in `eval/config/models.json`.

## Paths, destinations and other action kinds

Paths resolve against `context.cwd`, collapse `.` and `..`, and test root containment at segment boundaries. The
root itself counts as inside. Windows paths normalize both separators and the drive letter; filesystem case folding
comes from context. UNC, device, alternate-stream/colon and drive-relative forms ask. Home expansion uses context
only. There is no symlink resolution, existence check, glob expansion or filesystem access.

URLs use the WHATWG `URL` class. HTTP(S) hosts fold case and lose one trailing dot; ports, paths, query strings and
fragments do not affect the host decision. Clients may supply scheme-less hosts (default HTTP). Exact host entries
match only themselves. `*.cdn.example.test` includes subdomains at any depth and excludes the apex. Userinfo asks,
while a disallowed parsed host still denies; unsupported schemes and unparsable URLs ask. Messages split recipients
at commas and check each domain; no domain or ambiguous forms ask when Q07 restricts recipients. Webhooks use a URL.

SQL respects quoted strings/identifiers and dollar quotes, replaces line/nested block comments with whitespace and
splits at top-level semicolons. Unbalanced syntax and EXEC/EXECUTE/DO/PREPARE ask. WITH locates the main top-level
statement; data-changing CTE bodies, procedural SQL and dialect-specific syntax are outside the analyzed subset.
Completed statements remain visible if a later statement has malformed syntax or reaches the analysis budget. The
unfinished suffix contributes an opaque finding; a deny from an earlier completed statement still wins.
Q11 covers DROP/TRUNCATE and DELETE/UPDATE without a top-level WHERE. Only exact `1=1` and `true`, after whitespace
removal and folding, are recognized WHERE tautologies. Other logical equivalents are not proven. This is not a SQL
parser or semantic safety proof.

Git parses global options, push flags, `+refspec`, `src:dst`, `:branch`, `--delete`, `--mirror` and local `branch -d/-D`.
`refs/heads/` is stripped; protection follows the destination. Bare push, HEAD without a destination and wildcard/all
destinations ask when branch protection is enabled. Unknown subcommands and unsupported push flags ask. No aliases,
hooks, remote configuration or checked-out branch are read. Release rules cover the questionnaire's named commands
only: `npm publish` (except `--dry-run`), `vercel --prod`, `terraform apply` and `gh release create`.
Q08 matches the `push` subcommand with force, including remote deletion by `--delete` or `:branch`. Local `branch -D`
continues to follow Q09 branch protection rather than Q08 force-push restrictions.

Payments compare integer cents against the answer's limit; a different currency asks. At the largest representable
limit, a template cannot declare two valid over-limit examples; the generator must report the resulting witness Gap
instead of inventing unsafe integer amounts.

## Free-text destructive command and path parameters

An accepted `path` parameter denotes a literal path and its descendants. It is canonicalized using the evaluation
context (`cwd`, home, path flavor and case folding), including `.`/`..`, `~`, `$HOME`, `${HOME}` and Windows
`%USERPROFILE%`. The generated globs use the absolute canonical key and escape any literal glob characters from the
context. Unsupported variables, substitutions, other-user homes, glob patterns, brace forms, UNC/device and
drive-relative paths stay manual. Reads and lists remain permitted by this particular restriction.

An accepted `command` parameter is a POSIX literal token prefix with a bare executable name. Tokens use ASCII
letters/digits or `_ - . / : @ +`, with spaces between tokens. It compiles through the same normalizer as the guard:
non-flag operands form `command.words`, while supported required flags form `command.flags` predicates. The flag
subset is `rm` recursive/force (`-r`, `-R`, `-f`, clusters, `--recursive`, `--force` and uniquely resolved aliases).
Required flags are presence checks, so reordering or adding arguments/flags does not remove the match. Operand
tokens stay literal; use a `path` restriction for canonical filesystem-target matching. Value-taking options,
unsupported flags, `--`, quoting/escapes, variables, redirections, wrappers and compound expressions in the parameter
stay manual. Evaluated actions still receive the normalizer's documented wrapper/chain handling.

## Bounds and limitations

Shell-wrapper depth is at most 3, scan/substitution nesting at most 16, and simple-command nodes at most 128 per action.
Scanning and glob matching share 20,000 steps; budget exhaustion asks. These limits bound analysis, not actual tools.
The evaluator is not a security boundary and replay does not prove an agent honors it. Unsupported effects of ordinary
executables remain outside its model. See `DEFERRED-VALIDATION.md` for the commands needed to validate this source.

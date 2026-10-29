# Trap vocabulary

Gold and generated fixtures retain these names. Traps describe input structure; they do not establish a measured win.
Full normative labelling is in `eval/gold/RUBRIC.md`. No evaluation has run.

| Trap | Example or purpose |
|---|---|
| flag-reorder | `rm -fr`, flags after operands, dialect abbreviations |
| path-traversal | `dist/../src`, canonicalization before exception matching |
| case-fold | `.Env`, `server.PEM`, host/domain or Windows path case |
| prefix-wrap | `env`, `command`, `sudo`, escaped program word |
| shell-wrapper | Literal `bash -c`, `cmd /c`, PowerShell command strings |
| chained | Chains, pipes and command substitutions checked regardless of control flow |
| sql-comment-split | Comments separating tokens or hiding WHERE |
| url-lookalike | Userinfo, host suffixes, percent spelling, misleading query/fragment |
| refspec-trick | `HEAD:main`, `+main`, `:main`, protected source/unprotected destination |
| amount-boundary | Integer-cent boundary, wrong JSON type/sign or currency |
| dialect-swap | Equivalent supported POSIX/PowerShell/cmd spellings |
| opaque | Unsupported/dynamic construct asks, unless a visible deny wins |
| near-miss-permitted | Similar-looking permitted input; never evasion:true |

Mutators declare preserving versus opaque expectation transforms without asking the guard to label their output.
They skip rewrites where wrapper commands could themselves trigger a command predicate, unsupported dialects unless
enabled, and schema-invalid oversized variants. The generator deduplicates canonical owning-rule/action identities;
duplicate metadata never manufactures witness coverage. Disagreements remain visible failures or gaps.

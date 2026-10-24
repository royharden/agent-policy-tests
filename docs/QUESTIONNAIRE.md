# Twelve questions

Question ids and answer schemas live in `src/policyfix/questionnaire.ts`; the UI sample loader and eval both use
`eval/gold/reference-answers.json`. This table describes source behavior, not a successful browser check.

| Id | Restriction or parameter |
|---|---|
| Q01 | Synthetic project root, cwd, home, path flavor, filesystem case and grammar version |
| Q02 | Deletes/writes outside the root |
| Q03 | Recursive/force deletes inside the root, with root-level directory exceptions |
| Q04 | Privilege elevation |
| Q05 | Secret filename/path globs and permitted exceptions |
| Q06 | Enabled HTTP host allow-list; exact host or explicit `*.subdomain` |
| Q07 | Enabled recipient-domain allow-list |
| Q08 | Force push on any branch |
| Q09 | Protected branch updates/deletions |
| Q10 | Named publish/deploy commands: deny, ask or none |
| Q11 | Destructive/unbounded SQL |
| Q12 | Nonnegative safe-integer cents limit and uppercase currency; empty limit means unrestricted |

Every answer gets one disposition. Restricted answers own rules; explicitly disabled/empty deny-lists are
not-restricted and get permitted witnesses. Q06/Q07 enabled with empty lists deny every destination. Q01 is a
parameter linked to context-consuming rules. Unsupported free-text intent becomes an explained manual item and Gap.

Free-text classifiers select labels; extraction/user parameter review supplies scope. The UI shows each compiled
rule beside its answer and intent, then fixtures, fake effects, report and content-bound approvals. Editing source
inputs stales the report; recompile/regenerate/replay before export. Acknowledging manual text never makes it enforced.

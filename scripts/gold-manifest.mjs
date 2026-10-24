// Regenerates eval/gold/MANIFEST.json after an authorised gold edit. Usage: node scripts/gold-manifest.mjs eval/gold
// Writes eval/gold/MANIFEST.json: sha256 over the exact bytes of every other file in the directory, plus counts computed
// with the same definitions as tests/gold-integrity.test.ts (actionSummary / classifierSummary). Run LAST.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const DIR = process.argv[2];
const TRAPS = ['flag-reorder', 'path-traversal', 'case-fold', 'prefix-wrap', 'shell-wrapper', 'chained', 'sql-comment-split',
  'url-lookalike', 'refspec-trick', 'amount-boundary', 'dialect-swap', 'opaque', 'near-miss-permitted'];
const EXPECTED = ['deny', 'ask', 'allow', 'invalid'];
const LABELS = ['destructive-shell-fs', 'secrets-paths', 'network-egress', 'git-release', 'data-money', 'manual'];
const jsonl = (f) => readFileSync(join(DIR, f), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l));

function actionSummary(rows) {
  const by_expected = Object.fromEntries(EXPECTED.map((e) => [e, rows.filter((r) => r.expected === e).length]));
  const traps = Object.fromEntries(TRAPS.map((t) => [t, rows.filter((r) => r.traps.includes(t)).length]));
  const prohibited = rows.filter((r) => r.expected !== 'allow').length;
  return { rows: rows.length, prohibited, permitted: rows.length - prohibited, evasion: rows.filter((r) => r.evasion).length,
    opaque: rows.filter((r) => r.traps.includes('opaque')).length, by_expected, traps };
}
function classifierSummary(rows) {
  return { rows: rows.length, manual: rows.filter((r) => r.label === 'manual').length,
    injection: rows.filter((r) => r.injection).length,
    by_label: Object.fromEntries(LABELS.map((l) => [l, rows.filter((r) => r.label === l).length])) };
}

const names = readdirSync(DIR).filter((n) => n !== 'MANIFEST.json').sort();
const files = {};
let earliest = Infinity;
for (const n of names) {
  const b = readFileSync(join(DIR, n));
  files[n] = { sha256: createHash('sha256').update(b).digest('hex'), bytes: b.length };
  earliest = Math.min(earliest, statSync(join(DIR, n)).birthtimeMs);
}

const manifest = {
  author: 'S21-INT coder-high subagent (builder-authored, not independent)',
  authored_at: new Date(earliest).toISOString(),
  frozen_at: new Date().toISOString(),
  seed: 20261024,
  seed_use: 'Fixed seed for eval/run.ts ordering and for drawing the 20-row held-out review sample; the rows themselves were hand-written, not generated from it.',
  hash: 'sha256 over the exact file bytes (UTF-8, LF line endings; eval/gold/.gitattributes disables git EOL conversion). MANIFEST.json is not listed.',
  disclosure: 'Gold rows, labels and RUBRIC.md were written by the builder before any normaliser/matcher code existed; they are not independent. Roy reviews a 20-row held-out sample before the single published held-out run (PLAN D-5).',
  rubric: 'RUBRIC.md',
  reference_answers: 'reference-answers.json (CONTRACTS C3 values, no deliberate change)',
  not_in_this_manifest: 'B4 regex rules and classifier thresholds do not exist yet; their hashes are recorded in results.jsonl run metadata (PLAN M2 AC6 / M8 AC3).',
  files,
  counts: {
    actions: { dev: actionSummary(jsonl('actions.dev.jsonl')), heldout: actionSummary(jsonl('actions.heldout.jsonl')) },
    classifier: { dev: classifierSummary(jsonl('classifier.dev.jsonl')), heldout: classifierSummary(jsonl('classifier.heldout.jsonl')) },
  },
};
writeFileSync(join(DIR, 'MANIFEST.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest, null, 2));

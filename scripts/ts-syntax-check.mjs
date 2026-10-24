// Static syntax check for erasable TypeScript: strips types (node:module) then parses with `node --check`. Runs no project code.
import { stripTypeScriptTypes } from 'node:module';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
const dir = mkdtempSync(join(tmpdir(), 'tscheck-'));
let bad = 0;
for (const f of process.argv.slice(2)) {
  try {
    const js = stripTypeScriptTypes(readFileSync(f, 'utf8'), { mode: 'strip' });
    const out = join(dir, 'x.mjs'); writeFileSync(out, js);
    const r = spawnSync(process.execPath, ['--check', out], { encoding: 'utf8' });
    if (r.status !== 0) { bad++; console.log('FAIL', f, r.stderr.split('\n').slice(0, 6).join('\n')); }
    else console.log('ok  ', f);
  } catch (e) { bad++; console.log('FAIL', f, String(e.message).split('\n')[0]); }
}
process.exit(bad ? 1 : 0);

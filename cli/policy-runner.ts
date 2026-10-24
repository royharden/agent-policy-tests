import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseFixtures, parsePolicy } from '../src/policyfix/action';
import { MAX_FILE_BYTES } from '../src/policyfix/limits';
import { evaluatePolicy, type ScoreReport } from '../src/policyfix/score';

export interface RunnerIO { readonly readText: (path: string, maxBytes: number) => Promise<string>; readonly write: (text: string) => void }
export function reportExitCode(report: Pick<ScoreReport, 'status'>, strict: boolean): 0 | 1 | 2 {
  return report.status === 'Fail' ? 1 : strict && report.status === 'Gap' ? 2 : 0;
}

/** Never reads report.json or runs any fixture action. Invalid input and Fail precede strict Gap. */
export async function main(argv: readonly string[], io: RunnerIO): Promise<0 | 1 | 2> {
  let directory = '.'; let strict = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--strict') strict = true;
    else if (arg === '--dir' && argv[i + 1] !== undefined) { directory = argv[i + 1] ?? '.'; i += 1; }
    else { io.write(JSON.stringify({ ok: false, errors: [{ code: 'invalid_value', pointer: '/argv', message: `Unknown/incomplete argument ${arg ?? ''}. Use [--dir directory] [--strict].` }] })); return 1; }
  }
  try {
    const policy = parsePolicy(await io.readText(resolve(directory, 'policy.json'), MAX_FILE_BYTES));
    if (!policy.ok) { io.write(JSON.stringify(policy)); return 1; }
    const fixtures = parseFixtures(await io.readText(resolve(directory, 'fixtures.json'), MAX_FILE_BYTES), policy.value);
    if (!fixtures.ok) { io.write(JSON.stringify(fixtures)); return 1; }
    const report = evaluatePolicy(policy.value, fixtures.value.fixtures);
    io.write(JSON.stringify(report));
    return report.ok ? reportExitCode(report.value, strict) : 1;
  } catch (error: unknown) {
    io.write(JSON.stringify({ ok: false, errors: [{ code: 'invalid_value', pointer: '/files', message: error instanceof Error ? error.message : 'Cannot read bundle inputs.' }] }));
    return 1;
  }
}

const nodeIO: RunnerIO = {
  readText: async (path, maxBytes) => {
    const info = await stat(path);
    if (!info.isFile() || info.size > maxBytes) throw new Error('Input is not a bounded regular file.');
    const bytes = await readFile(path);
    if (bytes.length > maxBytes) throw new Error('Input exceeds the file byte cap.');
    return bytes.toString('utf8');
  },
  write: (text) => { process.stdout.write(`${text}\n`); },
};
if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  void main(process.argv.slice(2), nodeIO).then((code) => { process.exitCode = code; });
}

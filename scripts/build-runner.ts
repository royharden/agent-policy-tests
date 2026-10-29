// Build source only during Dirty Mode. npm run build invokes this before Vite copies public assets.
import { build } from 'esbuild';
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
await mkdir(new URL('../public/', import.meta.url), { recursive: true });
await build({ absWorkingDir: root, entryPoints: ['cli/policy-runner.ts'], outfile: 'public/policy-runner.mjs', bundle: true, platform: 'node', target: 'node20', format: 'esm', packages: 'bundle', sourcemap: false, legalComments: 'eof' });

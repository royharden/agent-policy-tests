// @ts-check
// ESLint flat config. Static bans are AST rules, not text greps (PLAN A23):
//   - no-eval / no-new-func / no-implied-eval everywhere;
//   - no child_process anywhere under src/ (static import, require(), dynamic import(), computed dynamic import);
//   - no regex literals or RegExp in src/policyfix/match.ts and src/policyfix/glob.ts;
//   - import boundary for src/policyfix/: no React, DOM, node: builtins, Deno/URL imports or app layers;
//   - erasable TypeScript only (CONTRACTS C6): no enum, namespace, parameter properties, `import =`, `export =`.
// Flat config replaces (does not merge) a rule's options when a later block sets the same rule, so each scoped block
// below re-lists every selector/path that must stay active for its files.
import { fileURLToPath } from 'node:url';
import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

const rootDir = fileURLToPath(new URL('.', import.meta.url));

const CHILD_PROCESS_MESSAGE = 'child_process is banned in src/: the app and the policy core never execute commands.';

const erasableOnlySyntax = [
  { selector: 'TSEnumDeclaration', message: 'Erasable TypeScript only (CONTRACTS C6): use a const array and a union type.' },
  { selector: 'TSModuleDeclaration[kind="namespace"]', message: 'Erasable TypeScript only (CONTRACTS C6): no namespaces.' },
  { selector: 'TSParameterProperty', message: 'Erasable TypeScript only (CONTRACTS C6): declare fields explicitly.' },
  { selector: 'TSImportEqualsDeclaration', message: 'Erasable TypeScript only (CONTRACTS C6): use ESM imports.' },
  { selector: 'TSExportAssignment', message: 'Erasable TypeScript only (CONTRACTS C6): use ESM exports.' },
];

const noChildProcessSyntax = [
  {
    selector: "CallExpression[callee.name='require'][arguments.0.value=/^(node:)?child_process$/]",
    message: CHILD_PROCESS_MESSAGE,
  },
  { selector: 'ImportExpression[source.value=/^(node:)?child_process$/]', message: CHILD_PROCESS_MESSAGE },
  {
    selector: "ImportExpression[source.type!='Literal']",
    message: 'Dynamic import() with a computed specifier is banned in src/ (it could load child_process).',
  },
];

const noRegexSyntax = [
  { selector: 'Literal[regex]', message: 'No regular expressions in the match language (PLAN A23).' },
  { selector: "NewExpression[callee.name='RegExp']", message: 'No RegExp in the match language (PLAN A23).' },
  { selector: "CallExpression[callee.name='RegExp']", message: 'No RegExp in the match language (PLAN A23).' },
  { selector: "MemberExpression[object.name='RegExp']", message: 'No RegExp in the match language (PLAN A23).' },
];

const childProcessImportPaths = [
  { name: 'child_process', message: CHILD_PROCESS_MESSAGE },
  { name: 'node:child_process', message: CHILD_PROCESS_MESSAGE },
];

const coreBoundaryPatterns = [
  {
    group: ['react', 'react/*', 'react-dom', 'react-dom/*'],
    message: 'src/policyfix is framework-free: no React (PLAN A23).',
  },
  {
    group: ['node:*'],
    message: 'src/policyfix runs in the browser, the runner and tests alike: no node: builtins (PLAN A23).',
  },
  {
    group: ['fs', 'fs/*', 'path', 'os', 'crypto', 'http', 'https', 'net', 'tls', 'dns', 'vm', 'worker_threads', 'process'],
    message: 'src/policyfix may not use Node builtins (PLAN A23).',
  },
  {
    group: ['jsr:*', 'npm:*', 'http://*', 'https://*'],
    message: 'src/policyfix may not use Deno or URL imports (PLAN A23).',
  },
  { group: ['@supabase/*'], message: 'src/policyfix has no backend client (PLAN A2).' },
  {
    group: ['**/ui', '**/ui/*', '**/lib', '**/lib/*', '**/providers', '**/providers/*'],
    message: 'src/policyfix may not import app layers (ui, lib, providers).',
  },
];

const coreBannedGlobals = [
  'window',
  'document',
  'navigator',
  'localStorage',
  'sessionStorage',
  'indexedDB',
  'fetch',
  'XMLHttpRequest',
  'WebSocket',
  'Deno',
  'process',
  'require',
  'Buffer',
  '__dirname',
  '__filename',
].map((name) => ({ name, message: `src/policyfix is environment-free: "${name}" is not available (PLAN A23).` }));

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'coverage/**',
      'public/policy-runner.mjs',
      'results/live/**',
      // Deno edge functions are checked with `deno lint` / `deno check` (docs/DEFERRED-VALIDATION.md D-16).
      'supabase/functions/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.json', './tsconfig.node.json'],
        tsconfigRootDir: rootDir,
      },
    },
  },
  {
    files: ['**/*.js', '**/*.mjs', '**/*.cjs'],
    ...tseslint.configs.disableTypeChecked,
  },
  {
    files: ['**/*.js', '**/*.mjs', '**/*.cjs'],
    languageOptions: { globals: globals.node },
  },
  {
    files: ['**/*.ts', '**/*.tsx'],
    rules: {
      'no-eval': 'error',
      'no-new-func': 'error',
      'no-implied-eval': 'off',
      '@typescript-eslint/no-implied-eval': 'error',
      '@typescript-eslint/explicit-module-boundary-types': 'error',
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-restricted-syntax': ['error', ...erasableOnlySyntax],
    },
  },
  {
    files: ['src/**/*.ts', 'src/**/*.tsx'],
    languageOptions: { globals: globals.browser },
    rules: {
      'no-restricted-imports': ['error', { paths: childProcessImportPaths }],
      'no-restricted-syntax': ['error', ...erasableOnlySyntax, ...noChildProcessSyntax],
    },
  },
  {
    files: ['src/policyfix/**/*.ts', 'src/policyfix/**/*.tsx'],
    rules: {
      'no-restricted-imports': ['error', { paths: childProcessImportPaths, patterns: coreBoundaryPatterns }],
      'no-restricted-globals': ['error', ...coreBannedGlobals],
      'no-restricted-syntax': ['error', ...erasableOnlySyntax, ...noChildProcessSyntax],
    },
  },
  {
    files: ['src/policyfix/match.ts', 'src/policyfix/glob.ts'],
    rules: {
      'no-restricted-syntax': ['error', ...erasableOnlySyntax, ...noChildProcessSyntax, ...noRegexSyntax],
    },
  },
  {
    files: ['tests/**/*.ts', 'eval/**/*.ts', 'cli/**/*.ts', 'scripts/**/*.ts', '*.config.ts'],
    languageOptions: { globals: globals.node },
  },
);

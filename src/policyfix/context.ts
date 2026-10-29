// Evaluation context (PLAN A5, CONTRACTS C2). Synthetic, part of policy.json, hashed into context_sha.
// Normalisation is purely lexical against this object: it never reads the real filesystem, environment or DNS.
import { z } from 'zod';
import { fail, fromZodIssues, ok, type Result, truncateErrors } from './errors';
import { MAX_COMMAND_CHARS, MAX_REPORTED_ERRORS, MAX_VERSION_CHARS } from './limits';

export const PATH_FLAVORS = ['posix', 'windows'] as const;
export type PathFlavor = (typeof PATH_FLAVORS)[number];

function isAsciiLetter(ch: string): boolean {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

/**
 * Lexical absolute-path test for the context's own paths.
 * posix: starts with '/'. windows: drive letter + ':' + separator (`C:\` or `C:/`); UNC, `\\?\` and
 * drive-relative (`C:foo`) roots are rejected because the normaliser treats them as `ask`.
 */
export function isAbsoluteContextPath(flavor: PathFlavor, path: string): boolean {
  if (path.includes('\u0000')) return false;
  if (flavor === 'posix') return path.startsWith('/');
  const sep = path.charAt(2);
  return path.length >= 3 && isAsciiLetter(path.charAt(0)) && path.charAt(1) === ':' && (sep === '\\' || sep === '/');
}

const contextPath = z.string().min(1).max(MAX_COMMAND_CHARS);

const CONTEXT_PATH_FIELDS = ['project_root', 'cwd', 'home'] as const;

export const EvaluationContextSchema = z
  .object({
    project_root: contextPath,
    cwd: contextPath,
    home: contextPath,
    path_flavor: z.enum(PATH_FLAVORS),
    case_insensitive_fs: z.boolean(),
    grammar_version: z.string().min(1).max(MAX_VERSION_CHARS),
  })
  .strict()
  .superRefine((context, ctx) => {
    for (const field of CONTEXT_PATH_FIELDS) {
      if (!isAbsoluteContextPath(context.path_flavor, context[field])) {
        ctx.addIssue({
          code: 'custom',
          path: [field],
          message: `${field} must be an absolute ${context.path_flavor} path (no UNC, \\\\?\\ or drive-relative form).`,
          params: { code: 'invalid_value' },
        });
      }
    }
  });

export type EvaluationContext = z.infer<typeof EvaluationContextSchema>;

/** Validates an in-memory context value; never throws. */
export function validateContext(value: unknown): Result<EvaluationContext> {
  const parsed = EvaluationContextSchema.safeParse(value);
  if (parsed.success) return ok(parsed.data);
  return fail(truncateErrors(fromZodIssues(parsed.error.issues), MAX_REPORTED_ERRORS));
}

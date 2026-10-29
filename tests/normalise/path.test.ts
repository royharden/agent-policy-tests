import { describe, expect, it } from 'vitest';
import { canonicalisePath } from '../../src/policyfix/normalise/path';
import { reference } from '../helpers/reference';

describe('lexical path context', () => {
  it('collapses traversal before testing root segment boundaries', () => {
    // what_bug_this_catches: textual root prefixes and pre-canonicalisation exceptions admit sibling or escaped paths.
    const context = reference('posix').context;
    expect(canonicalisePath('dist/../src/file', context, { expandHome: true })).toMatchObject({ ok: true, path: { root_relative: 'src/file', inside_root: true } });
    expect(canonicalisePath('../demo-evil/file', context, { expandHome: true })).toMatchObject({ ok: true, path: { inside_root: false, root_relative: null } });
    expect(canonicalisePath('.', context, { expandHome: true })).toMatchObject({ ok: true, path: { inside_root: true, root_relative: '' } });
  });

  it('uses only the supplied home and rejects unresolved variables', () => {
    // what_bug_this_catches: normalization accidentally using the host home or silently assuming an unknown build directory.
    const context = reference('posix').context;
    for (const path of ['~/.cache', '$HOME/.cache', '${HOME}/.cache']) {
      expect(canonicalisePath(path, context, { expandHome: true })).toMatchObject({ ok: true, path: { key: '/home/dev/.cache', inside_root: false } });
    }
    for (const path of ['$BUILD_DIR/out', '~other/.cache']) expect(canonicalisePath(path, context, { expandHome: true }).ok).toBe(false);
  });

  it('folds Windows paths and refuses UNC, device and drive-relative forms', () => {
    // what_bug_this_catches: Windows aliases escaping root checks or opaque operands being judged only by their basename.
    const context = reference('windows').context;
    expect(canonicalisePath('c:/WORKSPACE/Demo/src', context, { expandHome: true })).toMatchObject({ ok: true, path: { inside_root: true } });
    for (const path of ['C:notes.txt', '\\\\server\\share\\file', '\\\\?\\C:\\workspace\\demo\\file']) {
      expect(canonicalisePath(path, context, { expandHome: true }).ok).toBe(false);
    }
  });
});

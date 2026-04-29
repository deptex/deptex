import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  parseUdiff,
  applyDiff,
  applyDiffText,
  DiffApplyError,
} from '../edit-tool';

// Smoke for the udiff parser/applier. This is the single piece of code in
// the fix-worker most likely to silently corrupt files — every other failure
// mode (network, LLM, tests) is loud, but a wrong patch applied cleanly is
// silent. Cover the failure shapes we'd actually see from a real LLM:
// code-fence wrappers, whitespace drift in context lines, multi-file diffs,
// new-file and delete-file edges, and the "no newline at end of file"
// trailer.

describe('edit-tool', () => {
  let workDir: string;

  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edit-tool-test-'));
  });

  afterEach(() => {
    fs.rmSync(workDir, { recursive: true, force: true });
  });

  describe('parseUdiff', () => {
    test('parses a single-file modify diff', () => {
      const diff = `--- a/foo.ts
+++ b/foo.ts
@@ ... @@
 const x = 1;
-const y = 2;
+const y = 3;
 const z = 4;
`;
      const result = parseUdiff(diff);
      expect(result).toHaveLength(1);
      expect(result[0].oldPath).toBe('foo.ts');
      expect(result[0].newPath).toBe('foo.ts');
      expect(result[0].hunks).toHaveLength(1);
    });

    test('strips ```diff fence wrappers from LLM output', () => {
      const diff = '```diff\n--- a/foo.ts\n+++ b/foo.ts\n@@ ... @@\n-old\n+new\n```';
      const result = parseUdiff(diff);
      expect(result).toHaveLength(1);
    });

    test('parses /dev/null for new files', () => {
      const diff = `--- /dev/null
+++ b/new.ts
@@ ... @@
+export const greeting = 'hello';
`;
      const result = parseUdiff(diff);
      expect(result[0].oldPath).toBe(null);
      expect(result[0].newPath).toBe('new.ts');
    });

    test('parses /dev/null for deleted files', () => {
      const diff = `--- a/old.ts
+++ /dev/null
@@ ... @@
-export const obsolete = true;
`;
      const result = parseUdiff(diff);
      expect(result[0].oldPath).toBe('old.ts');
      expect(result[0].newPath).toBe(null);
    });

    test('parses multiple files in one diff', () => {
      const diff = `--- a/a.ts
+++ b/a.ts
@@ ... @@
-old
+new
--- a/b.ts
+++ b/b.ts
@@ ... @@
-foo
+bar
`;
      const result = parseUdiff(diff);
      expect(result).toHaveLength(2);
      expect(result[0].oldPath).toBe('a.ts');
      expect(result[1].oldPath).toBe('b.ts');
    });

    test('throws on --- without matching +++', () => {
      const diff = `--- a/foo.ts
this is not a +++ line
@@ ... @@
-old
+new
`;
      expect(() => parseUdiff(diff)).toThrow(/Missing \+\+\+/);
    });
  });

  describe('applyDiff — modify', () => {
    test('replaces a line in the middle of a file', () => {
      fs.writeFileSync(path.join(workDir, 'foo.ts'), 'const x = 1;\nconst y = 2;\nconst z = 4;\n');
      const diff = parseUdiff(`--- a/foo.ts
+++ b/foo.ts
@@ ... @@
 const x = 1;
-const y = 2;
+const y = 3;
 const z = 4;
`)[0];

      applyDiff(workDir, diff);
      expect(fs.readFileSync(path.join(workDir, 'foo.ts'), 'utf-8')).toBe(
        'const x = 1;\nconst y = 3;\nconst z = 4;\n',
      );
    });

    test('whitespace-tolerant fallback matches when context has trailing-space drift', () => {
      // The LLM produced context "const y = 2;" but the file has "const y = 2;   "
      // (trailing whitespace). Should still apply.
      fs.writeFileSync(path.join(workDir, 'foo.ts'), 'const x = 1;   \nconst y = 2;   \nconst z = 4;\n');
      const diff = parseUdiff(`--- a/foo.ts
+++ b/foo.ts
@@ ... @@
 const x = 1;
-const y = 2;
+const y = 3;
 const z = 4;
`)[0];

      applyDiff(workDir, diff);
      // Whitespace-tolerant match preserves the LLM's normalized form for
      // the changed line and the surrounding context (offset replacement).
      expect(fs.readFileSync(path.join(workDir, 'foo.ts'), 'utf-8')).toBe(
        'const x = 1;\nconst y = 3;\nconst z = 4;\n',
      );
    });

    test('throws DiffApplyError when context truly does not match', () => {
      fs.writeFileSync(path.join(workDir, 'foo.ts'), 'const totally = "different";\n');
      const diff = parseUdiff(`--- a/foo.ts
+++ b/foo.ts
@@ ... @@
 const x = 1;
-const y = 2;
+const y = 3;
`)[0];

      expect(() => applyDiff(workDir, diff)).toThrow(DiffApplyError);
    });

    test('preserves files without trailing newline', () => {
      fs.writeFileSync(path.join(workDir, 'foo.ts'), 'const x = 1;\nconst y = 2;');
      const diff = parseUdiff(`--- a/foo.ts
+++ b/foo.ts
@@ ... @@
 const x = 1;
-const y = 2;
+const y = 3;
`)[0];

      applyDiff(workDir, diff);
      expect(fs.readFileSync(path.join(workDir, 'foo.ts'), 'utf-8')).toBe(
        'const x = 1;\nconst y = 3;',
      );
    });

    test('ignores "\\ No newline at end of file" markers', () => {
      fs.writeFileSync(path.join(workDir, 'foo.ts'), 'old');
      const diff = parseUdiff(`--- a/foo.ts
+++ b/foo.ts
@@ ... @@
-old
\\ No newline at end of file
+new
\\ No newline at end of file
`)[0];

      applyDiff(workDir, diff);
      expect(fs.readFileSync(path.join(workDir, 'foo.ts'), 'utf-8')).toBe('new');
    });
  });

  describe('applyDiff — create', () => {
    test('creates a new file from /dev/null diff', () => {
      const diff = parseUdiff(`--- /dev/null
+++ b/new.ts
@@ ... @@
+export const a = 1;
+export const b = 2;
`)[0];

      applyDiff(workDir, diff);
      expect(fs.readFileSync(path.join(workDir, 'new.ts'), 'utf-8')).toBe(
        'export const a = 1;\nexport const b = 2;\n',
      );
    });

    test('creates parent directories as needed', () => {
      const diff = parseUdiff(`--- /dev/null
+++ b/src/nested/dir/new.ts
@@ ... @@
+export const x = 1;
`)[0];

      applyDiff(workDir, diff);
      expect(fs.existsSync(path.join(workDir, 'src/nested/dir/new.ts'))).toBe(true);
    });
  });

  describe('applyDiff — delete', () => {
    test('removes a file when target is /dev/null', () => {
      fs.writeFileSync(path.join(workDir, 'old.ts'), 'export const obsolete = true;\n');
      const diff = parseUdiff(`--- a/old.ts
+++ /dev/null
@@ ... @@
-export const obsolete = true;
`)[0];

      applyDiff(workDir, diff);
      expect(fs.existsSync(path.join(workDir, 'old.ts'))).toBe(false);
    });
  });

  describe('applyDiffText', () => {
    test('applies a multi-file diff and reports filesChanged', () => {
      fs.writeFileSync(path.join(workDir, 'a.ts'), 'old-a\n');
      fs.writeFileSync(path.join(workDir, 'b.ts'), 'old-b\n');

      const result = applyDiffText(
        workDir,
        `--- a/a.ts
+++ b/a.ts
@@ ... @@
-old-a
+new-a
--- a/b.ts
+++ b/b.ts
@@ ... @@
-old-b
+new-b
`,
      );

      expect(result.filesChanged.sort()).toEqual(['a.ts', 'b.ts']);
      expect(fs.readFileSync(path.join(workDir, 'a.ts'), 'utf-8')).toBe('new-a\n');
      expect(fs.readFileSync(path.join(workDir, 'b.ts'), 'utf-8')).toBe('new-b\n');
    });
  });
});

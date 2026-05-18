/**
 * Validation Gate 3 (patch round-trip) excludes test / spec / fixture files
 * from the engine input. Several CVEs (axios test/specs, debug test/index.js,
 * Pillow Tests/test_pickle.py, urllib3 tests/, jinja2 tests/) ship the bug
 * reproduction in their fix commit alongside the source fix. Without this
 * filter the AI rule fires on the test reproduction and Gate 3 hard-fails
 * the spec on `post_matches > 0`.
 *
 * See `TEST_PATH_PATTERNS` in `rule-generator/validate.ts` for the source-
 * of-truth pattern list.
 */

import { filterApplicableChangedFiles, isTestPath } from '../rule-generator/validate';
import type { ChangedFileBlob } from '../rule-generator/patch-fetch';

function blob(path: string): ChangedFileBlob {
  return {
    path,
    status: 'modified',
    before: 'old',
    after: 'new',
    beforeTruncated: false,
    afterTruncated: false,
  };
}

describe('isTestPath', () => {
  test.each([
    // top-level test dirs
    'test/foo.js',
    'tests/bar.py',
    'Tests/test_pickle.py',
    '__tests__/baz.ts',
    '__tests__/sub/baz.ts',
    'spec/foo_spec.rb',
    'specs/run.ts',
    'src/foo/__tests__/bar.ts',
    'lib/sub/test/baz.js',
    // fixture / mock dirs
    'src/fixtures/payloads.json',
    'test/fixture/input.txt',
    'src/__mocks__/fs.ts',
    'src/__fixtures__/data.ts',
    // file-name conventions
    'pillow/Tests/test_pickle.py',
    'pillow/test_image.py',
    'foo_test.py',
    'pkg/bar_test.go',
    'lib/baz_test.rb',
    'src/foo.spec.ts',
    'src/foo.test.js',
    'src/foo.test.tsx',
    'java/src/MyFooTest.java',
    'csharp/proj/FooTests.cs',
  ])('matches test-like path %s', (p) => {
    expect(isTestPath(p)).toBe(true);
  });

  test.each([
    // Production source paths that contain partial test-substrings but are
    // not test files (must not be excluded).
    'src/index.js',
    'lib/foo.py',
    'latest/foo.js',           // contains "test" substring but not as dir segment
    'src/protest/foo.py',      // contains "test" substring inside a longer name
    'src/contestant.go',
    'lib/test.py',             // bare "test.py" file at module level — keep (not a test_)
    'src/testing-utils.ts',    // not a test dir, just dasherized name
    'src/foo.testing.ts',      // not .spec.ts / .test.ts
    'pkg/spectrum.go',         // contains "spec" substring
    'pkg/mockable.go',         // contains "mock" substring
    // Windows-style separators are normalized.
  ])('keeps non-test path %s', (p) => {
    expect(isTestPath(p)).toBe(false);
  });

  test('normalizes Windows-style separators', () => {
    expect(isTestPath('src\\__tests__\\foo.ts')).toBe(true);
    expect(isTestPath('Tests\\test_pickle.py')).toBe(true);
  });
});

describe('filterApplicableChangedFiles drops test files', () => {
  test('drops common test-shaped paths for js', () => {
    const files: ChangedFileBlob[] = [
      blob('lib/axios.js'),
      blob('test/specs/foo.spec.js'),
      blob('test/foo.js'),
      blob('__tests__/bar.ts'),
    ];
    const kept = filterApplicableChangedFiles(files, 'js');
    expect(kept.map((f) => f.path)).toEqual(['lib/axios.js']);
  });

  test('drops common test-shaped paths for python', () => {
    const files: ChangedFileBlob[] = [
      blob('src/PIL/Image.py'),
      blob('Tests/test_pickle.py'),
      blob('tests/test_image.py'),
      blob('src/PIL/_util.py'),
      blob('src/foo_test.py'),
    ];
    const kept = filterApplicableChangedFiles(files, 'python');
    expect(kept.map((f) => f.path).sort()).toEqual(['src/PIL/Image.py', 'src/PIL/_util.py']);
  });

  test('drops fixtures and mocks', () => {
    const files: ChangedFileBlob[] = [
      blob('src/foo.js'),
      blob('src/__mocks__/fs.js'),
      blob('src/fixtures/payload.js'),
    ];
    const kept = filterApplicableChangedFiles(files, 'js');
    expect(kept.map((f) => f.path)).toEqual(['src/foo.js']);
  });

  test('still drops non-applicable extensions and null blobs', () => {
    const files: ChangedFileBlob[] = [
      blob('src/foo.js'),
      blob('docs/readme.md'),
      { ...blob('src/added.js'), before: null },
      { ...blob('src/removed.js'), after: null },
    ];
    const kept = filterApplicableChangedFiles(files, 'js');
    expect(kept.map((f) => f.path)).toEqual(['src/foo.js']);
  });

  test('preserves productively-named files that share substrings with tests', () => {
    const files: ChangedFileBlob[] = [
      blob('src/protest.py'),
      blob('src/contestant.py'),
      blob('lib/spectrum.py'),
    ];
    const kept = filterApplicableChangedFiles(files, 'python');
    expect(kept.map((f) => f.path).sort()).toEqual([
      'lib/spectrum.py',
      'src/contestant.py',
      'src/protest.py',
    ]);
  });
});

/**
 * Unit tests for diff-targeted patch validation in rule-generator/validate.ts.
 *
 * The pure helper `filterApplicableChangedFiles` is tested directly. The
 * orchestration in `validateRule` is tested by mocking `child_process.spawn`
 * — semgrep is invoked once per fixture (vulnerable, safe) plus twice per
 * applicable changed file (before, after). We control match counts via the
 * mocked stdout payload to drive different verdicts.
 */

import { EventEmitter } from 'events';
import { Readable } from 'stream';

const mockSpawn = jest.fn();
jest.mock('child_process', () => ({
  spawn: (...args: unknown[]) => mockSpawn(...args),
}));

import { validateRule, filterApplicableChangedFiles, makeRuleGenWorkdir } from '../rule-generator/validate';
import type { GeneratedPayload } from '../rule-generator/generate';
import type { ChangedFileBlob } from '../rule-generator/patch-fetch';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Fake child process emitting canned semgrep JSON on stdout, then exit 0/1. */
function makeFakeChild(matchCount: number, exitCode = matchCount > 0 ? 1 : 0) {
  const body = JSON.stringify({
    results: Array.from({ length: matchCount }, () => ({ check_id: 'x' })),
    errors: [],
  });
  // Readable.from yields whatever the iterator gives it, but the consumer in
  // validate.ts pushes those chunks into `Buffer.concat(...)` — so they must
  // be Buffers, not strings.
  const stdout = Readable.from([Buffer.from(body)]);
  const stderr = Readable.from([Buffer.alloc(0)]);
  const child = new EventEmitter() as EventEmitter & {
    stdout: Readable;
    stderr: Readable;
    pid: number;
    kill: jest.Mock;
  };
  child.stdout = stdout;
  child.stderr = stderr;
  child.pid = 12345;
  child.kill = jest.fn();
  // Emit close async so all `data` listeners attach first.
  setImmediate(() => child.emit('close', exitCode));
  return child;
}

/**
 * Queue match counts in the order spawn() will be called:
 *   [vulnerableFixture, safeFixture, file0Before, file0After, file1Before, ...]
 */
function queueSemgrepResults(counts: number[]) {
  mockSpawn.mockReset();
  let idx = 0;
  mockSpawn.mockImplementation(() => {
    const next = counts[idx++] ?? 0;
    return makeFakeChild(next);
  });
}

const minimalRuleYaml = `rules:
  - id: deptex.test.rule
    languages: [javascript]
    severity: ERROR
    message: test
    pattern: foo($X)
`;

const minimalPayload: GeneratedPayload = {
  rule_yaml: minimalRuleYaml,
  vulnerable_fixture: 'foo(req.body.x)',
  safe_fixture: 'bar()',
  reachability_level: 'data_flow',
  entry_point_class: 'PUBLIC_UNAUTH',
  rationale: 'test',
};

function jsFile(p: string, before: string | null, after: string | null): ChangedFileBlob {
  return {
    path: p,
    status: 'modified',
    before,
    after,
    beforeTruncated: false,
    afterTruncated: false,
  };
}

// ---------------------------------------------------------------------------
// filterApplicableChangedFiles — pure helper
// ---------------------------------------------------------------------------

describe('filterApplicableChangedFiles', () => {
  it('keeps files whose extension matches the rule language', () => {
    const files = [
      jsFile('src/index.js', 'a', 'b'),
      jsFile('src/index.ts', 'a', 'b'),
      jsFile('README.md', 'a', 'b'),
    ];
    expect(filterApplicableChangedFiles(files, 'javascript').map((f) => f.path)).toEqual(['src/index.js']);
    expect(filterApplicableChangedFiles(files, 'typescript').map((f) => f.path)).toEqual(['src/index.ts']);
  });

  it('drops added files (before === null) — no pre-patch text to test', () => {
    const files = [jsFile('src/new.js', null, 'created'), jsFile('src/old.js', 'a', 'b')];
    expect(filterApplicableChangedFiles(files, 'javascript').map((f) => f.path)).toEqual(['src/old.js']);
  });

  it('drops deleted files (after === null) — no post-patch text to test', () => {
    const files = [jsFile('src/gone.js', 'a', null), jsFile('src/kept.js', 'a', 'b')];
    expect(filterApplicableChangedFiles(files, 'javascript').map((f) => f.path)).toEqual(['src/kept.js']);
  });

  it('returns empty for unsupported language', () => {
    const files = [jsFile('src/index.js', 'a', 'b')];
    expect(filterApplicableChangedFiles(files, 'cobol')).toEqual([]);
  });

  it('accepts jsx/mjs/cjs as javascript and tsx as typescript', () => {
    const files = [
      jsFile('src/a.jsx', 'a', 'b'),
      jsFile('src/b.mjs', 'a', 'b'),
      jsFile('src/c.cjs', 'a', 'b'),
      jsFile('src/d.tsx', 'a', 'b'),
    ];
    expect(filterApplicableChangedFiles(files, 'javascript').map((f) => f.path).sort()).toEqual([
      'src/a.jsx', 'src/b.mjs', 'src/c.cjs',
    ]);
    expect(filterApplicableChangedFiles(files, 'typescript').map((f) => f.path)).toEqual(['src/d.tsx']);
  });
});

// ---------------------------------------------------------------------------
// validateRule — diff-targeted orchestration
// ---------------------------------------------------------------------------

describe('validateRule (diff-targeted patch round-trip)', () => {
  const workDir = makeRuleGenWorkdir();

  it('passes when fixture round-trips AND patch pre>0 + post=0 across changed files', async () => {
    // Order: vuln(1), safe(0), file0.before(1), file0.after(0)
    queueSemgrepResults([1, 0, 1, 0]);
    const result = await validateRule({
      payload: minimalPayload,
      cveId: 'CVE-XX',
      ecosystem: 'npm',
      changedFiles: [jsFile('lib/template.js', 'pre-patch source', 'post-patch source')],
      workDir,
    });
    expect(result.status).toBe('validated');
    expect(result.log.fixture_pre_matches).toBe(1);
    expect(result.log.fixture_post_matches).toBe(0);
    expect(result.log.patch_pre_matches).toBe(1);
    expect(result.log.patch_post_matches).toBe(0);
    expect(result.log.patch_per_file).toEqual([{ path: 'lib/template.js', pre: 1, post: 0 }]);
    expect(result.log.errors).toEqual([]);
    expect(result.log.patch_validation_skipped_reason).toBeUndefined();
  });

  it('fails when patch post-matches > 0 (rule still fires after the fix)', async () => {
    queueSemgrepResults([1, 0, 1, 1]);
    const result = await validateRule({
      payload: minimalPayload,
      cveId: 'CVE-XX',
      ecosystem: 'npm',
      changedFiles: [jsFile('lib/template.js', 'pre', 'post')],
      workDir,
    });
    expect(result.status).toBe('failed_validation');
    expect(result.log.errors.some((e) => /post-patch matches=1/.test(e))).toBe(true);
  });

  it('passes (advisory) when patch pre-matches === 0 — app-callsite rules legitimately miss library-internal patches', async () => {
    queueSemgrepResults([1, 0, 0, 0]);
    const result = await validateRule({
      payload: minimalPayload,
      cveId: 'CVE-XX',
      ecosystem: 'npm',
      changedFiles: [jsFile('lib/template.js', 'pre', 'post')],
      workDir,
    });
    expect(result.status).toBe('validated');
    expect(result.log.errors).toEqual([]);
    expect(result.log.patch_pre_matches).toBe(0);
    expect(result.log.patch_post_matches).toBe(0);
    expect(result.log.patch_validation_skipped_reason).toBe('patch_pre_match_zero_advisory');
  });

  it('still fails when patch post-matches > 0 even if pre-matches === 0 (rule matches fixed code)', async () => {
    queueSemgrepResults([1, 0, 0, 1]);
    const result = await validateRule({
      payload: minimalPayload,
      cveId: 'CVE-XX',
      ecosystem: 'npm',
      changedFiles: [jsFile('lib/template.js', 'pre', 'post')],
      workDir,
    });
    expect(result.status).toBe('failed_validation');
    expect(result.log.errors.some((e) => /post-patch matches=1/.test(e))).toBe(true);
    expect(result.log.errors.some((e) => /pre-patch/.test(e))).toBe(false);
  });

  it('skips patch validation when no applicable files (rename to image, deletion-only diff)', async () => {
    // Order: vuln(1), safe(0) — no patch invocations because changedFiles all skipped
    queueSemgrepResults([1, 0]);
    const result = await validateRule({
      payload: minimalPayload,
      cveId: 'CVE-XX',
      ecosystem: 'npm',
      changedFiles: [
        jsFile('lib/added.js', null, 'added content'),
        jsFile('lib/deleted.js', 'old content', null),
        jsFile('docs/README.md', 'a', 'b'),
      ],
      workDir,
    });
    // Fixture passes; no patch ran → status validated (we treat patch as
    // "applicable when feasible", and here it's never feasible).
    expect(result.status).toBe('validated');
    expect(result.log.patch_pre_matches).toBeNull();
    expect(result.log.patch_post_matches).toBeNull();
    expect(result.log.patch_validation_skipped_reason).toBe('no_applicable_changed_files');
  });

  it('aggregates pre/post counts across multiple applicable files', async () => {
    // Order: vuln(1), safe(0),
    //        file0.before(2), file0.after(0), file1.before(0), file1.after(0)
    queueSemgrepResults([1, 0, 2, 0, 0, 0]);
    const result = await validateRule({
      payload: minimalPayload,
      cveId: 'CVE-XX',
      ecosystem: 'npm',
      changedFiles: [
        jsFile('lib/template.js', 'pre1', 'post1'),
        jsFile('lib/escape.js', 'pre2', 'post2'),
      ],
      workDir,
    });
    expect(result.status).toBe('validated');
    expect(result.log.patch_pre_matches).toBe(2);
    expect(result.log.patch_post_matches).toBe(0);
    expect(result.log.patch_per_file).toEqual([
      { path: 'lib/template.js', pre: 2, post: 0 },
      { path: 'lib/escape.js', pre: 0, post: 0 },
    ]);
  });

  it('skips patch validation when changedFiles omitted entirely', async () => {
    queueSemgrepResults([1, 0]);
    const result = await validateRule({
      payload: minimalPayload,
      cveId: 'CVE-XX',
      ecosystem: 'npm',
      workDir,
    });
    expect(result.status).toBe('validated');
    expect(result.log.patch_validation_skipped_reason).toBe('no_changed_files_provided');
    expect(result.log.patch_pre_matches).toBeNull();
  });

  it('reports fixture failure cleanly when patch validation is advisory-only', async () => {
    // vuln matches 0 (rule too narrow) — fixture fails. Patch still runs
    // because the fixture step didn't throw, but patch_pre=0 is advisory
    // (see file header), so only the fixture failure shows up in errors.
    queueSemgrepResults([0, 0, 0, 0]);
    const result = await validateRule({
      payload: minimalPayload,
      cveId: 'CVE-XX',
      ecosystem: 'npm',
      changedFiles: [jsFile('lib/template.js', 'pre', 'post')],
      workDir,
    });
    expect(result.status).toBe('failed_validation');
    expect(result.log.errors.some((e) => /fixture_round_trip_failed/.test(e))).toBe(true);
    expect(result.log.errors.some((e) => /pre-patch/.test(e))).toBe(false);
    expect(result.log.patch_validation_skipped_reason).toBe('patch_pre_match_zero_advisory');
  });

  it('honors runPatchValidation: false to skip the diff-targeted step', async () => {
    queueSemgrepResults([1, 0]);
    const result = await validateRule({
      payload: minimalPayload,
      cveId: 'CVE-XX',
      ecosystem: 'npm',
      changedFiles: [jsFile('lib/template.js', 'pre', 'post')],
      workDir,
      runPatchValidation: false,
    });
    expect(result.status).toBe('validated');
    expect(result.log.patch_validation_skipped_reason).toBe('disabled_by_caller');
  });
});

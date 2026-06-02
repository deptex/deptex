/**
 * Degraded scan run state — unit tests.
 *
 * Covers the two pieces the /review-plan flagged as highest-risk + lowest-
 * tested: the npm manifest-parse fallback (must recover express's real deps
 * WITH the unresolvable event-stream present, and must skip range specs) and
 * the markDegraded helper (flag + dedup + write-through + step-error row +
 * CLI/no-jobId behavior). Also the clean-stays-non-degraded invariant.
 */

// fs is module-mocked (the worker test convention — jest.spyOn can't redefine
// fs methods in this config). `mock`-prefixed vars are allowed inside the
// jest.mock factory by jest's hoisting rules.
let mockFsExists = false;
let mockFsContent = '';
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  existsSync: jest.fn(() => mockFsExists),
  readFileSync: jest.fn(() => mockFsContent),
}));

import { recoverNpmManifestDeps, isExactNpmVersion } from '../sbom';
import { markDegraded, flushDegradedToScanJobs, DEGRADED_REASONS } from '../with-timeout';

// ---------------------------------------------------------------------------
// isExactNpmVersion
// ---------------------------------------------------------------------------
describe('isExactNpmVersion', () => {
  it('accepts exact pins (optionally v-prefixed, with prerelease/build)', () => {
    for (const v of ['4.18.2', 'v1.2.3', '1.2.3-beta.1', '0.0.1', '1.2.3+build.5']) {
      expect(isExactNpmVersion(v)).toBe(true);
    }
  });

  it('rejects ranges, tags, and non-registry specs', () => {
    for (const v of ['^4.18.2', '~1.2.0', '>=1.0.0', '1.x', '*', 'latest', 'next', 'npm:foo@1.2.3', 'file:../x', 'github:user/repo', 'https://x/y.tgz', '']) {
      expect(isExactNpmVersion(v)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// recoverNpmManifestDeps — the manifest-parse fallback
// ---------------------------------------------------------------------------
describe('recoverNpmManifestDeps', () => {
  function mockPackageJson(json: unknown | string) {
    mockFsExists = true;
    mockFsContent = typeof json === 'string' ? json : JSON.stringify(json);
  }

  it('recovers the express fixture deps even with the unresolvable event-stream present', () => {
    // The express dogfood fixture: all seeds exact-pinned, event-stream@3.3.6
    // is unpublished (what zeroed the SBOM in the first place).
    mockPackageJson({
      name: 'dogfood-express',
      dependencies: {
        express: '4.18.2',
        lodash: '4.17.20',
        minimist: '1.2.5',
        'event-stream': '3.3.6',
      },
      devDependencies: { nodemon: '2.0.20', jest: '^29.0.0' },
    });

    const deps = recoverNpmManifestDeps('/ws');
    const byName = new Map(deps.map((d) => [d.name, d]));

    // The other three are NOT blocked by event-stream being unresolvable.
    expect(byName.get('express')?.version).toBe('4.18.2');
    expect(byName.get('lodash')?.version).toBe('4.17.20');
    expect(byName.get('minimist')?.version).toBe('1.2.5');
    expect(byName.get('event-stream')?.version).toBe('3.3.6');

    // Production deps: is_direct, source dependencies, not dev-scoped.
    expect(byName.get('express')?.is_direct).toBe(true);
    expect(byName.get('express')?.source).toBe('dependencies');
    expect(byName.get('express')?.devScoped).toBe(false);

    // devDependency (exact) recovered + dev-scoped.
    expect(byName.get('nodemon')?.source).toBe('devDependencies');
    expect(byName.get('nodemon')?.devScoped).toBe(true);

    // Range spec (jest ^29.0.0) is skipped — a range would poison deps_sync/PDV matching.
    expect(byName.has('jest')).toBe(false);

    expect(deps).toHaveLength(5);
  });

  it('returns [] for a malformed package.json (still degraded by the caller)', () => {
    mockPackageJson('{ this is not json');
    expect(recoverNpmManifestDeps('/ws')).toEqual([]);
  });

  it('returns [] when no package.json exists', () => {
    mockFsExists = false;
    mockFsContent = '';
    expect(recoverNpmManifestDeps('/ws')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// markDegraded
// ---------------------------------------------------------------------------
type RecordedCall = { table: string; op: 'update' | 'insert'; payload: any };

function makeMockSupabase() {
  const calls: RecordedCall[] = [];
  const supabase = {
    from(table: string) {
      return {
        update(payload: any) {
          return {
            eq: (_c: string, _v: any) => {
              calls.push({ table, op: 'update', payload });
              return Promise.resolve({ error: null });
            },
          };
        },
        insert(payload: any) {
          calls.push({ table, op: 'insert', payload });
          return Promise.resolve({ error: null });
        },
      };
    },
  };
  return { supabase, calls };
}

function makeCtx(jobId: string | undefined) {
  const { supabase, calls } = makeMockSupabase();
  const ctx = {
    degraded: false,
    degradedSteps: [] as Array<{ step: string; reason: string }>,
    supabase: supabase as any,
    job: { jobId } as any,
    projectId: 'proj-1',
  };
  return { ctx, calls };
}

describe('markDegraded', () => {
  it('sets the flag, records the reason, write-throughs to scan_jobs, and logs the step error when detail is given', async () => {
    const { ctx, calls } = makeCtx('job-1');
    await markDegraded(ctx, { step: 'vuln_scan', code: 'depscan_failed', detail: 'apsw.FullError: disk full' });

    expect(ctx.degraded).toBe(true);
    expect(ctx.degradedSteps).toEqual([{ step: 'vuln_scan', reason: DEGRADED_REASONS.depscan_failed }]);

    const scanJobsWrite = calls.find((c) => c.table === 'scan_jobs' && c.op === 'update');
    expect(scanJobsWrite?.payload.scan_degraded).toBe(true);
    expect(scanJobsWrite?.payload.scan_degraded_steps).toEqual(ctx.degradedSteps);

    const stepError = calls.find((c) => c.table === 'extraction_step_errors' && c.op === 'insert');
    expect(stepError?.payload.code).toBe('depscan_failed');
    expect(stepError?.payload.message).toBe('apsw.FullError: disk full');
    expect(stepError?.payload.severity).toBe('warn');
  });

  it('dedups identical step+reason', async () => {
    const { ctx } = makeCtx('job-1');
    await markDegraded(ctx, { step: 'sbom', code: 'sbom_empty_with_components' });
    await markDegraded(ctx, { step: 'sbom', code: 'sbom_empty_with_components' });
    expect(ctx.degradedSteps).toHaveLength(1);
  });

  it('does NOT write a step-error row when no detail is given (the row already exists via runStage)', async () => {
    const { ctx, calls } = makeCtx('job-1');
    await markDegraded(ctx, { step: 'malicious_scan', code: 'malicious_failed' });
    expect(calls.some((c) => c.table === 'extraction_step_errors')).toBe(false);
    expect(calls.some((c) => c.table === 'scan_jobs')).toBe(true);
  });

  it('still sets the ctx flag but skips DB writes when there is no jobId (CLI / local mode)', async () => {
    const { ctx, calls } = makeCtx(undefined);
    await markDegraded(ctx, { step: 'semgrep', code: 'binary_missing_semgrep', detail: 'semgrep missing' });
    expect(ctx.degraded).toBe(true);
    expect(ctx.degradedSteps).toHaveLength(1);
    expect(calls).toHaveLength(0); // no scan_jobs row to write in local mode
  });
});

describe('flushDegradedToScanJobs', () => {
  it('writes scan_jobs when degraded', async () => {
    const { ctx, calls } = makeCtx('job-1');
    ctx.degraded = true;
    ctx.degradedSteps = [{ step: 'vuln_scan', reason: 'x' }];
    await flushDegradedToScanJobs(ctx);
    expect(calls.some((c) => c.table === 'scan_jobs' && c.op === 'update' && c.payload.scan_degraded === true)).toBe(true);
  });

  it('is a no-op for a clean run (the self-clear / non-degraded invariant)', async () => {
    const { ctx, calls } = makeCtx('job-1');
    // Default ctx: degraded=false, steps=[]. A fully-successful scan never calls
    // markDegraded, so flush must NOT mark scan_jobs degraded.
    await flushDegradedToScanJobs(ctx);
    expect(ctx.degraded).toBe(false);
    expect(calls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// DEGRADED_REASONS — single source of truth for badge/banner copy
// ---------------------------------------------------------------------------
describe('DEGRADED_REASONS', () => {
  it('has a non-empty reason for every code the fix sites use', () => {
    const codes = [
      'depscan_failed',
      'sbom_empty_with_components',
      'sbom_empty_no_manifest',
      'malicious_failed',
      'binary_missing_semgrep',
      'binary_missing_trufflehog',
      'iac_failed',
    ] as const;
    for (const code of codes) {
      expect(typeof DEGRADED_REASONS[code]).toBe('string');
      expect(DEGRADED_REASONS[code].length).toBeGreaterThan(10);
    }
  });
});

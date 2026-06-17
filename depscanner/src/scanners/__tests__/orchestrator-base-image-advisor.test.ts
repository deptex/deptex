/**
 * runBaseImageAdvisor + reachabilityBudgetMs — Phase 2 close-out hardening.
 *
 * Pins the catalog pre-flight (a bad catalog YAML degrades to ONE warning, not
 * one per Dockerfile), the per-Dockerfile failure isolation (one bad file
 * doesn't abort the advisor for the rest), the catalog-hash observability log,
 * and the per-image reachability-budget clamp helper.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { _resetCatalogCacheForTests } from '../base-image-catalog';
import { _internal } from '../orchestrator';

// Eagerly resolve the same module instances the orchestrator captured at
// import time, so monkey-patches we apply later land on the same namespace
// objects the orchestrator dereferences via `base_image_catalog_1.loadCatalog`
// / `base_image_advisor_1.generateRecommendation`. Loading them via require()
// inside individual tests would, after a jest.resetModules() call, produce
// fresh module instances that the orchestrator's already-bound references do
// NOT see — the patch would land on a different object than the one the SUT
// reads.
const catalogModule = require('../base-image-catalog');
const advisorModule = require('../base-image-advisor');

const { runBaseImageAdvisor, reachabilityBudgetMs } = _internal;

// ---- Logger spy ------------------------------------------------------------

type LogCall = { level: 'info' | 'warn' | 'error'; step: string; message: string };

function makeLogger() {
  const calls: LogCall[] = [];
  const logger = {
    info: async (step: string, message: string) => {
      calls.push({ level: 'info', step, message });
    },
    warn: async (step: string, message: string) => {
      calls.push({ level: 'warn', step, message });
    },
    error: async (step: string, message: string) => {
      calls.push({ level: 'error', step, message });
    },
  } as any;
  return { logger, calls };
}

// ---- Supabase stub --------------------------------------------------------

function makeSupabase(): any {
  // upsertBaseImageRecommendations calls .from('...').upsert(...) and then a
  // best-effort stale-run reap: .from('...').delete({count}).in(...).neq(...).
  return {
    from: () => ({
      upsert: async () => ({ error: null }),
      delete: () => ({
        in: () => ({
          neq: async () => ({ count: 0, error: null }),
        }),
      }),
    }),
  };
}

// ---- Repo + Dockerfile fixtures -------------------------------------------

function makeRepo(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deptex-advisor-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return dir;
}

function cleanupRepo(dir: string) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
}

function makeCtx(opts: {
  repoPath: string;
  supabase?: any;
  logger?: any;
}) {
  return {
    supabase: opts.supabase ?? makeSupabase(),
    projectId: 'proj-1',
    organizationId: 'org-1',
    jobId: 'job-1',
    runId: 'run-1',
    repoPath: opts.repoPath,
    githubInstallationId: null,
    logger: opts.logger,
    onHeartbeat: async () => {},
  } as any;
}

// ============================================================================
// reachabilityBudgetMs — pure helper
// ============================================================================

describe('reachabilityBudgetMs', () => {
  const REACH_TIMEOUT = 30_000; // matches REACHABILITY_PER_IMAGE_TIMEOUT_MS default
  const TOTAL_BUDGET = 25 * 60_000; // matches CONTAINER_SCAN_TOTAL_BUDGET_MS default

  it('returns the per-image timeout when ample remaining budget', () => {
    expect(reachabilityBudgetMs(0)).toBe(REACH_TIMEOUT);
    expect(reachabilityBudgetMs(60_000)).toBe(REACH_TIMEOUT);
  });

  it('clamps to the remaining step-loop budget when less than the per-image timeout', () => {
    // 5s of remaining step budget is less than the 30s per-image default — clamp.
    const elapsed = TOTAL_BUDGET - 5_000;
    expect(reachabilityBudgetMs(elapsed)).toBe(5_000);
  });

  it('floors at 1ms when the step-loop budget is already exhausted', () => {
    expect(reachabilityBudgetMs(TOTAL_BUDGET)).toBe(1);
    expect(reachabilityBudgetMs(TOTAL_BUDGET + 60_000)).toBe(1);
  });

  it('returns a positive number for any non-negative elapsed input', () => {
    for (let i = 0; i <= 10; i++) {
      const elapsed = (TOTAL_BUDGET / 10) * i;
      expect(reachabilityBudgetMs(elapsed)).toBeGreaterThan(0);
    }
  });
});

// ============================================================================
// runBaseImageAdvisor — catalog pre-flight + per-Dockerfile isolation
// ============================================================================

describe('runBaseImageAdvisor — catalog pre-flight', () => {
  beforeEach(() => {
    _resetCatalogCacheForTests();
  });

  it('emits exactly one base_image_advisor_catalog_unavailable warning when loadCatalog throws', async () => {
    // Patch loadCatalog on the shared module instance — the same object the
    // orchestrator dereferences. Restored in finally so subsequent tests are
    // unaffected.
    const original = catalogModule.loadCatalog;
    catalogModule.loadCatalog = () => {
      throw new catalogModule.CatalogValidationError('bad-yaml.fixture');
    };

    const repo = makeRepo({
      'Dockerfile': 'FROM node:20\nCMD ["node", "server.js"]\n',
      'svc/Dockerfile': 'FROM python:3.12\nCMD ["python", "app.py"]\n',
    });
    try {
      const { logger, calls } = makeLogger();
      const ctx = makeCtx({ repoPath: repo, logger });
      const result = await runBaseImageAdvisor(ctx, []);

      // No exception escaped; advisor short-circuited.
      expect(result.written).toBe(0);
      // EXACTLY one catalog-unavailable warning — not one per Dockerfile.
      const catalogWarnings = result.warnings.filter((w: string) =>
        w.startsWith('base_image_advisor_catalog_unavailable:')
      );
      expect(catalogWarnings).toHaveLength(1);
      expect(catalogWarnings[0]).toMatch(/bad-yaml\.fixture/);
      // Logger surfaces the same fact once.
      const catalogLogs = calls.filter(
        (c) => c.step === 'base_image_advisor' && /catalog unavailable/.test(c.message)
      );
      expect(catalogLogs).toHaveLength(1);
      // And it does NOT continue into the Dockerfile loop.
      expect(
        calls.filter((c) => c.level === 'warn' && /dockerfile .* skipped/.test(c.message))
      ).toHaveLength(0);
    } finally {
      catalogModule.loadCatalog = original;
      cleanupRepo(repo);
    }
  });

  it('logs a catalog_hash + dockerfile_count once per scan when the catalog loads', async () => {
    const repo = makeRepo({
      'Dockerfile': 'FROM node:20\nCMD ["node", "server.js"]\n',
    });
    try {
      const { logger, calls } = makeLogger();
      const ctx = makeCtx({ repoPath: repo, logger });
      await runBaseImageAdvisor(ctx, []);

      const hashLogs = calls.filter(
        (c) => c.step === 'base_image_advisor' && /catalog_hash=/.test(c.message)
      );
      expect(hashLogs).toHaveLength(1);
      expect(hashLogs[0].message).toMatch(/catalog_hash=[0-9a-f]{16}/);
      expect(hashLogs[0].message).toMatch(/dockerfile_count=1/);
    } finally {
      cleanupRepo(repo);
    }
  });

  it('isolates a per-Dockerfile failure — others still produce recommendations', async () => {
    // Force a per-Dockerfile failure by patching generateRecommendation to
    // throw on the FIRST call only. The advisor's per-iteration try/catch
    // (orchestrator.ts:1086-1104) must catch the throw, push a warning that
    // names the failing file, and continue to the next Dockerfile so its
    // recommendation still lands. A regression that removes the try/catch
    // would let the throw escape — both Dockerfiles would be lost AND
    // result.written would be 0.
    const originalGenerate = advisorModule.generateRecommendation;
    const callIndex: { current: number } = { current: 0 };
    advisorModule.generateRecommendation = (input: any) => {
      const idx = callIndex.current++;
      if (idx === 0) {
        throw new Error('synthetic per-Dockerfile failure');
      }
      return originalGenerate(input);
    };

    const repo = makeRepo({
      // Two valid Dockerfiles with parseable FROM lines. Sort order is
      // determined by findDockerfiles() walking the tree — Dockerfile at
      // root is hit first on both POSIX and Windows.
      'Dockerfile': 'FROM node:20-bullseye\nCMD ["node", "server.js"]\n',
      'svc/Dockerfile': 'FROM node:20-bullseye\nCMD ["node", "app.js"]\n',
    });
    try {
      const { logger, calls } = makeLogger();
      const ctx = makeCtx({ repoPath: repo, logger });
      const result = await runBaseImageAdvisor(ctx, []);

      // Catalog loaded fine — no catalog-unavailable warning.
      expect(
        result.warnings.filter((w: string) =>
          w.startsWith('base_image_advisor_catalog_unavailable:')
        )
      ).toHaveLength(0);

      // EXACTLY one per-Dockerfile failure warning, naming the failing path.
      const failWarnings = result.warnings.filter((w: string) =>
        w.startsWith('base_image_advisor_failed:')
      );
      expect(failWarnings).toHaveLength(1);
      expect(failWarnings[0]).toMatch(/synthetic per-Dockerfile failure/);

      // The surviving Dockerfile (call #2) produced a row that upserted.
      expect(result.written).toBe(1);

      // The per-Dockerfile catch logged via ctx.logger.warn.
      const dockerfileWarns = calls.filter(
        (c) => c.level === 'warn' && /dockerfile .* skipped/.test(c.message)
      );
      expect(dockerfileWarns).toHaveLength(1);

      // generateRecommendation was actually invoked twice (the failure path
      // didn't short-circuit the loop on the second iteration).
      expect(callIndex.current).toBe(2);
    } finally {
      advisorModule.generateRecommendation = originalGenerate;
      cleanupRepo(repo);
    }
  });
});

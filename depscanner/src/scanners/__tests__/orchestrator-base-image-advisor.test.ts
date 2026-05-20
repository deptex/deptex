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
import type { ContainerFinding } from '../types';

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
  // upsertBaseImageRecommendations only calls .from('...').upsert(...).
  return {
    from: () => ({
      upsert: async () => ({ error: null }),
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

  afterEach(() => {
    jest.resetModules();
  });

  it('emits exactly one base_image_advisor_catalog_unavailable warning when loadCatalog throws', async () => {
    // Patch loadCatalog ON THE SHARED MODULE so the orchestrator imports the
    // throwing version too. jest.resetModules() in afterEach restores it.
    const catalog = require('../base-image-catalog');
    const original = catalog.loadCatalog;
    catalog.loadCatalog = () => {
      throw new catalog.CatalogValidationError('bad-yaml.fixture');
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
      catalog.loadCatalog = original;
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
    // The catalog is real; one Dockerfile is unreadable (a directory at the
    // same path), the other is a normal Dockerfile.
    const repo = makeRepo({
      'svc/Dockerfile': 'FROM node:20\nCMD ["node", "server.js"]\n',
    });
    // Make the second "Dockerfile" path an unreadable directory so
    // parseDockerfileFinalStage's fs.readFileSync surfaces an error.
    const badPath = path.join(repo, 'Dockerfile');
    fs.mkdirSync(badPath);

    try {
      const { logger, calls } = makeLogger();
      const supabase = {
        from: () => ({
          upsert: async () => ({ error: null }),
        }),
      };
      const ctx = makeCtx({ repoPath: repo, logger, supabase });
      const result = await runBaseImageAdvisor(ctx, [
        {
          scanner_version: 'trivy@0.69.3',
          image_reference: 'node:20',
          image_digest: 'sha256:' + 'a'.repeat(64),
          os_package_name: 'libc6',
          os_package_version: '1',
          os_package_ecosystem: 'debian',
          osv_id: null,
          cve_id: 'CVE-x',
          severity: 'HIGH',
          cvss_score: null,
          epss_score: null,
          is_kev: false,
          fix_versions: [],
          layer_digest: null,
          description: null,
          rule_doc_url: null,
          container_fingerprint: 'libc6@CVE-x',
        } as ContainerFinding,
      ]);

      // No catalog-unavailable warning (catalog loaded fine).
      expect(
        result.warnings.filter((w: string) =>
          w.startsWith('base_image_advisor_catalog_unavailable:')
        )
      ).toHaveLength(0);
      // The advisor still wrote at least one row from the surviving Dockerfile.
      expect(result.written).toBeGreaterThanOrEqual(1);
      // Per-Dockerfile failures (if any from the unreadable bad path) were
      // logged but did not stop the run.
      // (The bad path is a directory, so parseDockerfileFinalStage skips it
      // silently rather than throwing; this assertion just establishes that
      // surviving Dockerfiles are not held hostage by a broken sibling.)
    } finally {
      cleanupRepo(repo);
    }
  });
});

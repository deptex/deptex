/**
 * Extraction pipeline: clone -> resolve -> SBOM -> deps_sync -> usage_extraction
 *   -> dep_scan -> rule_generation -> taint_engine -> reachability + EPD
 *   -> iac_container_scan -> malicious_scan -> semgrep -> trufflehog -> finalize.
 *
 * Each `do<Step>(ctx)` body lives in its own file under `pipeline-steps/`.
 * This file is intentionally a thin orchestrator — read top to bottom to see
 * the pipeline order; jump into a step module when you need to change the
 * body. Shared types live in `pipeline-types.ts`; cross-cutting helpers
 * (updateStep, setError, retry, classifyError shims) live in
 * `pipeline-helpers.ts`.
 */

import { cleanupRepository } from './clone';
import type { ExtractionLogger } from './logger';
import type {
  ExtractionJob,
  PipelineContext,
  PipelineLogger,
  RunPipelineResult,
} from './pipeline-types';
import type { Storage } from './storage';
import { getSupabase, setError, clearDepscanCacheOnly } from './pipeline-helpers';
import { doClone } from './pipeline-steps/clone';
import { doResolve } from './pipeline-steps/resolve';
import { doSbom } from './pipeline-steps/sbom';
import { doDepsSync } from './pipeline-steps/deps-sync';
import { doUsageExtraction } from './pipeline-steps/usage-extraction';
import { loadAssetTier } from './pipeline-steps/asset-tier';
import { doDepScan } from './pipeline-steps/dep-scan';
import { doRuleGeneration } from './pipeline-steps/rule-generation';
import { doTaintEngine } from './pipeline-steps/taint-engine';
import { doReachabilityAndEpd } from './pipeline-steps/reachability';
import { doIaCContainer } from './pipeline-steps/iac-container';
import { doComposition } from './pipeline-steps/composition';
import { doMaliciousScan } from './pipeline-steps/malicious';
import { doSemgrep } from './pipeline-steps/semgrep';
import { doTruffleHog } from './pipeline-steps/trufflehog';
import { doFinalize } from './pipeline-steps/finalize';

// Re-export public types so existing callers (cli/scan.ts, clone.ts,
// __tests__/pipeline-failures.test.ts, src/index.ts) keep their imports.
export type { ExtractionJob, PipelineLogger, RunPipelineResult };

export async function runPipeline(
  job: ExtractionJob,
  logger?: ExtractionLogger | PipelineLogger,
  checkCancelled?: () => Promise<boolean>,
  heartbeat?: () => Promise<void>,
  storage?: Storage,
): Promise<RunPipelineResult | undefined> {
  const supabase: Storage = storage ?? (getSupabase() as unknown as Storage);

  const log = logger ?? ({
    info: async () => {},
    success: async () => {},
    warn: async () => {},
    error: async () => {},
  } as PipelineLogger);

  // Build the shared context once. doClone fills in repoPath, workspaceRoot,
  // jobEcosystem, runId before any other step touches them. asset tier is
  // hydrated mid-pipeline before the first depscore-touching step.
  const ctx: PipelineContext = {
    job,
    projectId: job.projectId,
    organizationId: job.organizationId,
    jobEcosystem: job.ecosystem || 'npm',
    runId: '', // set by doClone
    supabase,
    log,
    checkCancelled,
    heartbeat,
    repoPath: null,
    workspaceRoot: '',
    assetTier: 'EXTERNAL',
    tierMultiplier: undefined,
    graphTrusted: true,
    projectDepsCount: 0,
    newDepsToPopulate: [],
    astParsedSuccessfully: false,
  };

  try {
    // Clear only dep-scan cache (keep VDB ~30GB so we don't re-download every run).
    clearDepscanCacheOnly();

    // === Clone (CRITICAL) — sets ctx.repoPath, workspaceRoot, jobEcosystem, runId ===
    if (checkCancelled && await checkCancelled()) return;
    await doClone(ctx);

    // === Dependency resolution (ecosystem-specific install before SBOM) ===
    await doResolve(ctx);

    // === SBOM (CRITICAL) — returns parsed dependencies + relationships + bom-ref map ===
    if (checkCancelled && await checkCancelled()) return;
    const sbom = await doSbom(ctx);

    // === Dependency sync (CRITICAL) — sets ctx.projectDepsCount + newDepsToPopulate ===
    if (checkCancelled && await checkCancelled()) return;
    await doDepsSync(ctx, sbom);

    // === Usage extraction (tree-sitter) + framework entry-point detection ===
    if (checkCancelled && await checkCancelled()) return;
    await doUsageExtraction(ctx);

    // Asset tier: hydrate ctx.assetTier + tierMultiplier once before any
    // depscore-touching step (vuln_scan, semgrep, trufflehog) consumes them.
    await loadAssetTier(ctx);

    // === Vulnerability scan (OPTIONAL) — dep-scan + post-process VDR rows ===
    if (checkCancelled && await checkCancelled()) return;
    const { scanStart } = await doDepScan(ctx);

    // Phase 6.5 / M5 task 34 — atom integration retired entirely. The
    // cross-file taint engine + CVE-targeted FrameworkSpec rules replace
    // atom's reachables + usages flow output for every ecosystem. Existing
    // atom-shape rows in `project_reachable_flows` decay naturally as
    // projects re-extract; no backfill needed. tree-sitter remains the
    // source of truth for usage extraction on all MVP ecosystems.

    // === AI rule generation (Phase 5) ===
    if (!(checkCancelled && await checkCancelled())) {
      await doRuleGeneration(ctx);
    }

    // Phase 6.5 / M5 task 31 — `reachability_rules` step retired entirely.
    // The Phase 3 hand-authored Semgrep taint rule packs (37 CVEs) and
    // their org-generated counterparts have been replaced by the
    // CVE-targeted FrameworkSpec generator + cross-file taint engine
    // (the `taint_engine` step below). The `taint_engine` confirmed-tier
    // OR-clause in `updateReachabilityLevels` reads `taint_engine` rows
    // alongside any legacy `semgrep_taint` rows still in the DB, so
    // existing data decays naturally as projects re-extract.

    // === Cross-file taint engine (Phase 6, shadow mode) ===
    if (checkCancelled && await checkCancelled()) return;
    const { validOsvIds, fpFilterCostUsd, cveSinkPatterns, usedDependencies } =
      await doTaintEngine(ctx);

    // === Reachability classification + depscore recalc + EPD scoring ===
    await doReachabilityAndEpd(
      ctx,
      validOsvIds,
      fpFilterCostUsd,
      scanStart,
      cveSinkPatterns,
      usedDependencies,
    );

    // === IaC, Malicious, Semgrep, TruffleHog (OPTIONAL) ===
    // None of these four affect reachability classification (done above) —
    // they are SAST / secrets / IaC / malicious-package scans. They are also
    // the dominant scan-time cost on real repos (the malicious step fans
    // GuardDog out to a semgrep run per dependency). DEPTEX_SKIP_OPTIONAL_SCANS
    // skips them so the reachability corpus harness can scan many repos
    // without paying that cost; production extraction always runs them.
    const skipOptionalScans =
      process.env.DEPTEX_SKIP_OPTIONAL_SCANS === '1' ||
      /^true$/i.test(process.env.DEPTEX_SKIP_OPTIONAL_SCANS ?? '');

    let scannerSummary: Awaited<ReturnType<typeof doIaCContainer>> = null;
    if (skipOptionalScans) {
      await log.info('finalize', 'Optional scans (IaC, malicious-package, SAST, secrets) skipped — DEPTEX_SKIP_OPTIONAL_SCANS set');
    } else {
      // === IaC + Container scanning (OPTIONAL) ===
      if (checkCancelled && await checkCancelled()) return;
      scannerSummary = await doIaCContainer(ctx);

      // === IaC↔Code reachability composition (OPTIONAL, Item G) ===
      // Folds container OS-package reachability with code-side PDV
      // reachability into PDV.contextual_depscore via the
      // apply_composition_results RPC. Soft-fail: a failure here only
      // affects PDV ranking on already-classified rows; the underlying
      // contextual_depscore stays at its EPD-finalized value.
      if (checkCancelled && await checkCancelled()) return;
      await doComposition(ctx, scannerSummary);

      // === Malicious-package scan (OPTIONAL, soft-fail) ===
      if (checkCancelled && await checkCancelled()) return;
      await doMaliciousScan(ctx);

      // === Semgrep (OPTIONAL) ===
      if (checkCancelled && await checkCancelled()) return;
      await doSemgrep(ctx);

      // === TruffleHog (OPTIONAL) ===
      if (checkCancelled && await checkCancelled()) return;
      await doTruffleHog(ctx);
    }

    // === Finalize ===
    if (checkCancelled && await checkCancelled()) return;
    const finalizeSummary = await doFinalize(ctx, scannerSummary);

    return { finalizeSummary };
  } catch (error: any) {
    await setError(supabase, ctx.projectId, error.message);
    throw error;
  } finally {
    // Don't nuke a local workspace the user handed us — that would delete
    // their actual source tree. Only cleanup repos we cloned ourselves.
    if (ctx.repoPath && !job.localWorkspacePath) {
      if (process.env.KEEP_EXTRACT_WORKSPACE === '1') {
        console.log('[EXTRACT] KEEP_EXTRACT_WORKSPACE=1; skipping workspace cleanup');
      } else {
        cleanupRepository(ctx.repoPath);
      }
    }
  }
}

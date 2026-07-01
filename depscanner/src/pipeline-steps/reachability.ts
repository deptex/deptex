/**
 * STEP: Reachability classification + depscore recalc + EPD contextual scoring.
 *
 * Three sub-passes that always run together:
 *   1. updateReachabilityLevels — classifies every PDV as confirmed /
 *      data_flow / function / module / unreachable based on tree-sitter
 *      usage_slices (non-Java) or atom slices + usages (Java). Maven
 *      additionally recomputes files_importing_count.
 *   2. Depscore recalc — refreshes depscore + base_depscore_no_reachability
 *      using the new reachability_level, fresh asset tier, and current
 *      tier multiplier.
 *   3. EPD contextual scoring (Phase 4) — adds entry_point_classification
 *      + contextual_depscore on confirmed/data_flow vulns; heuristic-only
 *      (no AI call) for function/module per epd.ts:aiEligible. Failures
 *      are warn-level — the extraction completes with base depscore.
 *      EpdBudgetExceededError is intentionally allowed to propagate so
 *      the env / per-org `fail_job` behavior can hard-fail when chosen.
 *
 * Inputs come from the taint-engine step (validOsvIds for the classifier's
 * defense-in-depth; fpFilterCostUsd for EPD's burn-breaker ceiling).
 */

import { logStepError, classifyError } from '../with-timeout';
import { updateReachabilityLevels, computeImportCountsFromUsageSlices } from '../reachability';
import { isPureClientSpa } from '../taint-engine/runner';
import {
  calculateBaseDepscoreNoReachability,
  calculateDepscore,
  SEVERITY_TO_CVSS,
} from '../depscore';
import { applyEpdScoringFallback, EpdBudgetExceededError } from '../epd';
import type { PipelineContext } from '../pipeline-types';

/** The slice of a project_dependencies row the rescore multiplier reads. */
export interface RescorePdContext {
  /** `false` ⇒ transitive (0.75× directness taper); true/null/undefined ⇒ direct. */
  is_direct?: boolean | null;
  /** `'dev'` ⇒ dev/test/build scope (0.4× env taper). */
  environment?: string | null;
}

/**
 * SC1 — the authoritative post-classifier rescore for one PDV.
 *
 * This is the FINAL depscore that ships: it runs after the taint classifier
 * has set `reachability_level`, so it folds in the reachability tier weight
 * (confirmed 1.0 … module 0.5, unreachable 0.0) AND the dependency-context
 * taper (0.75× transitive, 0.4× dev) — mirroring dep-scan.ts's `scoreVulnRow`
 * but additionally threading `reachabilityLevel`. Before SC1 this site re-read
 * only PDV columns and passed no directness/scope, silently overwriting the
 * initial taper dep-scan.ts applied back to flat for the full pipeline.
 *
 * Malicious + reputation are intentionally NOT threaded here either — they are
 * populated later (malicious-package scan + QStash populate-dependencies), and
 * taper correctly when that pass rescore picks them up.
 */
export function rescoreVulnRow(
  row: {
    cvss_score: number | null;
    epss_score: number | null;
    cisa_kev: boolean | null;
    is_reachable: boolean | null;
    reachability_level: string | null;
    severity: string | null;
  },
  pd: RescorePdContext | undefined,
  importance: number,
): { depscore: number; base_depscore_no_reachability: number } {
  // Preserve the prior site's CVSS default of 4.0 (medium) when both
  // cvss_score and the severity lookup are absent.
  const cvss = row.cvss_score ?? (row.severity ? (SEVERITY_TO_CVSS[row.severity] ?? 4.0) : 4.0);
  const epss = row.epss_score ?? 0;
  const cisaKev = row.cisa_kev ?? false;
  const isDirect = pd?.is_direct ?? undefined;
  const isDevDependency = pd?.environment === 'dev';
  return {
    depscore: calculateDepscore({
      cvss, epss, cisaKev,
      isReachable: row.is_reachable ?? false,
      reachabilityLevel: row.reachability_level ?? undefined,
      importance, isDirect, isDevDependency,
    }),
    base_depscore_no_reachability: calculateBaseDepscoreNoReachability({
      cvss, epss, cisaKev, importance, isDirect, isDevDependency,
    }),
  };
}


export async function doReachabilityAndEpd(
  ctx: PipelineContext,
  validOsvIds: Set<string>,
  fpFilterCostUsd: number,
  scanStart: number,
  cveSinkPatterns: Map<string, string[]>,
  usedDependencies: Set<string>,
): Promise<void> {
  const {
    supabase,
    job,
    projectId,
    organizationId,
    log,
    workspaceRoot,
    jobEcosystem,
    runId,
    astParsedSuccessfully,
    graphTrusted,
    importance,
  } = ctx;

  // v3 precision — persist project_dependencies.callgraph_reached for every
  // PD row in this run when the engine's callgraph extracted dep credits.
  // The classifier reads usedDependencies in-memory; this column is
  // provenance for future UI/EPD signals and lets operators query
  // "which deps got demoted by the callgraph pass" without re-running.
  // Skip when usedDependencies is empty: either the callgraph didn't
  // extract for this ecosystem yet, or the engine was rollout-gated off —
  // either way the column stays NULL (= not measured).
  if (usedDependencies.size > 0) {
    try {
      const { data: pdRows } = await supabase
        .from('project_dependencies')
        .select('id, name')
        .eq('project_id', projectId)
        .eq('last_seen_extraction_run_id', runId);
      const updates: Array<{ id: string; reached: boolean }> = [];
      for (const row of (pdRows ?? []) as Array<{ id: string; name: string | null }>) {
        const reached = !!row.name && usedDependencies.has(row.name.toLowerCase());
        updates.push({ id: row.id, reached });
      }
      // Two batched UPDATEs (one per boolean value) — `in('id', [...])`
      // lets us avoid N+1 round-trips. Stay below PostgREST's URL-length
      // ceiling by chunking on 200 ids per call.
      const reachedIds = updates.filter((u) => u.reached).map((u) => u.id);
      const unreachedIds = updates.filter((u) => !u.reached).map((u) => u.id);
      const CHUNK = 200;
      const writePartition = async (ids: string[], value: boolean) => {
        for (let i = 0; i < ids.length; i += CHUNK) {
          const slice = ids.slice(i, i + CHUNK);
          if (slice.length === 0) continue;
          const { error } = await supabase
            .from('project_dependencies')
            .update({ callgraph_reached: value })
            .in('id', slice);
          if (error) {
            await log.warn(
              'reachability',
              `callgraph_reached write failed (${value} batch, ${slice.length} rows): ${error.message}`,
            );
          }
        }
      };
      await writePartition(reachedIds, true);
      await writePartition(unreachedIds, false);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      await log.warn('reachability', `callgraph_reached persist failed: ${msg}`);
    }
  }

  // Reachability classification runs for every ecosystem — it consumes
  // tree-sitter's usage_slices (non-Java) or atom's slices + usages
  // (Java). files_importing_count is authoritative from the tree-sitter
  // storage write for non-Java; for Java we recompute from atom output.
  // Client-SPA bundling floor: on a pure browser SPA the bundler ships the
  // entire prod dependency graph, so a prod/unknown-scope dep is loaded even
  // with zero first-party imports. Lets the classifier keep `unreachable` for
  // dev/build-only deps while flooring prod deps at `module`. Best-effort.
  let isClientSpaProject = false;
  try {
    const { data: projFw } = await supabase
      .from('projects')
      .select('framework')
      .eq('id', projectId)
      .maybeSingle();
    const fw = (projFw as { framework?: string | null } | null)?.framework;
    isClientSpaProject = fw ? isPureClientSpa([fw]) : false;
  } catch {
    // non-fatal — floor just stays off
  }

  await updateReachabilityLevels(projectId, runId, supabase, log, workspaceRoot, {
    validOsvIds,
    organizationId,
    astParsedSuccessfully,
    graphTrusted,
    cveSinkPatterns,
    isClientSpaProject,
    // v3 precision: dep names the callgraph confirmed are reached. The
    // classifier's heuristicUnreachable branch AND-clauses with
    // `!usedTransitives.has(depName)` to demote called-but-not-imported
    // transitives from `unreachable` to `module` (the jackson-vs-idna fix).
    usedTransitives: usedDependencies,
    // v3 follow-up: composer/pypi/npm have explicit `use`/`import`
    // semantics, so `files_importing_count === 0` is strong negative
    // evidence even on a direct dep. Enabling this for these ecosystems
    // lets the heuristic demote directly-declared-but-never-imported
    // packages (dev utilities, optional features behind flags) that
    // currently stay at `module`. Excluded: gem (Rails autoload),
    // maven/golang/cargo/nuget (tree-sitter import resolution is partial).
    ecosystem: jobEcosystem,
  });
  if (jobEcosystem === 'maven') {
    await computeImportCountsFromUsageSlices(projectId, runId, jobEcosystem, supabase, log);
  }

  // --- Sub-step: Recalculate depscores with updated reachability ---
  try {
    const { data: pdvsForRescore } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('id, project_dependency_id, osv_id, cvss_score, epss_score, cisa_kev, is_reachable, reachability_level, severity')
      .eq('project_id', projectId)
      .eq('extraction_run_id', runId);

    if (pdvsForRescore && pdvsForRescore.length > 0) {
      // Importance was already hydrated onto ctx by loadImportance() before any
      // depscore-touching step ran (pipeline.ts), so reuse it rather than
      // re-querying projects.importance a second time here.
      const rscoreImportance = importance;

      // SC1: join project_dependencies so the rescore can thread directness +
      // dev-scope into calculateDepscore (mirrors dep-scan.ts's scoreVulnRow).
      // Without this the dep-scan.ts initial taper is overwritten back to flat.
      const { data: pdScopeRows } = await supabase
        .from('project_dependencies')
        .select('id, is_direct, environment')
        .eq('project_id', projectId)
        .eq('last_seen_extraction_run_id', runId);
      const pdById = new Map<string, RescorePdContext>();
      for (const r of (pdScopeRows ?? []) as Array<{ id: string; is_direct: boolean | null; environment: string | null }>) {
        pdById.set(r.id, { is_direct: r.is_direct, environment: r.environment });
      }

      // R3: batch the rescore writes into a single upsert (onConflict id)
      // instead of one UPDATE per PDV. project_id / project_dependency_id /
      // osv_id carry existing values for the never-taken INSERT arm.
      const rescoreRows = pdvsForRescore.map((row: any) => {
        const { depscore, base_depscore_no_reachability } = rescoreVulnRow(
          row,
          pdById.get(row.project_dependency_id as string),
          rscoreImportance,
        );
        return {
          id: row.id,
          project_id: projectId,
          project_dependency_id: row.project_dependency_id,
          osv_id: row.osv_id,
          depscore,
          base_depscore_no_reachability,
        };
      });
      for (let i = 0; i < rescoreRows.length; i += 100) {
        const chunk = rescoreRows.slice(i, i + 100);
        const { error: rescoreErr } = await supabase
          .from('project_dependency_vulnerabilities')
          .upsert(chunk, { onConflict: 'id' });
        if (rescoreErr) {
          await log.warn('reachability', `depscore rescore upsert failed (${chunk.length} rows, chunk ${i}): ${rescoreErr.message}`);
        }
      }
    }
  } catch (rescoreErr: any) {
    // Non-fatal — the run still completes with base depscores — but never
    // discard silently: a partial failure here means stale scores ship.
    await log.warn('reachability', `depscore recalculation failed (continuing with stale depscores): ${rescoreErr?.message ?? rescoreErr}`);
  }

  // --- EPD contextual scoring (Phase 4) ---
  // Wired now that Phase 3 produces taint flows with framework-input
  // entry-point tags and the tree-sitter framework detectors populate
  // project_entry_points.
  const epdStart = Date.now();
  try {
    await applyEpdScoringFallback(supabase, projectId, workspaceRoot, log, fpFilterCostUsd, job.jobId, runId);
  } catch (epdErr: any) {
    // EpdBudgetExceededError must propagate WITHOUT persisting an
    // extraction_step_errors row — env / per-org `fail_job` is the only
    // intended consumer and a stray warn-row would muddy ops triage.
    if (epdErr instanceof EpdBudgetExceededError) throw epdErr;
    if (job.jobId) {
      const { code, message, stack } = classifyError(epdErr);
      await logStepError(supabase, {
        jobId: job.jobId,
        projectId,
        step: 'epd',
        code,
        message,
        stack,
        durationMs: Date.now() - epdStart,
        severity: 'warn',
      });
    }
    await log.warn('epd', `EPD scoring failed (continuing with base depscore): ${epdErr?.message ?? epdErr}`);
  }

  // --- Final vuln scan summary ---
  await log.success('vuln_scan', 'Vulnerability scan complete', Date.now() - scanStart);
}

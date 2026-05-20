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
import {
  calculateBaseDepscoreNoReachability,
  calculateDepscore,
  SEVERITY_TO_CVSS,
  type AssetTier,
} from '../depscore';
import { applyEpdScoringFallback, EpdBudgetExceededError } from '../epd';
import type { PipelineContext } from '../pipeline-types';

const VALID_TIERS: AssetTier[] = ['CROWN_JEWELS', 'EXTERNAL', 'INTERNAL', 'NON_PRODUCTION'];

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
  await updateReachabilityLevels(projectId, runId, supabase, log, workspaceRoot, {
    validOsvIds,
    organizationId,
    astParsedSuccessfully,
    graphTrusted,
    cveSinkPatterns,
    // v3 precision: dep names the callgraph confirmed are reached. The
    // classifier's heuristicUnreachable branch AND-clauses with
    // `!usedTransitives.has(depName)` to demote called-but-not-imported
    // transitives from `unreachable` to `module` (the jackson-vs-idna fix).
    usedTransitives: usedDependencies,
  });
  if (jobEcosystem === 'maven') {
    await computeImportCountsFromUsageSlices(projectId, runId, jobEcosystem, supabase, log);
  }

  // --- Sub-step: Recalculate depscores with updated reachability ---
  try {
    const { data: pdvsForRescore } = await supabase
      .from('project_dependency_vulnerabilities')
      .select('id, cvss_score, epss_score, cisa_kev, is_reachable, reachability_level, severity')
      .eq('project_id', projectId)
      .eq('extraction_run_id', runId);

    if (pdvsForRescore && pdvsForRescore.length > 0) {
      const { data: projForTier } = await supabase
        .from('projects')
        .select('asset_tier, asset_tier_id')
        .eq('id', projectId)
        .single();
      let rscoreTier: AssetTier = 'EXTERNAL';
      let rscoreTierMult: number | undefined;
      const rawTier = (projForTier as any)?.asset_tier;
      if (rawTier && VALID_TIERS.includes(rawTier)) rscoreTier = rawTier;
      if ((projForTier as any)?.asset_tier_id) {
        const { data: td } = await supabase
          .from('organization_asset_tiers')
          .select('environmental_multiplier')
          .eq('id', (projForTier as any).asset_tier_id)
          .single();
        if (td?.environmental_multiplier != null) rscoreTierMult = Number(td.environmental_multiplier);
      }
      for (const row of pdvsForRescore) {
        const cvss = row.cvss_score ?? (row.severity ? (SEVERITY_TO_CVSS[row.severity] ?? 4.0) : 4.0);
        const newScore = calculateDepscore({
          cvss, epss: row.epss_score ?? 0, cisaKev: row.cisa_kev ?? false,
          isReachable: row.is_reachable ?? false,
          reachabilityLevel: row.reachability_level ?? undefined,
          assetTier: rscoreTier, tierMultiplier: rscoreTierMult,
        });
        const newBase = calculateBaseDepscoreNoReachability({
          cvss, epss: row.epss_score ?? 0, cisaKev: row.cisa_kev ?? false,
          assetTier: rscoreTier, tierMultiplier: rscoreTierMult,
        });
        const { error: rescoreErr } = await supabase.from('project_dependency_vulnerabilities')
          .update({ depscore: newScore, base_depscore_no_reachability: newBase })
          .eq('id', row.id);
        if (rescoreErr) {
          await log.warn('reachability', `depscore rescore write failed for pdv ${row.id}: ${rescoreErr.message}`);
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
    await applyEpdScoringFallback(supabase, projectId, workspaceRoot, log, fpFilterCostUsd, job.jobId);
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

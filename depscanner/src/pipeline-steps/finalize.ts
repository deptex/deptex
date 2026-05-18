/**
 * STEP: Finalize.
 *
 * Atomic Phase 19.3 finalization. Single-transaction RPC:
 *   - Marks deps missing from this run as removed_at = NOW()
 *   - Carries forward PDV user state (status, suppressed, SLA, re_review_reasons) by (dep_name, osv_id)
 *   - Detects re-review triggers (depscore/severity/reachability/KEV/EPSS/direct/env deltas)
 *   - Writes 'detected'/'reopened'/'rereview_triggered' events to project_vulnerability_events
 *   - Carries forward semgrep status (by fingerprint, falls back to tuple) and secret status
 *   - Computes SLA deadlines for newly-detected findings via tier-aware get_effective_sla_policy
 *   - Flips active_extraction_run_id → this run, previous → old active
 *   - Reaps finding rows from any run_id that is neither (new active, previous)
 *   - Returns summary JSONB — used by the CLI for `summary.json.finalize_summary`
 *
 * After the RPC succeeds, also:
 *   - flips project_repositories.status to 'analyzing' (when new direct deps
 *     need populate-dependencies to fan out) or 'ready'
 *   - stamps ast_parsed_at when usage_extraction reported success
 *   - marks the scan job 'completed' (only when status === 'ready' so
 *     Overview / Recent Activity stay in sync)
 *   - persists detected infra_types from the IaC + container scan
 */

import { runStage } from '../pipeline-stage-runner';
import { logStepError, classifyError } from '../with-timeout';
import { updateStep } from '../pipeline-helpers';
import { updateJobStatus } from '../job-db';
import type { ScannerSummary } from '../scanners/orchestrator';
import type { PipelineContext } from '../pipeline-types';

export async function doFinalize(
  ctx: PipelineContext,
  scannerSummary: ScannerSummary | null,
): Promise<unknown> {
  const {
    supabase,
    job,
    projectId,
    organizationId,
    log,
    runId,
    newDepsToPopulate,
    projectDepsCount,
    astParsedSuccessfully,
  } = ctx;

  await updateStep(supabase, projectId, 'uploading');
  await log.info('uploading', 'Updating project status...');

  const status = newDepsToPopulate.length > 0 ? 'analyzing' : 'ready';

  // Phase 19.3: atomic finalization. See file header for the full list of
  // operations the single-transaction RPC performs.
  const finalizeStart = Date.now();
  let finalizeSummary: unknown = null;
  await runStage({
    name: 'finalize',
    // 10min budget. Finalize does mark-removed + carry-forward + trigger
    // detection + lifecycle events + SLA computation + pointer flip + reap
    // in a single transaction. For projects with 100k+ PDVs the carry-
    // forward / reap stages can legitimately take minutes on shared
    // Supabase infra. Original 2min budget caused premature timeouts on
    // large monorepos, leaving the active_extraction_run_id pointer
    // un-flipped and findings invisible until the next successful run.
    timeoutMs: 10 * 60_000,
    severity: 'error',
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    onError: async ({ err }) => {
      await log.error('finalize', `Atomic commit failed: ${(err as Error).message ?? String(err)}`);
      return { rethrow: true };
    },
    fn: async () => {
      const { data: finalizeData, error: finalizeErr } = await supabase.rpc('finalize_extraction', {
        p_job_id: job.jobId ?? null,
        p_project_id: projectId,
        p_extraction_run_id: runId,
      });
      if (finalizeErr) {
        // Persist the original RPC error directly — by the time this
        // re-throws and the runner's catch sees the wrapped Error,
        // classifyError loses the structured Supabase error code. So we
        // write the structured row here BEFORE re-throwing; the runner
        // will then write a second row keyed on the wrapped 'unexpected'
        // shape (matching the prior dual-row behavior of the inline
        // try/catch this stage replaced).
        if (job.jobId) {
          const { code, message, stack } = classifyError(finalizeErr);
          await logStepError(supabase, {
            jobId: job.jobId,
            projectId,
            step: 'finalize',
            code,
            message,
            stack,
            durationMs: Date.now() - finalizeStart,
            severity: 'error',
          });
        }
        await log.error('finalize', `finalize_extraction RPC failed: ${finalizeErr.message}`);
        throw new Error(`finalize_extraction: ${finalizeErr.message}`);
      }
      // RPC returns jsonb (deps_removed, vulns_new, extraction_run_id, etc.).
      // CLI plumbs this into summary.json.finalize_summary; production worker
      // discards it.
      finalizeSummary = finalizeData ?? null;
    },
  });

  // Status writes happen AFTER finalize_extraction succeeds. If the RPC fails,
  // runStage rethrows above and these never run — so the project can't show
  // 'ready' with stale findings while the active_extraction_run_id pointer is
  // still un-flipped.
  await supabase
    .from('project_repositories')
    .update({
      status,
      extraction_step: 'completed',
      extraction_error: null,
      ...(astParsedSuccessfully ? { ast_parsed_at: new Date().toISOString() } : {}),
      updated_at: new Date().toISOString(),
    })
    .eq('project_id', projectId);

  // Mark job completed in sync with repo status so Overview and Repository/Recent Activity never disagree.
  const didUpdateJob = status === 'ready' && !!job.jobId;
  if (didUpdateJob) {
    await updateJobStatus(supabase, job.jobId!, undefined, undefined, 'completed');
  }

  await supabase
    .from('projects')
    .update({
      dependencies_count: projectDepsCount,
      updated_at: new Date().toISOString(),
    })
    .eq('id', projectId)
    .eq('organization_id', organizationId);

  // Post-finalize: write detected infra types onto the projects row. This
  // happens AFTER finalize_extraction returns success (architect-f5: NOT
  // inside the RPC) so a worker crash between finalize and this UPDATE
  // results in infra_types lagging one extraction at most. Acceptable
  // since infra_types feeds UI tiles, not security-critical paths.
  if (scannerSummary && scannerSummary.infraTypes.length > 0) {
    const { error: infraErr } = await supabase
      .from('projects')
      .update({ infra_types: scannerSummary.infraTypes })
      .eq('id', projectId)
      .eq('organization_id', organizationId);
    if (infraErr) {
      await log.warn('iac_scan', `infra_types update failed: ${infraErr.message}`);
    }
  }

  return finalizeSummary;
}

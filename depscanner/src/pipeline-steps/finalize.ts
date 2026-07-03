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

  // Everything below runs AFTER finalize_extraction succeeds (if the RPC fails,
  // runStage rethrows above and none of this runs — so the project can't show
  // 'ready' with stale findings while the active-run pointer is un-flipped).
  //
  // ORDER MATTERS: the project_repositories status write is LAST because it fires
  // the Realtime the overview graph listens on (un-greys the node + triggers a
  // summary re-read). The findings, active-run pointer, job status, AND the
  // recomputed summary must all be committed BEFORE that write, or the frontend
  // reads a stale/zero summary in the gap and the node shows "0 findings" until a
  // manual refresh.

  // Mark the job completed here (only on the 'ready' path — the analyzing path is
  // finished by the backend populate). Ordering: before the recompute keeps the
  // summary's last_scan_at current, and before the status write keeps Overview and
  // Repository/Recent Activity converging together.
  // Guarded: only flip a still-in-flight ('processing') job to 'completed'. The
  // prior unguarded write would silently overwrite a user cancel landing during
  // finalize — cancel sets status='cancelled' on this row WITHOUT rotating
  // machine_id/run_id, so a machine/run guard can't catch it; a status guard
  // can. A recovery requeue (status→'queued') is left intact for the same
  // reason. The worker's post-pipeline completion write makes the equivalent
  // isJobCancelled check, so the two stay consistent.
  const didUpdateJob = status === 'ready' && !!job.jobId;
  if (didUpdateJob) {
    const { data: marked, error: markErr } = await supabase
      .from('scan_jobs')
      .update({ status: 'completed', error: null, completed_at: new Date().toISOString() })
      .eq('id', job.jobId!)
      .eq('status', 'processing')
      .select('id');
    if (markErr) {
      await log.warn('finalize', `scan job completion write failed: ${markErr.message}`);
    } else if (!Array.isArray(marked) || marked.length === 0) {
      await log.warn(
        'finalize',
        'Scan job no longer in-flight (cancelled or requeued during finalize) — left its status untouched',
      );
    }
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

  // Refresh the denormalized overview summary — findings + active-run pointer are
  // committed by finalize_extraction above, so counts are correct now. This MUST
  // precede the status write below (see ORDER MATTERS) so the overview's
  // summary re-read on the 'ready' Realtime event sees fresh counts. Reuses the
  // same security_summary_counts the overview reads. Non-fatal: the scan
  // succeeded; the daily self-heal cron backstops any failure.
  const { error: recomputeErr } = await supabase.rpc('recompute_project_summary', {
    p_project_id: projectId,
  });
  if (recomputeErr) {
    await log.error('finalize', `recompute_project_summary failed: ${recomputeErr.message}`);
  }

  // Status write LAST — flips the node out of "creating" and triggers the overview
  // summary re-read, with everything above already committed. Also stamps
  // last_extracted_at: the authoritative completion path for EVERY scan (worker-
  // owned since the pipeline moved off the backend). Without it, a re-scan whose
  // dependency set is unchanged takes the status='ready' branch (newDepsToPopulate=0),
  // so no populate-dependencies batch runs and the backend's successful>0 stamp
  // never fires — leaving last_extracted_at frozen and the daily/weekly scheduler
  // re-queuing the project every 6-hourly cron tick forever.
  await supabase
    .from('project_repositories')
    .update({
      status,
      extraction_step: 'completed',
      extraction_error: null,
      last_extracted_at: new Date().toISOString(),
      ...(astParsedSuccessfully ? { ast_parsed_at: new Date().toISOString() } : {}),
      updated_at: new Date().toISOString(),
    })
    .eq('project_id', projectId);

  return finalizeSummary;
}

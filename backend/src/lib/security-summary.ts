import { supabase } from './supabase';
import { captureInfraError } from './observability/capture';

/**
 * Recompute the denormalized project_security_summaries row for one project by
 * re-running the live security_summary_counts aggregation for that project (via the
 * recompute_project_summary RPC). Call this — awaited — at the end of every successful
 * finding-state mutation so the org overview reflects the change on the very next load.
 *
 * Non-fatal: a triage click must still succeed even if the recompute fails, so this
 * logs + reports to Sentry but never throws. Drift from a missed/failed recompute is
 * bounded by the daily self-heal cron (recompute_all_project_summaries).
 *
 * Note the `{ error }`-as-value idiom: supabase-js resolves Postgres errors as
 * `{ data, error }` rather than rejecting, so a `.then(undefined, onRejected)` /
 * bare `.catch()` would never fire. The try/catch only guards a genuine throw
 * (e.g. the network layer), which is also reported and swallowed.
 */
export async function recomputeProjectSummary(projectId: string): Promise<void> {
  try {
    const { error } = await supabase.rpc('recompute_project_summary', { p_project_id: projectId });
    if (error) {
      console.error('[security-summary] recompute failed:', projectId, error.message);
      captureInfraError(error, 'security-summary-recompute', { projectId });
    }
  } catch (e: any) {
    console.error('[security-summary] recompute threw:', projectId, e?.message);
    captureInfraError(e, 'security-summary-recompute', { projectId });
  }
}

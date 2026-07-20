// v2.1c: end-of-scan CVE→PDV runtime-confirmation batch.
//
// After a Nuclei scan commits its findings, this wraps the
// confirm_pdvs_from_dast_run RPC — which flips matching
// project_dependency_findings rows to reachability_level='confirmed'
// when a Nuclei finding both resolves to the PDV's dependency and its cve-id
// array intersects the PDV's osv_id / aliases.
//
// Runtime confirmation is a best-effort enrichment layered on top of an
// already-committed scan: a failure here is logged but never fails the
// scan_job (the findings themselves are still valuable).

import type { Storage } from '../storage';

export interface RuntimeConfirmFlip {
  pdv_id: string;
  osv_id: string;
  prior_reachability_level: string;
  new_reachability_level: string;
}

export interface ConfirmPdvsResult {
  confirmed_count: number;
  flips: RuntimeConfirmFlip[];
  /**
   * True when the RPC itself errored. Distinguishes a genuine failure (DB
   * error, migration drift) from a clean run that legitimately matched no
   * PDVs — both otherwise return confirmed_count=0. The caller logs the
   * failure distinctly rather than reporting a misleading "0 confirmed".
   */
  rpc_failed: boolean;
}

/**
 * Invoke confirm_pdvs_from_dast_run for a completed Nuclei run. Never throws —
 * on RPC error it logs a structured line and returns a zero result with
 * `rpc_failed: true`.
 */
export async function confirmPdvsFromDastRun(
  supabase: Storage,
  orgId: string,
  projectId: string,
  dastRunId: string,
): Promise<ConfirmPdvsResult> {
  const { data, error } = await supabase.rpc('confirm_pdvs_from_dast_run', {
    p_project_id: projectId,
    p_dast_run_id: dastRunId,
  });

  if (error) {
    console.error(
      JSON.stringify({
        event: 'dast.runtime_confirm_failed',
        org_id: orgId,
        project_id: projectId,
        dast_run_id: dastRunId,
        error: error.message,
      }),
    );
    return { confirmed_count: 0, flips: [], rpc_failed: true };
  }

  const flips = (Array.isArray(data) ? data : []) as RuntimeConfirmFlip[];
  console.log(
    JSON.stringify({
      event: 'dast.runtime_confirmed',
      org_id: orgId,
      project_id: projectId,
      dast_run_id: dastRunId,
      confirmed_count: flips.length,
      flipped_count: flips.length,
    }),
  );
  return { confirmed_count: flips.length, flips, rpc_failed: false };
}

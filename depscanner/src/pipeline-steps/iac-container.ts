/**
 * STEP: IaC + Container scanning (OPTIONAL).
 *
 * Detects Terraform / Kubernetes / Dockerfile in the cloned tree, runs
 * Checkov for IaC misconfig, runs Trivy config for Dockerfile misconfig,
 * and runs Trivy image on the Dockerfile FINAL-stage base image (with
 * Patch C namespace check for ghcr.io). Non-blocking — failures log a
 * warn step_error and the pipeline continues.
 *
 * Returns the scanner summary so finalize can stamp infra_types onto the
 * projects row after finalize_extraction returns success.
 */

import { runStage } from '../pipeline-stage-runner';
import { runIaCAndContainerScans, type ScannerSummary } from '../scanners/orchestrator';
import type { PipelineContext } from '../pipeline-types';

export async function doIaCContainer(ctx: PipelineContext): Promise<ScannerSummary | null> {
  const { supabase, job, projectId, organizationId, log, workspaceRoot, runId, heartbeat } = ctx;

  let scannerSummary: ScannerSummary | null = null;
  const scannerSummaryResult = await runStage<ScannerSummary | null>({
    name: 'iac_container_scan',
    severity: 'warn',
    omitDuration: true,
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    onError: async ({ err }) => {
      // Top-level orchestrator failure (shouldn't happen — orchestrator
      // catches per-scanner failures internally — but defensive).
      await log.warn('iac_scan', `IaC + container scan failed: ${(err as Error)?.message ?? err}`);
    },
    fn: async () => {
      // Resolve the org's GitHub App installation id once (used by ghcr.io
      // namespace check during container scan). Failure to resolve is OK —
      // the scanner will conservatively skip ghcr.io images.
      let installationId: string | null = null;
      try {
        const { data: orgRow } = await supabase
          .from('organizations')
          .select('github_installation_id')
          .eq('id', organizationId)
          .single();
        installationId =
          (orgRow as { github_installation_id?: string | null } | null)
            ?.github_installation_id ?? null;
      } catch { /* non-fatal */ }

      return await runIaCAndContainerScans({
        supabase: supabase as any,
        projectId,
        organizationId,
        jobId: job.jobId ?? null,
        runId,
        repoPath: workspaceRoot,
        githubInstallationId: installationId,
        logger: {
          info: async (step: string, msg: string) => log.info(step, msg),
          warn: async (step: string, msg: string) => log.warn(step, msg),
        },
        onHeartbeat: async () => {
          if (heartbeat) await heartbeat();
        },
      });
    },
  });
  if (scannerSummaryResult !== undefined) scannerSummary = scannerSummaryResult;
  return scannerSummary;
}

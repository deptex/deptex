/**
 * STEP: IaC↔Code reachability composition (OPTIONAL).
 *
 * Inserted between doIaCContainer and doMaliciousScan, inside the
 * `if (!skipOptionalScans)` block. composeFindings reads PCF + PDV +
 * native bindings written upstream by Phase 6/EPD + doIaCContainer and
 * folds the resulting per-PDV multiplier into PDV.contextual_depscore
 * via the apply_composition_results RPC.
 *
 * Early-returns when:
 *   - doIaCContainer returned null (failure or skipped)
 *   - no PCF rows exist for runId (also implies no language bindings)
 *
 * Soft-fail: composition failures never abort the scan. runStage logs
 * the failure under `composition` step and continues to malicious-scan.
 */

import { runStage } from '../pipeline-stage-runner';
import { composeFindings, type ComposeFindingsSummary } from '../scanners/composition';
import type { ScannerSummary } from '../scanners/orchestrator';
import type { PipelineContext } from '../pipeline-types';

export async function doComposition(
  ctx: PipelineContext,
  iacContainerSummary: ScannerSummary | null
): Promise<ComposeFindingsSummary | null> {
  const { supabase, job, projectId, organizationId, runId, log } = ctx;

  // Early-return: if doIaCContainer produced no container findings, there
  // are no PCFs to pair against. Mirrors the soft-fail pattern; cheap
  // round-trip avoidance for DEPTEX_SKIP_OPTIONAL_SCANS=1 corpus runs.
  if (iacContainerSummary === null) {
    return null;
  }
  if (iacContainerSummary.containerFindingsWritten === 0) {
    await log.info(
      'composition',
      'No container findings written — skipping composition'
    );
    return null;
  }

  let summary: ComposeFindingsSummary | null = null;
  const result = await runStage<ComposeFindingsSummary | null>({
    name: 'composition',
    severity: 'warn',
    omitDuration: true,
    supabase,
    jobId: job.jobId,
    projectId,
    log,
    onError: async ({ err }) => {
      await log.warn(
        'composition',
        `composition failed: ${(err as Error)?.message ?? err}`
      );
    },
    fn: async () => {
      return await composeFindings({
        supabase: supabase as any,
        projectId,
        organizationId,
        runId,
        logger: {
          info: async (step: string, msg: string) => log.info(step, msg),
          warn: async (step: string, msg: string) => log.warn(step, msg),
        },
      });
    },
  });
  if (result !== undefined) summary = result;
  return summary;
}

/**
 * Per-scan AI telemetry + per-scan cost-cap enforcement.
 *
 * Wraps the `scan_jobs.ai_*` columns + `add_scan_job_ai_usage` RPC added
 * in phase33. Two responsibilities:
 *
 *  1. `recordScanJobAiUsage()` — POST-call: roll an AI call's tokens +
 *     cost into the scan's running total + per-model breakdown.
 *     Atomic via SQL function (concurrent rule-gen + fp-filter +
 *     epd-fallback calls don't lose updates).
 *
 *  2. `checkScanJobCostCap()` — PRE-call: returns whether the next call
 *     would exceed the per-scan cap. Caller emits a structured
 *     `ai_cost_cap_exceeded` extraction_step_errors row and aborts.
 *
 * Per-scan cap is the SECOND ceiling on top of:
 *  - organization_reachability_settings.monthly_budget_usd (org-month, rule-gen)
 *  - taint_engine_settings.monthly_ai_cost_cap_usd (org-month, fp-filter)
 *
 * Caller responsibility — this module:
 *  - Never throws on telemetry failures (rollup is non-fatal; a Supabase
 *    blip should not abort an extraction).
 *  - Returns a structured `capExceeded` flag so callers control the
 *    abort path themselves (some sites want to log + degrade, others
 *    abort the whole step).
 *
 * jobId is OPTIONAL on every entry point: in CLI mode (`depscanner scan`)
 * no scan_jobs row exists, so we just return `{ capExceeded: false }`
 * and don't touch the DB.
 */

import type { Storage } from './storage';
import { logStepError } from './with-timeout';

export interface RecordScanJobAiUsageArgs {
  jobId: string | undefined;
  organizationId: string;
  provider: string;
  model: string;
  promptTokens: number;
  completionTokens: number;
  costUsd: number;
}

export interface RecordScanJobAiUsageResult {
  /** True if the post-rollup running total now exceeds the per-scan cap.
   *  Caller uses this for "abort the NEXT call" semantics — the just-made
   *  call already incurred its spend. */
  capExceeded: boolean;
  /** New running total after the rollup. NaN when telemetry write failed. */
  newTotalUsd: number;
}

/**
 * Atomically merge an AI call's tokens + cost into the scan row, then
 * compare the new running total against the per-scan cap. Telemetry
 * write failures are swallowed (logged via console.warn) so a Supabase
 * blip on the rollup doesn't poison the extraction.
 */
export async function recordScanJobAiUsage(
  storage: Storage,
  args: RecordScanJobAiUsageArgs,
): Promise<RecordScanJobAiUsageResult> {
  if (!args.jobId) {
    return { capExceeded: false, newTotalUsd: 0 };
  }
  try {
    const { data, error } = await storage.rpc<number>('add_scan_job_ai_usage', {
      p_job_id: args.jobId,
      p_organization_id: args.organizationId,
      p_provider: args.provider,
      p_model: args.model,
      p_prompt_tokens: Math.max(0, Math.floor(args.promptTokens || 0)),
      p_completion_tokens: Math.max(0, Math.floor(args.completionTokens || 0)),
      p_cost_usd: Number((args.costUsd || 0).toFixed(6)),
    });
    if (error) {
      console.warn(
        `[ai-telemetry] add_scan_job_ai_usage failed for job ${args.jobId}: ${(error as { message?: string }).message ?? String(error)}`,
      );
      return { capExceeded: false, newTotalUsd: Number.NaN };
    }
    const newTotal = typeof data === 'number' ? data : Number(data ?? 0);
    // We do a second tiny read to check the cap; SECURITY DEFINER RPC
    // could return the cap too but keeping the function signature stable
    // means future cap fields land in this read-side check, not in a
    // multi-arg RPC return.
    const cap = await readScanJobCap(storage, args.jobId);
    const capExceeded = cap !== null && newTotal > cap;
    return { capExceeded, newTotalUsd: newTotal };
  } catch (err) {
    console.warn(
      `[ai-telemetry] add_scan_job_ai_usage threw for job ${args.jobId}: ${err instanceof Error ? err.message : String(err)}`,
    );
    return { capExceeded: false, newTotalUsd: Number.NaN };
  }
}

/**
 * Pre-call gate. Returns true iff the projected NEXT call would push
 * (current total + projected cost) past the per-scan cap. NULL cap
 * means "no per-scan cap" (only the monthly cap applies).
 */
export async function checkScanJobCostCap(
  storage: Storage,
  jobId: string | undefined,
  projectedCostUsd: number,
): Promise<{ wouldExceed: boolean; cap: number | null; currentTotal: number }> {
  if (!jobId) return { wouldExceed: false, cap: null, currentTotal: 0 };
  try {
    const { data, error } = await storage
      .from<{ ai_total_cost_usd: number | string | null; ai_cost_cap_usd: number | string | null }>('scan_jobs')
      .select('ai_total_cost_usd, ai_cost_cap_usd')
      .eq('id', jobId)
      .maybeSingle();
    if (error || !data) return { wouldExceed: false, cap: null, currentTotal: 0 };
    const currentTotal = Number(data.ai_total_cost_usd ?? 0) || 0;
    const cap = data.ai_cost_cap_usd === null || data.ai_cost_cap_usd === undefined
      ? null
      : Number(data.ai_cost_cap_usd);
    if (cap === null || !Number.isFinite(cap)) return { wouldExceed: false, cap: null, currentTotal };
    return { wouldExceed: currentTotal + Math.max(0, projectedCostUsd) > cap, cap, currentTotal };
  } catch (err) {
    console.warn(
      `[ai-telemetry] checkScanJobCostCap failed for job ${jobId}: ${err instanceof Error ? err.message : String(err)}`,
    );
    return { wouldExceed: false, cap: null, currentTotal: 0 };
  }
}

async function readScanJobCap(storage: Storage, jobId: string): Promise<number | null> {
  try {
    const { data, error } = await storage
      .from<{ ai_cost_cap_usd: number | string | null }>('scan_jobs')
      .select('ai_cost_cap_usd')
      .eq('id', jobId)
      .maybeSingle();
    if (error || !data) return null;
    const cap = data.ai_cost_cap_usd;
    if (cap === null || cap === undefined) return null;
    const n = Number(cap);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

/**
 * Emit a structured `ai_cost_cap_exceeded` row into extraction_step_errors
 * so the admin extraction-failures UI surfaces it. Wraps logStepError so
 * callers don't have to duplicate the boilerplate.
 *
 * `severity` defaults to `warn` because the pipeline still continues —
 * the offending step degrades to "AI bypassed; running deterministic
 * only" rather than failing the whole extraction.
 */
export async function logScanJobCostCapExceeded(
  storage: Storage,
  args: {
    jobId: string;
    projectId: string;
    step: string;
    cap: number;
    currentTotal: number;
    projectedCost: number;
    provider: string;
    model: string;
  },
): Promise<void> {
  await logStepError(storage, {
    jobId: args.jobId,
    projectId: args.projectId,
    step: args.step,
    code: 'ai_cost_cap_exceeded',
    message:
      `Per-scan AI cost cap exhausted for ${args.step}: cap=$${args.cap.toFixed(4)} ` +
      `current=$${args.currentTotal.toFixed(4)} projected_next=$${args.projectedCost.toFixed(4)} ` +
      `provider=${args.provider} model=${args.model}. Step degraded; remaining AI calls skipped.`,
    severity: 'warn',
  });
}

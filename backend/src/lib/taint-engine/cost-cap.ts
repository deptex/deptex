/**
 * Per-org cost-cap enforcement for the taint engine's AI features.
 *
 * Reads taint_engine_settings.monthly_ai_cost_cap_usd as the cap, then
 * sums the current calendar month's ai_usage_logs.estimated_cost where
 * feature ∈ ('taint_engine_spec_inference', 'taint_engine_fp_filter').
 * Returns the remaining budget so callers can decide whether to proceed.
 *
 * Used pre-call by:
 *   - inferFrameworkSpec route handler (spec inference)
 *   - M7's per-flow FP filter
 */

import { supabase } from '../supabase';
import { DEFAULT_MONTHLY_AI_COST_CAP_USD } from '../taint-engine-defaults';

const FEATURES = ['taint_engine_spec_inference', 'taint_engine_fp_filter'] as const;

export interface CostCapState {
  capUsd: number;
  spentUsdThisMonth: number;
  remainingUsd: number;
  /** True when the cap has been blown; false otherwise. */
  exceeded: boolean;
}

export async function getCostCapState(organizationId: string): Promise<CostCapState> {
  // Cap defaults to DEFAULT_MONTHLY_AI_COST_CAP_USD if no row exists yet —
  // single source of truth shared with the route synthesizer + frontend so
  // the migration default and the synthesized fallback never diverge.
  const { data: settingsRow } = await supabase
    .from('taint_engine_settings')
    .select('monthly_ai_cost_cap_usd')
    .eq('organization_id', organizationId)
    .maybeSingle();
  const capUsd = Number((settingsRow as { monthly_ai_cost_cap_usd?: number } | null)?.monthly_ai_cost_cap_usd ?? DEFAULT_MONTHLY_AI_COST_CAP_USD);

  // Spend this calendar month — reuse the same boundary getAIUsageSummary
  // implies (start of UTC current month).
  const start = new Date();
  start.setUTCDate(1);
  start.setUTCHours(0, 0, 0, 0);

  const { data: logs } = await supabase
    .from('ai_usage_logs')
    .select('estimated_cost, feature')
    .eq('organization_id', organizationId)
    .eq('success', true)
    .in('feature', FEATURES as unknown as string[])
    .gte('created_at', start.toISOString());

  let spent = 0;
  for (const row of (logs ?? []) as Array<{ estimated_cost: string | number }>) {
    const v = typeof row.estimated_cost === 'number' ? row.estimated_cost : parseFloat(row.estimated_cost);
    if (Number.isFinite(v)) spent += v;
  }

  const remaining = Math.max(0, capUsd - spent);
  return {
    capUsd,
    spentUsdThisMonth: spent,
    remainingUsd: remaining,
    exceeded: spent >= capUsd,
  };
}

/**
 * Hard pre-call check: throws CostCapExceededError if calling now would
 * exceed the cap. Use the projected-cost overload when the caller knows
 * a per-call estimate (FP filter); use no projection for spec inference
 * (a single call is a few cents at worst).
 */
export class CostCapExceededError extends Error {
  constructor(public readonly state: CostCapState, public readonly projectedAdditionalUsd: number) {
    super(
      `taint engine AI cost cap exceeded: $${state.spentUsdThisMonth.toFixed(4)} spent of $${state.capUsd.toFixed(2)} cap, projected +$${projectedAdditionalUsd.toFixed(4)}`,
    );
    this.name = 'CostCapExceededError';
  }
}

export async function assertWithinCostCap(organizationId: string, projectedAdditionalUsd = 0): Promise<CostCapState> {
  const state = await getCostCapState(organizationId);
  if (state.spentUsdThisMonth + projectedAdditionalUsd > state.capUsd) {
    throw new CostCapExceededError(state, projectedAdditionalUsd);
  }
  return state;
}

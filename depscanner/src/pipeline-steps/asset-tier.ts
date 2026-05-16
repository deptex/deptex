/**
 * Helper: fetch the project's asset tier + per-org tier multiplier once before
 * depscore-touching steps run (vuln_scan, semgrep, trufflehog).
 *
 * Not a runStage step because it does not log, has no timeout, has no failure
 * mode worth persisting (a missing row degrades to default tier silently).
 * Mutates ctx.assetTier + ctx.tierMultiplier.
 */

import type { AssetTier } from '../depscore';
import type { PipelineContext } from '../pipeline-types';

const VALID_ASSET_TIERS: AssetTier[] = ['CROWN_JEWELS', 'EXTERNAL', 'INTERNAL', 'NON_PRODUCTION'];

export async function loadAssetTier(ctx: PipelineContext): Promise<void> {
  const { supabase, projectId } = ctx;
  let assetTier: AssetTier = 'EXTERNAL';
  let tierMultiplier: number | undefined;

  const { data: projRow, error: projErr } = await supabase
    .from('projects')
    .select('asset_tier, asset_tier_id')
    .eq('id', projectId)
    .maybeSingle();
  if (projErr) {
    console.warn(`[asset-tier] Failed to load project asset tier for ${projectId}; defaulting to EXTERNAL:`, projErr.message);
  }
  const raw = (projRow as { asset_tier?: string; asset_tier_id?: string } | null)?.asset_tier;
  if (raw && VALID_ASSET_TIERS.includes(raw as AssetTier)) assetTier = raw as AssetTier;

  const tierIdVal = (projRow as { asset_tier_id?: string } | null)?.asset_tier_id;
  if (tierIdVal) {
    const { data: tierData, error: tierErr } = await supabase
      .from('organization_asset_tiers')
      .select('environmental_multiplier')
      .eq('id', tierIdVal)
      .maybeSingle();
    if (tierErr) {
      console.warn(`[asset-tier] Failed to load tier multiplier for ${tierIdVal}; depscore uses default multiplier:`, tierErr.message);
    }
    if (tierData?.environmental_multiplier != null) {
      tierMultiplier = Number(tierData.environmental_multiplier);
    }
  }

  ctx.assetTier = assetTier;
  ctx.tierMultiplier = tierMultiplier;
}

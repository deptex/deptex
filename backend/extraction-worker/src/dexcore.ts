/**
 * Dexcore: context-aware vulnerability score (0–100).
 * Same formula as frontend lib/scoring/dexcore.ts for consistency.
 */

export type AssetTier = 'CROWN_JEWELS' | 'EXTERNAL' | 'INTERNAL' | 'NON_PRODUCTION';

export interface DexcoreContext {
  cvss: number;
  epss: number;
  cisaKev: boolean;
  isReachable: boolean;
  assetTier: AssetTier;
}

const TIER_WEIGHT: Record<AssetTier, number> = {
  CROWN_JEWELS: 1.3,
  EXTERNAL: 1.1,
  INTERNAL: 0.9,
  NON_PRODUCTION: 0.6,
};

const REACHABILITY_WEIGHT_UNREACHABLE: Record<AssetTier, number> = {
  CROWN_JEWELS: 0.8,
  EXTERNAL: 0.5,
  INTERNAL: 0.3,
  NON_PRODUCTION: 0.1,
};

export function calculateDexcore(context: DexcoreContext): number {
  const cvss = Math.max(0, Math.min(10, context.cvss));
  const epss = Math.max(0, Math.min(1, context.epss));

  const baseImpact = cvss * 10;

  const threatMultiplier = context.cisaKev
    ? 1.2
    : 0.6 + 0.6 * Math.sqrt(epss);

  const tierWeight = TIER_WEIGHT[context.assetTier];
  const reachabilityWeight = context.isReachable
    ? 1.0
    : REACHABILITY_WEIGHT_UNREACHABLE[context.assetTier];

  const environmentalMultiplier = tierWeight * reachabilityWeight;
  const rawScore = baseImpact * threatMultiplier * environmentalMultiplier;

  return Math.min(100, Math.round(rawScore));
}

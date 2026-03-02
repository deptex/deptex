/**
 * Depscore: context-aware vulnerability score (0–100).
 * Supports both legacy 4-tier enum and custom tier multipliers from organization_asset_tiers.
 * Matches backend extraction-worker depscore formula.
 */

export type AssetTier = 'CROWN_JEWELS' | 'EXTERNAL' | 'INTERNAL' | 'NON_PRODUCTION';

export interface DepscoreContext {
  cvss: number;       // 0–10
  epss: number;       // 0–1
  cisaKev: boolean;
  isReachable: boolean;
  assetTier: AssetTier;
  tierMultiplier?: number;
  tierRank?: number;
  isDirect?: boolean;
  isDevDependency?: boolean;
  isMalicious?: boolean;
  packageScore?: number | null;
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

function packageReputationWeight(score: number | null | undefined): number {
  if (score == null) return 1.0;
  if (score < 30) return 1.15;
  if (score > 70) return 0.95;
  return 1.0;
}

export function calculateDepscore(context: DepscoreContext): number {
  const cvss = Math.max(0, Math.min(10, context.cvss));
  const epss = Math.max(0, Math.min(1, context.epss));

  const baseImpact = cvss * 10;

  const threatMultiplier = context.cisaKev
    ? 1.2
    : 0.6 + 0.6 * Math.sqrt(epss);

  const tierWeight = context.tierMultiplier ?? TIER_WEIGHT[context.assetTier];

  const reachabilityWeight = context.isReachable
    ? 1.0
    : context.tierMultiplier != null
      ? 0.1 + 0.7 * (context.tierMultiplier / 1.5)
      : REACHABILITY_WEIGHT_UNREACHABLE[context.assetTier];

  const environmentalMultiplier = tierWeight * reachabilityWeight;

  const directnessWeight = context.isDirect === false ? 0.75 : 1.0;
  const envWeight = context.isDevDependency === true ? 0.4 : 1.0;
  const maliciousWeight = context.isMalicious === true ? 1.3 : 1.0;
  const reputationWeight = packageReputationWeight(context.packageScore);
  const dependencyContextMultiplier = directnessWeight * envWeight * maliciousWeight * reputationWeight;

  const rawScore = baseImpact * threatMultiplier * environmentalMultiplier * dependencyContextMultiplier;

  return Math.min(100, Math.round(rawScore));
}

/** Map severity label to CVSS when cvss_score is not available. */
export const SEVERITY_TO_CVSS: Record<string, number> = {
  critical: 9.0,
  high: 7.0,
  medium: 4.0,
  low: 2.0,
};

/**
 * Depscore: context-aware vulnerability score (0–100).
 * Uses 4-tier asset criticality + dependency context (directness, environment, malicious, reputation).
 */

export type AssetTier = 'CROWN_JEWELS' | 'EXTERNAL' | 'INTERNAL' | 'NON_PRODUCTION';

export interface DepscoreContext {
  cvss: number;
  epss: number;
  cisaKev: boolean;
  isReachable: boolean;
  assetTier: AssetTier;
  isDirect?: boolean;
  isDevDependency?: boolean;
  isMalicious?: boolean;
  packageScore?: number | null;
}

export const SEVERITY_TO_CVSS: Record<string, number> = {
  critical: 9.0,
  high: 7.0,
  medium: 4.0,
  low: 2.0,
};

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

export function calculateDepscore(ctx: DepscoreContext): number {
  const cvss = Math.max(0, Math.min(10, ctx.cvss));
  const epss = Math.max(0, Math.min(1, ctx.epss));

  const baseImpact = cvss * 10;

  const threatMultiplier = ctx.cisaKev
    ? 1.2
    : 0.6 + 0.6 * Math.sqrt(epss);

  const tierWeight = TIER_WEIGHT[ctx.assetTier];
  const reachabilityWeight = ctx.isReachable
    ? 1.0
    : REACHABILITY_WEIGHT_UNREACHABLE[ctx.assetTier];
  const environmentalMultiplier = tierWeight * reachabilityWeight;

  // Dependency context multiplier (new fields are optional for backward compat)
  const directnessWeight = ctx.isDirect === false ? 0.75 : 1.0;
  const envWeight = ctx.isDevDependency === true ? 0.4 : 1.0;
  const maliciousWeight = ctx.isMalicious === true ? 1.3 : 1.0;
  const reputationWeight = packageReputationWeight(ctx.packageScore);
  const dependencyContextMultiplier = directnessWeight * envWeight * maliciousWeight * reputationWeight;

  const score = baseImpact * threatMultiplier * environmentalMultiplier * dependencyContextMultiplier;
  return Math.min(100, Math.round(score));
}

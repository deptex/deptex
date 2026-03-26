/**
 * Depscore: context-aware vulnerability score (0–100).
 * Supports both legacy 4-tier enum and custom tier multipliers from organization_asset_tiers.
 */

export type AssetTier = 'CROWN_JEWELS' | 'EXTERNAL' | 'INTERNAL' | 'NON_PRODUCTION';

export interface DepscoreContext {
  cvss: number;
  epss: number;
  cisaKev: boolean;
  isReachable: boolean;
  reachabilityLevel?: string;
  assetTier: AssetTier;
  tierMultiplier?: number;
  tierRank?: number;
  isDirect?: boolean;
  isDevDependency?: boolean;
  isMalicious?: boolean;
  packageScore?: number | null;
}

export interface BaseDepscoreContext {
  cvss: number;
  epss: number;
  cisaKev: boolean;
  assetTier: AssetTier;
  tierMultiplier?: number;
  isDirect?: boolean;
  isDevDependency?: boolean;
  isMalicious?: boolean;
  packageScore?: number | null;
}

const REACHABILITY_LEVEL_WEIGHTS: Record<string, number> = {
  confirmed: 1.0,
  data_flow: 0.9,
  function: 0.7,
  module: 0.5,
};

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

/** Unreachable vulns are heavily discounted (not used in code). Same for all tiers. */
const REACHABILITY_WEIGHT_UNREACHABLE = 0.2;

function packageReputationWeight(score: number | null | undefined): number {
  if (score == null) return 1.0;
  if (score < 30) return 1.15;
  if (score > 70) return 0.95;
  return 1.0;
}

function computeBaseImpactAndMultipliers(ctx: BaseDepscoreContext): { baseImpact: number; threatMultiplier: number; dependencyContextMultiplier: number; tierWeight: number } {
  const cvss = Math.max(0, Math.min(10, ctx.cvss));
  const epss = Math.max(0, Math.min(1, ctx.epss));

  const baseImpact = cvss * 10;
  const threatMultiplier = ctx.cisaKev
    ? 1.2
    : 0.6 + 0.6 * Math.sqrt(epss);

  const tierWeight = ctx.tierMultiplier ?? TIER_WEIGHT[ctx.assetTier];

  const directnessWeight = ctx.isDirect === false ? 0.75 : 1.0;
  const envWeight = ctx.isDevDependency === true ? 0.4 : 1.0;
  const maliciousWeight = ctx.isMalicious === true ? 1.3 : 1.0;
  const reputationWeight = packageReputationWeight(ctx.packageScore);
  const dependencyContextMultiplier = directnessWeight * envWeight * maliciousWeight * reputationWeight;

  return {
    baseImpact,
    threatMultiplier,
    dependencyContextMultiplier,
    tierWeight,
  };
}

export function calculateBaseDepscoreNoReachability(ctx: BaseDepscoreContext): number {
  const { baseImpact, threatMultiplier, dependencyContextMultiplier, tierWeight } = computeBaseImpactAndMultipliers(ctx);
  const score = baseImpact * threatMultiplier * tierWeight * dependencyContextMultiplier;
  return Math.min(100, Math.round(score));
}

export function calculateDepscore(ctx: DepscoreContext): number {
  const { baseImpact, threatMultiplier, dependencyContextMultiplier, tierWeight } = computeBaseImpactAndMultipliers(ctx);

  let reachabilityWeight: number;
  if (ctx.reachabilityLevel && ctx.reachabilityLevel !== 'unreachable') {
    reachabilityWeight = REACHABILITY_LEVEL_WEIGHTS[ctx.reachabilityLevel] ?? 0.5;
  } else if (ctx.reachabilityLevel === 'unreachable' || !ctx.isReachable) {
    reachabilityWeight = REACHABILITY_WEIGHT_UNREACHABLE;
  } else {
    reachabilityWeight = 1.0;
  }

  const score = baseImpact * threatMultiplier * tierWeight * reachabilityWeight * dependencyContextMultiplier;
  return Math.min(100, Math.round(score));
}

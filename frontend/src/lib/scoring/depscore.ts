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
  /** Phase 6B: tiered reachability (confirmed, data_flow, function, module, unreachable). */
  reachabilityLevel?: string | null;
  assetTier: AssetTier;
  tierMultiplier?: number;
  tierRank?: number;
  isDirect?: boolean;
  isDevDependency?: boolean;
  isMalicious?: boolean;
  packageScore?: number | null;
}

/** Reachability level weights (must match extraction-worker). */
const REACHABILITY_LEVEL_WEIGHTS: Record<string, number> = {
  confirmed: 1.0,
  data_flow: 0.9,
  function: 0.7,
  module: 0.5,
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

export function calculateDepscore(context: DepscoreContext): number {
  const cvss = Math.max(0, Math.min(10, context.cvss));
  const epss = Math.max(0, Math.min(1, context.epss));

  const baseImpact = cvss * 10;

  const threatMultiplier = context.cisaKev
    ? 1.2
    : 0.6 + 0.6 * Math.sqrt(epss);

  const tierWeight = context.tierMultiplier ?? TIER_WEIGHT[context.assetTier];

  let reachabilityWeight: number;
  if (context.reachabilityLevel && context.reachabilityLevel !== 'unreachable') {
    reachabilityWeight = REACHABILITY_LEVEL_WEIGHTS[context.reachabilityLevel] ?? 0.5;
  } else if (context.reachabilityLevel === 'unreachable' || context.isReachable === false) {
    reachabilityWeight = REACHABILITY_WEIGHT_UNREACHABLE;
  } else {
    reachabilityWeight = 1.0;
  }

  const environmentalMultiplier = tierWeight * reachabilityWeight;

  const directnessWeight = context.isDirect === false ? 0.75 : 1.0;
  const envWeight = context.isDevDependency === true ? 0.4 : 1.0;
  const maliciousWeight = context.isMalicious === true ? 1.3 : 1.0;
  const reputationWeight = packageReputationWeight(context.packageScore);
  const dependencyContextMultiplier = directnessWeight * envWeight * maliciousWeight * reputationWeight;

  const rawScore = baseImpact * threatMultiplier * environmentalMultiplier * dependencyContextMultiplier;

  return Math.min(100, Math.round(rawScore));
}

/** Human-readable breakdown of how depscore was computed (for sidebar/UI). */
export interface DepscoreBreakdown {
  baseImpact: number;
  threatMultiplier: number;
  threatLabel: string;
  tierWeight: number;
  reachabilityWeight: number;
  reachabilityLabel: string;
  environmentalMultiplier: number;
  directnessWeight: number;
  envWeight: number;
  maliciousWeight: number;
  reputationWeight: number;
  dependencyContextMultiplier: number;
  rawScore: number;
  finalScore: number;
}

export function getDepscoreBreakdown(context: DepscoreContext): DepscoreBreakdown {
  const cvss = Math.max(0, Math.min(10, context.cvss));
  const epss = Math.max(0, Math.min(1, context.epss));
  const baseImpact = cvss * 10;

  const threatMultiplier = context.cisaKev
    ? 1.2
    : 0.6 + 0.6 * Math.sqrt(epss);
  const threatLabel = context.cisaKev
    ? 'CISA KEV (×1.2)'
    : `EPSS ${(epss * 100).toFixed(1)}% (×${threatMultiplier.toFixed(2)})`;

  const tierWeight = context.tierMultiplier ?? TIER_WEIGHT[context.assetTier];

  let reachabilityWeight: number;
  let reachabilityLabel: string;
  if (context.reachabilityLevel && context.reachabilityLevel !== 'unreachable') {
    reachabilityWeight = REACHABILITY_LEVEL_WEIGHTS[context.reachabilityLevel] ?? 0.5;
    reachabilityLabel = `${context.reachabilityLevel.replace('_', ' ')} (×${reachabilityWeight.toFixed(2)})`;
  } else if (context.reachabilityLevel === 'unreachable' || context.isReachable === false) {
    reachabilityWeight = REACHABILITY_WEIGHT_UNREACHABLE;
    reachabilityLabel = `Unreachable (×${reachabilityWeight.toFixed(2)})`;
  } else {
    reachabilityWeight = 1.0;
    reachabilityLabel = 'Reachable (×1.0)';
  }

  const environmentalMultiplier = tierWeight * reachabilityWeight;

  const directnessWeight = context.isDirect === false ? 0.75 : 1.0;
  const envWeight = context.isDevDependency === true ? 0.4 : 1.0;
  const maliciousWeight = context.isMalicious === true ? 1.3 : 1.0;
  const reputationWeight = packageReputationWeight(context.packageScore);
  const dependencyContextMultiplier = directnessWeight * envWeight * maliciousWeight * reputationWeight;

  const rawScore = baseImpact * threatMultiplier * environmentalMultiplier * dependencyContextMultiplier;
  const finalScore = Math.min(100, Math.round(rawScore));

  return {
    baseImpact,
    threatMultiplier,
    threatLabel,
    tierWeight,
    reachabilityWeight,
    reachabilityLabel,
    environmentalMultiplier,
    directnessWeight,
    envWeight,
    maliciousWeight,
    reputationWeight,
    dependencyContextMultiplier,
    rawScore,
    finalScore,
  };
}

/** Map severity label to CVSS when cvss_score is not available. */
export const SEVERITY_TO_CVSS: Record<string, number> = {
  critical: 9.0,
  high: 7.0,
  medium: 4.0,
  low: 2.0,
};

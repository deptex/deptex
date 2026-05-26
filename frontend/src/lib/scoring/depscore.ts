/**
 * Depscore: context-aware vulnerability score (0–100).
 *
 * Frontend mirror of `depscanner/src/depscore.ts`. Per-project `importance`
 * (numeric, [0.5, 2.0]) is multiplied directly into the score as `tierWeight`.
 * Replaces the legacy AssetTier enum + custom organization_asset_tiers
 * multiplier (both dropped in phase41).
 */

export interface DepscoreContext {
  cvss: number;       // 0–10
  epss: number;       // 0–1
  cisaKev: boolean;
  isReachable: boolean;
  /** tiered reachability (confirmed, data_flow, function, module, unreachable). */
  reachabilityLevel?: string | null;
  /** Per-project importance multiplier in [0.5, 2.0]. The number IS the depscore multiplier. */
  importance: number;
  isDirect?: boolean;
  isDevDependency?: boolean;
  isMalicious?: boolean;
  packageScore?: number | null;
}

/** Reachability level weights (must match depscanner). */
const REACHABILITY_LEVEL_WEIGHTS: Record<string, number> = {
  confirmed: 1.0,
  data_flow: 0.9,
  function: 0.7,
  module: 0.5,
};

/** Unreachable vulns score to 0 (extractor-confirmed absence). Must match backend depscore.ts. */
const REACHABILITY_WEIGHT_UNREACHABLE = 0.0;

/** Legacy `isReachable === false` (pre-Phase-2 callers). Mild dampening. */
const REACHABILITY_WEIGHT_LEGACY_UNREACHED = 0.2;

function packageReputationWeight(score: number | null | undefined): number {
  if (score == null) return 1.0;
  if (score < 30) return 1.15;
  if (score > 70) return 0.95;
  return 1.0;
}

function clampImportance(value: number): number {
  if (!Number.isFinite(value)) return 1.0;
  return Math.max(0.5, Math.min(2.0, value));
}

export function calculateDepscore(context: DepscoreContext): number {
  const cvss = Math.max(0, Math.min(10, context.cvss));
  const epss = Math.max(0, Math.min(1, context.epss));

  const baseImpact = cvss * 10;

  const threatMultiplier = context.cisaKev
    ? 1.2
    : 0.6 + 0.6 * Math.sqrt(epss);

  const tierWeight = clampImportance(context.importance);

  let reachabilityWeight: number;
  if (context.reachabilityLevel === 'unreachable') {
    reachabilityWeight = REACHABILITY_WEIGHT_UNREACHABLE;
  } else if (context.reachabilityLevel) {
    reachabilityWeight = REACHABILITY_LEVEL_WEIGHTS[context.reachabilityLevel] ?? 0.5;
  } else if (context.isReachable === false) {
    reachabilityWeight = REACHABILITY_WEIGHT_LEGACY_UNREACHED;
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

  const tierWeight = clampImportance(context.importance);

  let reachabilityWeight: number;
  let reachabilityLabel: string;
  if (context.reachabilityLevel === 'unreachable') {
    reachabilityWeight = REACHABILITY_WEIGHT_UNREACHABLE;
    reachabilityLabel = `Unreachable (×${reachabilityWeight.toFixed(2)})`;
  } else if (context.reachabilityLevel) {
    reachabilityWeight = REACHABILITY_LEVEL_WEIGHTS[context.reachabilityLevel] ?? 0.5;
    reachabilityLabel = `${context.reachabilityLevel.replace('_', ' ')} (×${reachabilityWeight.toFixed(2)})`;
  } else if (context.isReachable === false) {
    reachabilityWeight = REACHABILITY_WEIGHT_LEGACY_UNREACHED;
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

/**
 * Color helper for an importance value. Higher importance = redder/stronger;
 * lower importance = muted. Returns Tailwind tokens (no hardcoded hex), per
 * .cursor/skills/frontend-design/SKILL.md.
 */
export function importanceColorClasses(importance: number | null | undefined): {
  text: string;
  bg: string;
  border: string;
  /** Inline-style opacity for a colored dot (scales with the value). */
  dotOpacity: number;
} {
  const v = importance == null || !Number.isFinite(importance)
    ? 1.0
    : Math.max(0.5, Math.min(2.0, importance));
  if (v >= 1.5) {
    return {
      text: 'text-destructive',
      bg: 'bg-destructive/10',
      border: 'border-destructive/40',
      dotOpacity: 1.0,
    };
  }
  if (v >= 1.1) {
    return {
      text: 'text-foreground',
      bg: 'bg-background-subtle',
      border: 'border-border',
      dotOpacity: 0.75,
    };
  }
  if (v >= 0.8) {
    return {
      text: 'text-foreground-secondary',
      bg: 'bg-background-subtle',
      border: 'border-border',
      dotOpacity: 0.5,
    };
  }
  return {
    text: 'text-muted-foreground',
    bg: 'bg-background-subtle',
    border: 'border-border',
    dotOpacity: 0.3,
  };
}

/** Format importance as "1.50" with a fixed precision so badges line up. */
export function formatImportance(importance: number | null | undefined): string {
  const v = importance == null || !Number.isFinite(importance) ? 1.0 : importance;
  return v.toFixed(2);
}

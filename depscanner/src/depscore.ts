/**
 * Depscore: context-aware vulnerability score (0–100).
 *
 * Per-project `importance` (numeric, [0.5, 2.0]) is multiplied directly into
 * the score as `tierWeight`. Replaces the legacy AssetTier enum + custom
 * organization_asset_tiers multiplier (both dropped in phase41).
 */

export interface DepscoreContext {
  cvss: number;
  epss: number;
  cisaKev: boolean;
  isReachable: boolean;
  reachabilityLevel?: string;
  importance: number;
  isDirect?: boolean;
  isDevDependency?: boolean;
  isMalicious?: boolean;
  packageScore?: number | null;
}

export interface BaseDepscoreContext {
  cvss: number;
  epss: number;
  cisaKev: boolean;
  importance: number;
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

/** Explicit `reachabilityLevel === 'unreachable'` — the extractor confirmed
 * the dep is transitive AND no source file imports it. Drops out of the
 * depscore ranking entirely (still visible in the UI). */
const REACHABILITY_WEIGHT_UNREACHABLE = 0.0;

/** Legacy `isReachable === false` — pre-Phase-2 callers and vuln rows that
 * predate the extractor. Mild dampening; we haven't confirmed anything, we
 * just didn't detect a reachable path. */
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

function computeBaseImpactAndMultipliers(ctx: BaseDepscoreContext): { baseImpact: number; threatMultiplier: number; dependencyContextMultiplier: number; tierWeight: number } {
  const cvss = Math.max(0, Math.min(10, ctx.cvss));
  const epss = Math.max(0, Math.min(1, ctx.epss));

  const baseImpact = cvss * 10;
  const threatMultiplier = ctx.cisaKev
    ? 1.2
    : 0.6 + 0.6 * Math.sqrt(epss);

  const tierWeight = clampImportance(ctx.importance);

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
  if (ctx.reachabilityLevel === 'unreachable') {
    reachabilityWeight = REACHABILITY_WEIGHT_UNREACHABLE;
  } else if (ctx.reachabilityLevel) {
    reachabilityWeight = REACHABILITY_LEVEL_WEIGHTS[ctx.reachabilityLevel] ?? 0.5;
  } else if (!ctx.isReachable) {
    reachabilityWeight = REACHABILITY_WEIGHT_LEGACY_UNREACHED;
  } else {
    reachabilityWeight = 1.0;
  }

  const score = baseImpact * threatMultiplier * tierWeight * reachabilityWeight * dependencyContextMultiplier;
  return Math.min(100, Math.round(score));
}

// --- Secret finding depscore ---

/** Detector type weights — higher-impact credential types score higher. */
const DETECTOR_TYPE_WEIGHT: Record<string, number> = {
  AWS: 1.0,
  GCP: 1.0,
  Azure: 1.0,
  PrivateKey: 1.0,
  Stripe: 0.95,
  GitHub: 0.9,
  GitLab: 0.9,
  Postgres: 0.85,
  MySQL: 0.85,
  MongoDB: 0.85,
  Redis: 0.8,
  SendGrid: 0.8,
  Twilio: 0.8,
  Mailgun: 0.8,
  SlackWebhook: 0.7,
  Slack: 0.7,
  URI: 0.5,
};

export interface SecretDepscoreContext {
  detectorType: string;
  isVerified: boolean;
  isCurrent: boolean;
  importance: number;
}

export function calculateSecretDepscore(ctx: SecretDepscoreContext): number {
  const base = ctx.isVerified ? 90 : 60;
  const detectorWeight = DETECTOR_TYPE_WEIGHT[ctx.detectorType] ?? 0.6;
  const currentWeight = ctx.isCurrent ? 1.0 : 0.8;
  const tierWeight = clampImportance(ctx.importance);

  const score = base * detectorWeight * currentWeight * tierWeight;
  return Math.min(100, Math.round(score));
}

// --- Semgrep finding depscore ---

/** CWE prefixes that indicate high-impact vulnerability classes. */
const HIGH_IMPACT_CWE_PREFIXES = [
  'CWE-79',   // XSS
  'CWE-89',   // SQL injection
  'CWE-78',   // OS command injection
  'CWE-94',   // Code injection
  'CWE-502',  // Deserialization
  'CWE-918',  // SSRF
  'CWE-22',   // Path traversal
  'CWE-611',  // XXE
  'CWE-77',   // Command injection
  'CWE-74',   // Injection
];

export interface SemgrepDepscoreContext {
  severity: string;
  cweIds: string[];
  category: string;
  importance: number;
}

export function calculateSemgrepDepscore(ctx: SemgrepDepscoreContext): number {
  let base: number;
  switch (ctx.severity?.toUpperCase()) {
    case 'ERROR': base = 70; break;
    case 'WARNING': base = 45; break;
    case 'INFO': base = 20; break;
    default: base = 30; break;
  }

  // Boost for high-impact CWE classes
  const hasHighImpactCwe = (ctx.cweIds ?? []).some(cwe =>
    HIGH_IMPACT_CWE_PREFIXES.some(prefix => cwe.startsWith(prefix))
  );
  if (hasHighImpactCwe) base += 15;

  // Security category boost
  if (ctx.category === 'security') base += 5;

  const tierWeight = clampImportance(ctx.importance);
  const score = base * tierWeight;
  return Math.min(100, Math.round(score));
}

// --- License violation depscore ---

export interface LicenseDepscoreContext {
  reasons: string[];
  isDirect: boolean;
  isDevDependency: boolean;
  importance: number;
}

export function calculateLicenseDepscore(ctx: LicenseDepscoreContext): number {
  const lower = ctx.reasons.map(r => r.toLowerCase()).join(' ');
  let base: number;
  if (lower.includes('agpl')) {
    base = 80;
  } else if (lower.includes('copyleft') || lower.includes('gpl')) {
    base = 70;
  } else if (lower.includes('malicious') || lower.includes('malware')) {
    base = 95;
  } else if (lower.includes('banned') || lower.includes('blocked')) {
    base = 75;
  } else if (lower.includes('unknown') || lower.includes('no license')) {
    base = 50;
  } else {
    base = 55;
  }

  const directWeight = ctx.isDirect ? 1.0 : 0.75;
  const envWeight = ctx.isDevDependency ? 0.4 : 1.0;
  const tierWeight = clampImportance(ctx.importance);
  const score = base * directWeight * envWeight * tierWeight;
  return Math.min(100, Math.round(score));
}

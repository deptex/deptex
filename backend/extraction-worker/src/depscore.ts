export interface DepscoreContext {
  cvss: number;
  epss: number;
  cisaKev: boolean;
  isReachable: boolean;
  assetCriticality: number; // 1 = Internet Facing, 2 = Internal, 3 = Sandbox
}

export const SEVERITY_TO_CVSS: Record<string, number> = {
  critical: 9.0,
  high: 7.0,
  medium: 4.0,
  low: 2.0,
};

export function calculateDepscore(ctx: DepscoreContext): number {
  const cvss = Math.max(0, Math.min(10, ctx.cvss));
  const epss = Math.max(0, Math.min(1, ctx.epss));
  const tier = Math.max(1, Math.min(3, ctx.assetCriticality));

  const baseImpact = cvss * 10;

  const threatMultiplier = ctx.cisaKev
    ? 1.2
    : 0.6 + 0.6 * Math.sqrt(epss);

  const tierWeight = 1.4 - 0.2 * tier;
  const reachabilityWeight = ctx.isReachable
    ? 1.0
    : 0.7 - 0.2 * tier;
  const environmentalMultiplier = tierWeight * reachabilityWeight;

  const score = baseImpact * threatMultiplier * environmentalMultiplier;
  return Math.min(100, Math.round(score));
}

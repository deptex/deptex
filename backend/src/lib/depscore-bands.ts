/**
 * Depscore-band bucketing — shared by the org and team security-summary endpoints so the
 * "issues" pills (Critical / High / Medium / Low) are computed identically in both places.
 *
 * Bands come from each finding's reachability-aware Depscore (NOT raw CVSS severity), preferring
 * the contextual (EPD-applied) score when present: >= 90 critical / >= 70 high / >= 40 medium /
 * < 40 low. So an unreachable "Critical" CVE correctly lands in a lower band.
 *
 * NOTE: production now does this bucketing in SQL (the `security_summary_counts` RPC —
 * `backend/database/phase47_security_summary_counts_rpc.sql`) to avoid PostgREST row caps. This
 * helper is the canonical reference for the thresholds (guarded by its unit test); keep the two
 * in sync if the bands ever change.
 */

export type DepscoreBand = 'critical' | 'high' | 'medium' | 'low';

export function depscoreBand(score: number): DepscoreBand {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

export interface DepscoreBandCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** Count vulns into depscore bands, preferring contextual_depscore, then depscore, then 0. */
export function countDepscoreBands(
  vulns: Array<{ contextual_depscore?: number | null; depscore?: number | null }>,
): DepscoreBandCounts {
  const counts: DepscoreBandCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of vulns) {
    const score = v.contextual_depscore ?? v.depscore ?? 0;
    counts[depscoreBand(score)]++;
  }
  return counts;
}

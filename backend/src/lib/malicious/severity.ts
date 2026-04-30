import type { MaliciousSeverity } from './types';

/**
 * Severity mapping for malicious-package findings.
 *
 * The schema CHECK is 5-wide (`critical | high | medium | low | info`) for
 * forward compatibility, but v1 produces only three effective levels:
 *
 *   - feed match (OSV / GHSA confirmed-malicious advisory)  ->  critical
 *   - GuardDog ERROR rule hit                              ->  high
 *   - GuardDog WARNING rule hit                            ->  medium
 *
 * Anything else is mapped to `info` rather than rejected — GuardDog's rule
 * set evolves, and an unfamiliar severity should still surface (just not
 * gate on severity-driven UI thresholds).
 */
export function severityForFeedFinding(): MaliciousSeverity {
  return 'critical';
}

export function severityForGuardDogFinding(rawSeverity: string | null | undefined): MaliciousSeverity {
  switch ((rawSeverity ?? '').toUpperCase()) {
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    case 'INFO':
      return 'info';
    default:
      return 'info';
  }
}

const SEVERITY_RANK: Record<MaliciousSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Numeric rank for sorting by severity. Higher = more severe.
 */
export function severityRank(severity: MaliciousSeverity): number {
  return SEVERITY_RANK[severity];
}

/**
 * Highest-severity wins when multiple findings collapse onto the same row
 * (e.g. when picking the `top_finding_id` for the notification indicator).
 */
export function maxSeverity(a: MaliciousSeverity, b: MaliciousSeverity): MaliciousSeverity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

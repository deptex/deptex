/**
 * Auto-triage derivation for dependency vulnerabilities — the backend mirror
 * of the findings table's `autoTriageRow` (frontend/src/components/security/
 * VulnerabilityExpandableTable.tsx). The UI shows these findings as
 * "Auto Ignored", so the Aegis tools must reason with the same verdict or the
 * agent contradicts what the user sees (e.g. opening a fix plan for a CVE the
 * findings table has set aside as not reachable). Keep the two in lockstep.
 *
 * Rules:
 *   - runtime-confirmed (DAST) findings are never set aside
 *   - confirmed / data_flow reachability stay front and center
 *   - unreachable (or is_reachable === false) -> set aside: not reachable
 *   - module-level -> set aside: in the tree but no path to the vulnerable fn
 *   - function-level or no verdict -> not confident enough to set aside
 */

export interface VulnTriageFields {
  runtime_confirmed_at?: string | null;
  reachability_level?: string | null;
  is_reachable?: boolean | null;
}

export type VulnAutoIgnoreReason = 'not_reachable' | 'unconfirmed_reachable';

export function vulnAutoIgnoreReason(v: VulnTriageFields): VulnAutoIgnoreReason | null {
  if (v.runtime_confirmed_at) return null;
  const level = (v.reachability_level ?? '').toLowerCase();
  if (level === 'confirmed' || level === 'data_flow') return null;
  if (level === 'unreachable' || v.is_reachable === false) return 'not_reachable';
  if (level === 'module') return 'unconfirmed_reachable';
  return null;
}

export function autoIgnoreReasonText(reason: VulnAutoIgnoreReason): string {
  return reason === 'not_reachable'
    ? 'reachability analysis found no path from the project code to the vulnerable function'
    : 'the package is in the dependency tree but no execution path reaches the vulnerable function';
}

import type { TeamFindingsBundle, ProjectVulnerability, BaseImageRecommendation } from './api';
import type { SecurityTableRow } from '../components/security/VulnerabilityExpandableTable';

function vulnScore(v: ProjectVulnerability): number {
  const c = (v as any).contextual_depscore;
  if (c != null && Number.isFinite(Number(c))) return Number(c);
  const d = (v as any).depscore;
  if (d != null && Number.isFinite(Number(d))) return Number(d);
  return -1;
}

/**
 * Pure mapper: a team findings bundle → the unified `SecurityTableRow[]` the team
 * Findings table renders (plus the base-image recommendations, which render as their
 * own collapsed rows). Replaces the per-project `loadProjectFindingRows` mapping for
 * the whole team — every finding type maps to a row, and rows arrive already stamped
 * with `project_id`/`project_name` by the server.
 *
 * SCA dedup key is `project_id:dependency_id:osv_id` — `dependency_id` is the GLOBAL
 * `dependencies.id` (shared across projects for the same package@version), so the
 * SAME CVE in two team projects MUST stay two rows; keying on `dependency_id:osv_id`
 * alone would collapse them and hide the finding for all-but-one project.
 */
export function teamBundleToRows(bundle: TeamFindingsBundle): {
  rows: SecurityTableRow[];
  baseImageRecs: BaseImageRecommendation[];
} {
  const rows: SecurityTableRow[] = [];

  const byKey = new Map<string, ProjectVulnerability>();
  for (const v of bundle.vulnerabilities ?? []) {
    const key = `${(v as any).project_id ?? ''}:${v.dependency_id}:${v.osv_id}`;
    const prev = byKey.get(key);
    if (!prev || vulnScore(v) > vulnScore(prev)) byKey.set(key, v);
  }
  for (const v of byKey.values()) rows.push({ type: 'vulnerability', data: v });

  for (const s of bundle.secrets ?? []) rows.push({ type: 'secret', data: s as any });
  for (const s of bundle.semgrep ?? []) rows.push({ type: 'semgrep', data: s as any });
  for (const f of bundle.iac ?? []) rows.push({ type: 'iac', data: f as any });
  for (const f of bundle.container ?? []) rows.push({ type: 'container', data: f as any });
  for (const f of bundle.malicious ?? []) rows.push({ type: 'malicious', data: f as any });
  for (const f of bundle.dast ?? []) rows.push({ type: 'dast', data: f as any });
  for (const f of bundle.codeFlows ?? []) rows.push({ type: 'taint_flow', data: f as any });

  return { rows, baseImageRecs: bundle.baseImageRecs ?? [] };
}

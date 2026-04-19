/**
 * Derive vulnerability counts from dependency_vulnerabilities (version vs affected_versions + severity).
 * Used after dependency_versions.critical_vulns/high_vulns/medium_vulns/low_vulns were removed.
 */

import { SupabaseClient } from '@supabase/supabase-js';
import { isVersionAffected } from './semver-affected';
import {
  fetchGhsaVulnerabilitiesBatch,
  filterGhsaVulnsByVersion,
  ghsaSeverityToLevel,
  type GhsaVuln,
} from './ghsa';

export interface VulnCounts {
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
}

const ZERO: VulnCounts = {
  critical_vulns: 0,
  high_vulns: 0,
  medium_vulns: 0,
  low_vulns: 0,
};

function normalizeSeverity(severity: string | null): 'critical' | 'high' | 'medium' | 'low' {
  if (!severity) return 'medium';
  const s = severity.toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium' || s === 'moderate') return 'medium';
  if (s === 'low') return 'low';
  return 'medium';
}

/**
 * Get vuln counts for a single (dependency_id, version) from dependency_vulnerabilities.
 */
export async function getVulnCountsForVersion(
  supabase: SupabaseClient,
  dependencyId: string,
  version: string
): Promise<VulnCounts> {
  const { data: rows, error } = await supabase
    .from('dependency_vulnerabilities')
    .select('severity, affected_versions')
    .eq('dependency_id', dependencyId);

  if (error || !rows || rows.length === 0) return ZERO;

  const counts = { ...ZERO };
  for (const row of rows as Array<{ severity: string | null; affected_versions: unknown }>) {
    if (!isVersionAffected(version, row.affected_versions)) continue;
    const level = normalizeSeverity(row.severity);
    if (level === 'critical') counts.critical_vulns++;
    else if (level === 'high') counts.high_vulns++;
    else if (level === 'medium') counts.medium_vulns++;
    else counts.low_vulns++;
  }
  return counts;
}

/**
 * Get vuln counts for multiple versions of the same dependency in one query.
 * Returns a Map from version string to VulnCounts.
 */
export async function getVulnCountsForVersionsBatch(
  supabase: SupabaseClient,
  dependencyId: string,
  versions: string[]
): Promise<Map<string, VulnCounts>> {
  const result = new Map<string, VulnCounts>();
  const versionSet = new Set(versions);
  if (versionSet.size === 0) return result;

  const { data: rows, error } = await supabase
    .from('dependency_vulnerabilities')
    .select('severity, affected_versions')
    .eq('dependency_id', dependencyId);

  if (error || !rows) {
    versions.forEach((v) => result.set(v, { ...ZERO }));
    return result;
  }

  const vulnRows = rows as Array<{ severity: string | null; affected_versions: unknown }>;
  for (const version of versionSet) {
    const counts = { ...ZERO };
    for (const row of vulnRows) {
      if (!isVersionAffected(version, row.affected_versions)) continue;
      const level = normalizeSeverity(row.severity);
      if (level === 'critical') counts.critical_vulns++;
      else if (level === 'high') counts.high_vulns++;
      else if (level === 'medium') counts.medium_vulns++;
      else counts.low_vulns++;
    }
    result.set(version, counts);
  }
  return result;
}

/**
 * Get vuln counts for multiple (dependency_id, version) pairs.
 * Key format: `${dependencyId}\t${version}`. Groups by dependency_id to minimize DB round-trips.
 */
export async function getVulnCountsBatch(
  supabase: SupabaseClient,
  pairs: Array<{ dependencyId: string; version: string }>
): Promise<Map<string, VulnCounts>> {
  const result = new Map<string, VulnCounts>();
  if (pairs.length === 0) return result;

  const byDepId = new Map<string, string[]>();
  for (const { dependencyId, version } of pairs) {
    const key = `${dependencyId}\t${version}`;
    result.set(key, { ...ZERO });
    const list = byDepId.get(dependencyId) || [];
    if (!list.includes(version)) list.push(version);
    byDepId.set(dependencyId, list);
  }

  const promises = Array.from(byDepId.entries()).map(([dependencyId, versions]) =>
    getVulnCountsForVersionsBatch(supabase, dependencyId, versions).then((countsMap) => ({
      dependencyId,
      versions,
      countsMap,
    }))
  );
  const resolved = await Promise.all(promises);
  for (const { dependencyId, versions, countsMap } of resolved) {
    for (const version of versions) {
      const key = `${dependencyId}\t${version}`;
      result.set(key, countsMap.get(version) ?? ZERO);
    }
  }
  return result;
}

/**
 * Check if a (dependency_id, version) exceeds the given severity threshold
 * (has any vuln at or above that level).
 */
export function exceedsThreshold(
  counts: VulnCounts,
  severity: 'critical' | 'high' | 'medium' | 'low'
): boolean {
  const c = counts.critical_vulns ?? 0;
  const h = counts.high_vulns ?? 0;
  const m = counts.medium_vulns ?? 0;
  const l = counts.low_vulns ?? 0;
  switch (severity) {
    case 'critical':
      return c > 0;
    case 'high':
      return c + h > 0;
    case 'medium':
      return c + h + m > 0;
    case 'low':
      return c + h + m + l > 0;
    default:
      return c + h > 0;
  }
}

/**
 * Get vuln counts for a package name and version: try DB first (dependencies + dependency_vulnerabilities),
 * then fall back to GHSA on-demand.
 */
export async function getVulnCountsForPackageVersion(
  supabase: SupabaseClient,
  packageName: string,
  version: string
): Promise<VulnCounts> {
  const { data: dep } = await supabase
    .from('dependencies')
    .select('id')
    .eq('name', packageName)
    .single();
  if (dep?.id) {
    const fromDb = await getVulnCountsForVersion(supabase, dep.id, version);
    const hasAny = fromDb.critical_vulns + fromDb.high_vulns + fromDb.medium_vulns + fromDb.low_vulns > 0;
    if (hasAny) return fromDb;
  }
  const ghsaMap = await fetchGhsaVulnerabilitiesBatch([packageName]);
  const vulns: GhsaVuln[] = ghsaMap.get(packageName) ?? [];
  const affecting = filterGhsaVulnsByVersion(vulns, version);
  const counts = { ...ZERO };
  for (const v of affecting) {
    const level = normalizeSeverity(ghsaSeverityToLevel(v.severity));
    if (level === 'critical') counts.critical_vulns++;
    else if (level === 'high') counts.high_vulns++;
    else if (level === 'medium') counts.medium_vulns++;
    else counts.low_vulns++;
  }
  return counts;
}

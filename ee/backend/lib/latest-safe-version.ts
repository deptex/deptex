import semver from 'semver';
import pacote from 'pacote';
import { supabase } from '../../../backend/src/lib/supabase';
import {
  getLatestSafeVersionCacheKey,
  getCached,
  setCached,
  CACHE_TTL_SECONDS,
} from './cache';
import { getVulnCountsForVersionsBatch, getVulnCountsBatch, exceedsThreshold as vulnExceedsThreshold } from '../../../backend/src/lib/vuln-counts';

export interface LatestSafeVersionResponse {
  safeVersion: string | null;
  safeVersionId: string | null;
  isCurrent: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  versionsChecked: number;
  message: string | null;
}

export interface CalculateLatestSafeVersionParams {
  organizationId: string;
  projectId: string;
  projectDependencyId: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  excludeBanned?: boolean;
  /** When true, skip Redis cache and recompute (so security-check changes in DB are reflected). */
  skipCache?: boolean;
}

/**
 * Calculate the latest safe version for a dependency by checking vulnerabilities
 * across versions and their transitive dependencies.
 */
export async function calculateLatestSafeVersion(
  params: CalculateLatestSafeVersionParams
): Promise<LatestSafeVersionResponse> {
  const {
    organizationId,
    projectId,
    projectDependencyId,
    severity = 'high',
    excludeBanned = true,
    skipCache = false,
  } = params;

  const severityParam = severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low';

  // Validate severity param
  const validSeverities = ['critical', 'high', 'medium', 'low'];
  if (!validSeverities.includes(severityParam)) {
    throw new Error('severity must be one of: critical, high, medium, low');
  }

  const cacheKey = getLatestSafeVersionCacheKey(
    organizationId,
    projectId,
    projectDependencyId,
    severityParam,
    excludeBanned
  );
  if (!skipCache) {
    const cached = await getCached<LatestSafeVersionResponse>(cacheKey);
    if (cached !== null) {
      return cached;
    }
  }

  // 1. Get current dependency version from project_dependency
  const { data: pd, error: pdError } = await supabase
    .from('project_dependencies')
    .select('id, name, version, dependency_version_id')
    .eq('id', projectDependencyId)
    .eq('project_id', projectId)
    .single();

  if (pdError || !pd) {
    throw new Error('Project dependency not found');
  }
  const currentVersionId = (pd as any).dependency_version_id;
  if (!currentVersionId) {
    const result: LatestSafeVersionResponse = {
      safeVersion: null,
      safeVersionId: null,
      isCurrent: false,
      severity: severityParam,
      versionsChecked: 0,
      message: 'Dependency version not resolved',
    };
    // Cache this result too (short TTL since it might resolve soon)
    await setCached(cacheKey, result, CACHE_TTL_SECONDS.LATEST_SAFE_VERSION);
    return result;
  }

  // 2. Get dependency_id and package info
  const { data: currentDv, error: dvError } = await supabase
    .from('dependency_versions')
    .select('dependency_id, version')
    .eq('id', currentVersionId)
    .single();

  if (dvError || !currentDv) {
    throw new Error('Dependency version not found');
  }
  const dependencyId = (currentDv as any).dependency_id;
  const currentVersion = (currentDv as any).version;

  const { data: dep, error: depError } = await supabase
    .from('dependencies')
    .select('name, latest_version')
    .eq('id', dependencyId)
    .single();

  if (depError || !dep) {
    throw new Error('Dependency not found');
  }
  const packageName = (dep as any).name;

  // 3. Fetch all versions for this dependency, sort by semver descending
  const { data: allVersionRows, error: versionsError } = await supabase
    .from('dependency_versions')
    .select('id, version')
    .eq('dependency_id', dependencyId);

  if (versionsError) throw versionsError;
  if (!allVersionRows || allVersionRows.length === 0) {
    const result: LatestSafeVersionResponse = {
      safeVersion: null,
      safeVersionId: null,
      isCurrent: false,
      severity: severityParam,
      versionsChecked: 0,
      message: 'No versions found',
    };
    // Cache this result
    await setCached(cacheKey, result, CACHE_TTL_SECONDS.LATEST_SAFE_VERSION);
    return result;
  }

  // Sort by semver descending (latest first); only consider stable releases (no prerelease tags)
  const sortedVersions = (allVersionRows as any[])
    .filter((v) => {
      const coerced = semver.coerce(v.version);
      if (!semver.valid(coerced)) return false;
      return !semver.prerelease(v.version);
    })
    .sort((a, b) => {
      const va = semver.coerce(a.version)!;
      const vb = semver.coerce(b.version)!;
      return semver.rcompare(va, vb);
    });

  // Vuln counts per version (derived from dependency_vulnerabilities)
  const versionStrs = sortedVersions.map((v: any) => v.version);
  const vulnCountsByVersion = await getVulnCountsForVersionsBatch(supabase, dependencyId, versionStrs);

  // Optionally fetch org + team-banned versions to exclude from consideration (by dependency_id)
  let bannedVersionSet: Set<string> | null = null;
  if (excludeBanned) {
    bannedVersionSet = new Set<string>();
    const { data: orgBannedRows } = await supabase
      .from('banned_versions')
      .select('banned_version')
      .eq('organization_id', organizationId)
      .eq('dependency_id', dependencyId);
    if (orgBannedRows && orgBannedRows.length > 0) {
      orgBannedRows.forEach((r: any) => bannedVersionSet!.add(r.banned_version));
    }
    const { data: projectTeams } = await supabase
      .from('project_teams')
      .select('team_id')
      .eq('project_id', projectId);
    const teamIds = (projectTeams ?? []).map((t: any) => t.team_id);
    if (teamIds.length > 0) {
      const { data: teamBannedRows } = await supabase
        .from('team_banned_versions')
        .select('banned_version')
        .in('team_id', teamIds)
        .eq('dependency_id', dependencyId);
      if (teamBannedRows && teamBannedRows.length > 0) {
        teamBannedRows.forEach((r: any) => bannedVersionSet!.add(r.banned_version));
      }
    }
    if (bannedVersionSet.size === 0) {
      bannedVersionSet = null;
    }
  }

  // Watchtower integration: check if this org has the package on watchtower (for quarantine rules)
  let watchlistRow: { quarantine_until: string | null; is_current_version_quarantined: boolean; latest_allowed_version: string | null } | null = null;

  const { data: wlRow } = await supabase
    .from('organization_watchlist')
    .select('quarantine_until, is_current_version_quarantined, latest_allowed_version')
    .eq('organization_id', organizationId)
    .eq('dependency_id', dependencyId)
    .maybeSingle();

  if (wlRow) {
    watchlistRow = wlRow as any;
  }

  // Always load security check statuses for this dependency so we skip versions with any check === 'fail'
  // (even when the org doesn't have the package in Watchtower — e.g. manual DB edits or worker-populated data)
  let securityChecksByVersion: Map<string, { registry_integrity_status: string | null; install_scripts_status: string | null; entropy_analysis_status: string | null }> | null = null;
  const { data: secRows } = await supabase
    .from('dependency_versions')
    .select('version, registry_integrity_status, install_scripts_status, entropy_analysis_status')
    .eq('dependency_id', dependencyId);
  if (secRows && secRows.length > 0) {
    securityChecksByVersion = new Map();
    for (const row of secRows as any[]) {
      securityChecksByVersion.set(row.version, {
        registry_integrity_status: row.registry_integrity_status ?? null,
        install_scripts_status: row.install_scripts_status ?? null,
        entropy_analysis_status: row.entropy_analysis_status ?? null,
      });
    }
  }

  const MAX_VERSIONS_TO_CHECK = 25;
  let versionsChecked = 0;

  // 4. Iterate through versions from latest to oldest
  for (const versionRow of sortedVersions.slice(0, MAX_VERSIONS_TO_CHECK)) {
    versionsChecked++;
    const vId = versionRow.id;
    const vStr = versionRow.version;

    // 4a-pre. Skip banned versions when exclude_banned is set
    if (bannedVersionSet && bannedVersionSet.has(vStr)) {
      continue;
    }

    // 4a-pre2. Watchtower: skip quarantined versions (org-scoped, only when package is in watchlist)
    if (watchlistRow) {
      // If the latest version is currently quarantined, skip it
      if (watchlistRow.is_current_version_quarantined && watchlistRow.quarantine_until) {
        const quarantineExpired = new Date(watchlistRow.quarantine_until) <= new Date();
        if (!quarantineExpired && watchlistRow.latest_allowed_version !== vStr) {
          // This version is newer than the allowed version and quarantine hasn't expired — skip
          if (watchlistRow.latest_allowed_version) {
            const allowed = semver.coerce(watchlistRow.latest_allowed_version);
            const candidate = semver.coerce(vStr);
            if (allowed && candidate && semver.gt(candidate, allowed)) {
              continue;
            }
          }
        }
      }
    }

    // Skip versions with failed critical security checks (always apply when we have check data)
    if (securityChecksByVersion) {
      const checks = securityChecksByVersion.get(vStr);
      if (checks) {
        const hasCriticalFailure =
          checks.registry_integrity_status === 'fail' ||
          checks.install_scripts_status === 'fail' ||
          checks.entropy_analysis_status === 'fail';
        if (hasCriticalFailure) {
          continue;
        }
      }
    }

    // 4a. Check center node vuln counts (from dependency_vulnerabilities)
    const versionCounts = vulnCountsByVersion.get(vStr) ?? { critical_vulns: 0, high_vulns: 0, medium_vulns: 0, low_vulns: 0 };
    if (vulnExceedsThreshold(versionCounts, severityParam)) {
      continue; // This version itself has vulns above threshold
    }

    // 4b. Check transitive dependencies
    let childVersionIds: string[] = [];

    // Check for existing edges
    const { data: edgeRows, error: edgesError } = await supabase
      .from('dependency_version_edges')
      .select('child_version_id')
      .eq('parent_version_id', vId);

    if (edgesError) throw edgesError;
    childVersionIds = (edgeRows || []).map((e: any) => e.child_version_id);

    // If no edges, resolve via pacote and check vulns via GHSA
    if (childVersionIds.length === 0) {
      try {
        const manifest = await pacote.manifest(`${packageName}@${vStr}`, { fullMetadata: false });
        const deps = manifest.dependencies || {};
        const depEntries = Object.entries(deps);

        if (depEntries.length > 0) {
          const edgesToInsert: Array<{ parent_version_id: string; child_version_id: string }> = [];

          for (const [childName, childRange] of depEntries) {
            let resolvedVersion: string;
            try {
              const childManifest = await pacote.manifest(`${childName}@${childRange}`, { fullMetadata: false });
              resolvedVersion = childManifest.version;
            } catch {
              continue;
            }

            // Upsert child dependency
            let childDepId: string | null = null;
            const { data: childDep } = await supabase
              .from('dependencies')
              .upsert({ name: childName }, { onConflict: 'name', ignoreDuplicates: true })
              .select('id')
              .single();

            if (childDep) {
              childDepId = (childDep as any).id;
            } else {
              const { data: existingDep } = await supabase
                .from('dependencies')
                .select('id')
                .eq('name', childName)
                .single();
              if (existingDep) childDepId = (existingDep as any).id;
            }
            if (!childDepId) continue;

            // Upsert child version
            let childVersionId: string | null = null;
            const { data: childDv } = await supabase
              .from('dependency_versions')
              .upsert(
                { dependency_id: childDepId, version: resolvedVersion },
                { onConflict: 'dependency_id,version', ignoreDuplicates: true }
              )
              .select('id')
              .single();

            if (childDv) {
              childVersionId = (childDv as any).id;
            } else {
              const { data: existingDv } = await supabase
                .from('dependency_versions')
                .select('id')
                .eq('dependency_id', childDepId)
                .eq('version', resolvedVersion)
                .single();
              if (existingDv) childVersionId = (existingDv as any).id;
            }
            if (!childVersionId) continue;

            edgesToInsert.push({ parent_version_id: vId, child_version_id: childVersionId });
          }

          // Bulk upsert edges
          if (edgesToInsert.length > 0) {
            await supabase
              .from('dependency_version_edges')
              .upsert(edgesToInsert, { onConflict: 'parent_version_id,child_version_id', ignoreDuplicates: true });
          }

          // Re-fetch edges
          const { data: newEdges } = await supabase
            .from('dependency_version_edges')
            .select('child_version_id')
            .eq('parent_version_id', vId);

          childVersionIds = (newEdges || []).map((e: any) => e.child_version_id);

        } else {
          // Package has no dependencies at all — children are clean
        }
      } catch (pacoteError: any) {
        console.warn(`[safe-version] Pacote error for ${packageName}@${vStr}, treating as no known transitive deps:`, pacoteError.message);
        // Don't skip — if own vulns are clean and we can't resolve deps, still consider it safe
      }
    }

    // 4c. Now check all child version vuln counts (from dependency_vulnerabilities)
    let childrenSafe = true;
    if (childVersionIds.length > 0) {
      const BATCH_SIZE = 100;
      const childDvRows: Array<{ id: string; dependency_id: string; version: string }> = [];
      for (let i = 0; i < childVersionIds.length; i += BATCH_SIZE) {
        const batch = childVersionIds.slice(i, i + BATCH_SIZE);
        const { data: rows, error: childError } = await supabase
          .from('dependency_versions')
          .select('id, dependency_id, version')
          .in('id', batch);
        if (childError) throw childError;
        if (rows) childDvRows.push(...(rows as any));
      }
      const childPairs = childDvRows.map((r) => ({ dependencyId: r.dependency_id, version: r.version }));
      const childCountsMap = await getVulnCountsBatch(supabase, childPairs);
      for (const row of childDvRows) {
        const key = `${row.dependency_id}\t${row.version}`;
        const counts = childCountsMap.get(key) ?? { critical_vulns: 0, high_vulns: 0, medium_vulns: 0, low_vulns: 0 };
        if (vulnExceedsThreshold(counts, severityParam)) {
          childrenSafe = false;
          break;
        }
      }
    }

    if (childrenSafe) {
      // Found a safe version!
      const isCurrent = vId === currentVersionId;
      const result: LatestSafeVersionResponse = {
        safeVersion: vStr,
        safeVersionId: vId,
        isCurrent,
        severity: severityParam,
        versionsChecked,
        message: isCurrent ? 'Current version is the latest safe version' : null,
      };

      // Cache the result
      await setCached(cacheKey, result, CACHE_TTL_SECONDS.LATEST_SAFE_VERSION);

      return result;
    }
  }

  // No safe version found
  const result: LatestSafeVersionResponse = {
    safeVersion: null,
    safeVersionId: null,
    isCurrent: false,
    severity: severityParam,
    versionsChecked,
    message: 'No recent versions meet this criteria',
  };

  // Cache the result
  await setCached(cacheKey, result, CACHE_TTL_SECONDS.LATEST_SAFE_VERSION);

  return result;
}

import express from 'express';
import semver from 'semver';
import { authenticateUser, AuthRequest } from '../middleware/auth';
import { supabase } from '../lib/supabase';
import { getOpenAIClient } from '../lib/openai';
import { createInstallationToken, getCommitDiff, getCommitDiffPublic } from '../lib/github';
import {
  getWatchtowerSummaryCacheKey,
  getCached,
  setCached,
  CACHE_TTL_SECONDS,
} from '../lib/cache';

const router = express.Router();

/**
 * Helper function to check if user has access to view watchtower data for a package
 * Users can view watchtower data if they are members of an organization that has
 * this package in its organization_watchlist (org-level watching)
 */
async function checkWatchtowerAccess(
  userId: string,
  packageName: string,
  projectDependencyId?: string
): Promise<{ hasAccess: boolean; watchedPackageId?: string; dependencyVersionId?: string; error?: { status: number; message: string } }> {
  // Get all organizations the user is a member of
  const { data: memberships, error: memberError } = await supabase
    .from('organization_members')
    .select('organization_id')
    .eq('user_id', userId);

  if (memberError || !memberships || memberships.length === 0) {
    return { hasAccess: false, error: { status: 403, message: 'Access denied' } };
  }

  const orgIds = memberships.map(m => m.organization_id);

  // Resolve dependency_id from dependencies by package name
  const { data: depRow, error: depErr } = await supabase
    .from('dependencies')
    .select('id')
    .eq('name', packageName)
    .limit(1)
    .single();

  if (depErr || !depRow) {
    if (projectDependencyId) {
      console.warn(`[Watchtower Access] package ${packageName} not found in dependencies`);
    }
    return { hasAccess: false, error: { status: 404, message: 'Package not found or not being watched' } };
  }

  const packageDependencyId = (depRow as any).id;

  // Check if any of these organizations have this package in their watchlist (by dependency_id)
  const { data: watchlistRows, error: watchError } = await supabase
    .from('organization_watchlist')
    .select('organization_id')
    .eq('dependency_id', packageDependencyId)
    .in('organization_id', orgIds)
    .limit(1);

  if (watchError || !watchlistRows || watchlistRows.length === 0) {
    if (projectDependencyId) {
      console.warn(`[Watchtower Access] package ${packageName} not in org watchlist or access denied`);
    }
    return { hasAccess: false, error: { status: 404, message: 'Package not found or not being watched' } };
  }

  // Get the watched_packages entry by dependency_id
  const { data: watchedPkgRow, error: pkgError } = await supabase
    .from('watched_packages')
    .select('id')
    .eq('dependency_id', packageDependencyId)
    .limit(1)
    .single();

  const watchedPackageId = (watchedPkgRow as any)?.id;

  if (pkgError || !watchedPackageId) {
    return { hasAccess: false, error: { status: 404, message: 'Package analysis not found' } };
  }

  // Optionally get dependency_version_id from a project dependency in one of these orgs (for status fields)
  let dependencyVersionId: string | undefined;
  let depQuery = supabase
    .from('project_dependencies')
    .select('id, dependency_version_id, projects!inner(organization_id)')
    .eq('name', packageName)
    .in('projects.organization_id', orgIds)
    .limit(1);
  if (projectDependencyId) {
    depQuery = depQuery.eq('id', projectDependencyId);
  }
  const { data: projDepRow } = await depQuery.maybeSingle();
  if (projDepRow && (projDepRow as any).dependency_version_id) {
    dependencyVersionId = (projDepRow as any).dependency_version_id;
  }

  return {
    hasAccess: true,
    watchedPackageId,
    dependencyVersionId
  };
}

/**
 * GET /api/watchtower/:packageName
 * Get the full analysis results for a watched package
 */
router.get('/:packageName', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { packageName } = req.params;

    const accessCheck = await checkWatchtowerAccess(userId, packageName);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Get the full watched package data with joined dependencies
    // Update to select from dependencies via relation since watched_packages no longer has name/etc.
    const { data: watchedPkg, error } = await supabase
      .from('watched_packages')
      .select(`
        *,
        dependencies!dependency_id (
            name,
            license,
            openssf_score,
            weekly_downloads,
            last_published_at
        )
      `)
      // We can't query by name directly on watched_packages anymore
      // But we have the accessCheck result which already did the lookup!
      .eq('id', accessCheck.watchedPackageId)
      .single();

    if (error || !watchedPkg) {
      return res.status(404).json({ error: 'Package analysis not found' });
    }

    // Transform response to match what frontend expects (flattening the join)
    // The frontend likely expects { name: ..., status: ..., ... }
    const response = {
      ...watchedPkg,
      name: (watchedPkg.dependencies as any)?.name || packageName, // Fallback to param if missing
      license: (watchedPkg.dependencies as any)?.license,
      openssf_score: (watchedPkg.dependencies as any)?.openssf_score,
      weekly_downloads: (watchedPkg.dependencies as any)?.weekly_downloads,
      last_published_at: (watchedPkg.dependencies as any)?.last_published_at,
    };

    res.json(response);
  } catch (error: any) {
    console.error('Error fetching watchtower data:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch watchtower data' });
  }
});

/**
 * GET /api/watchtower/:packageName/commits
 * Get recent commits for a watched package.
 * Optional query params:
 *   - organization_id: filter by watchtower_cleared_at and exclude individually cleared commits
 *   - project_dependency_id: enrich with touches_imported_functions (intersection with project's imported functions)
 *   - filter=touches_imported: return only commits that touch at least one function the project imports (requires project_dependency_id)
 */
router.get('/:packageName/commits', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { packageName } = req.params;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const offset = parseInt(req.query.offset as string) || 0;
    const organizationId = (req.query.organization_id as string) || null;
    const projectDependencyId = (req.query.project_dependency_id as string) || null;
    const filterTouchesImported = (req.query.filter as string) === 'touches_imported';
    const sortByAnomaly = (req.query.sort as string) === 'anomaly';

    const accessCheck = await checkWatchtowerAccess(userId, packageName);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    if (projectDependencyId) {
      const { data: pd } = await supabase
        .from('project_dependencies')
        .select('id, project_id')
        .eq('id', projectDependencyId)
        .maybeSingle();
      if (!pd) {
        return res.status(404).json({ error: 'Project dependency not found' });
      }
      const { data: proj } = await supabase
        .from('projects')
        .select('organization_id')
        .eq('id', pd.project_id)
        .maybeSingle();
      if (!proj) {
        return res.status(404).json({ error: 'Project not found' });
      }
      const { data: member } = await supabase
        .from('organization_members')
        .select('organization_id')
        .eq('organization_id', proj.organization_id)
        .eq('user_id', userId)
        .maybeSingle();
      if (!member) {
        return res.status(403).json({ error: 'Access denied to project dependency' });
      }
    }

    let watchtowerClearedAt: string | null = null;
    let clearedShasSet: Set<string> = new Set();

    if (organizationId) {
      const { data: membership } = await supabase
        .from('organization_members')
        .select('organization_id')
        .eq('organization_id', organizationId)
        .eq('user_id', userId)
        .maybeSingle();
      if (!membership) {
        return res.status(403).json({ error: 'Access denied to organization' });
      }

      const { data: depRow } = await supabase
        .from('dependencies')
        .select('id')
        .eq('name', packageName)
        .limit(1)
        .single();
      const packageDependencyId = (depRow as any)?.id;
      if (packageDependencyId) {
        const { data: watchlistRow } = await supabase
          .from('organization_watchlist')
          .select('watchtower_cleared_at')
          .eq('organization_id', organizationId)
          .eq('dependency_id', packageDependencyId)
          .maybeSingle();
        watchtowerClearedAt = watchlistRow?.watchtower_cleared_at ?? null;
      }

      const { data: clearedRows } = await supabase
        .from('organization_watchlist_cleared_commits')
        .select('commit_sha')
        .eq('organization_id', organizationId)
        .eq('dependency_id', packageDependencyId);
      if (clearedRows) {
        clearedRows.forEach((r: { commit_sha: string }) => clearedShasSet.add(r.commit_sha));
      }
    }

    let commits: any[] | null;
    let count: number | null;
    let error: any;

    if (filterTouchesImported && projectDependencyId) {
      // Use the exact same query and range as the organizationId branch (one page), then filter in memory.
      // This avoids a separate large-range query that was returning 0 rows (PostgREST/Supabase behavior).
      let query = supabase
        .from('package_commits')
        .select('*', { count: 'exact' })
        .eq('watched_package_id', accessCheck.watchedPackageId)
        .order('timestamp', { ascending: false });
      if (watchtowerClearedAt) {
        query = query.gte('created_at', watchtowerClearedAt);
      }
      if (clearedShasSet.size > 0) {
        const clearedList = Array.from(clearedShasSet).map(s => `"${String(s).replace(/"/g, '\\"')}"`).join(',');
        query = query.not('sha', 'in', `(${clearedList})`);
      }
      // Always use first page for filter so we use the same working query; "load more" not supported for this filter
      const result = await query.range(0, limit - 1);
      const pageCommits = result.data || [];
      const commitShasForJoin = pageCommits.map((c: { sha: string }) => c.sha);
      if (commitShasForJoin.length === 0) {
        commits = [];
        count = 0;
        error = null;
      } else {
        const { data: touchedRows } = await supabase
          .from('package_commit_touched_functions')
          .select('commit_sha, function_name')
          .eq('watched_package_id', accessCheck.watchedPackageId)
          .in('commit_sha', commitShasForJoin);
        const { data: importedRows } = await supabase
          .from('project_dependency_functions')
          .select('function_name')
          .eq('project_dependency_id', projectDependencyId);
        const importedSet = new Set((importedRows || []).map((r: { function_name: string }) => r.function_name));
        const touchedBySha: Record<string, Set<string>> = {};
        for (const row of touchedRows || []) {
          if (!touchedBySha[row.commit_sha]) touchedBySha[row.commit_sha] = new Set();
          touchedBySha[row.commit_sha].add(row.function_name);
        }
        const shasThatTouchImported = pageCommits.filter((c: { sha: string }) => {
          const touched = touchedBySha[c.sha];
          if (!touched || touched.size === 0) return false;
          for (const fn of touched) {
            if (importedSet.has(fn)) return true;
          }
          return false;
        }).map((c: { sha: string }) => c.sha);
        const shaSet = new Set(shasThatTouchImported);
        commits = pageCommits.filter((c: { sha: string }) => shaSet.has(c.sha));
        count = commits.length;
        error = null;
      }
    } else if (organizationId) {
      if (sortByAnomaly) {
        // Paginated "top 100 by anomaly, then next 100 on scroll" via RPC
        const clearedArr = clearedShasSet.size > 0 ? Array.from(clearedShasSet) : [];
        const { data: rpcData, error: rpcError } = await supabase.rpc('get_watchtower_commits_by_anomaly', {
          p_watched_package_id: accessCheck.watchedPackageId,
          p_since_created_at: watchtowerClearedAt || null,
          p_cleared_shas: clearedArr.length > 0 ? clearedArr : null,
          p_limit: limit,
          p_offset: offset,
        });
        commits = rpcData ?? [];
        error = rpcError ?? null;
        // Total count with same filters (no order)
        let countQuery = supabase
          .from('package_commits')
          .select('*', { count: 'exact', head: true })
          .eq('watched_package_id', accessCheck.watchedPackageId);
        if (watchtowerClearedAt) {
          countQuery = countQuery.gte('created_at', watchtowerClearedAt);
        }
        if (clearedShasSet.size > 0) {
          const clearedList = Array.from(clearedShasSet).map(s => `"${String(s).replace(/"/g, '\\"')}"`).join(',');
          countQuery = countQuery.not('sha', 'in', `(${clearedList})`);
        }
        const { count: totalCount } = await countQuery.range(0, 0);
        count = totalCount ?? commits.length;
      } else {
        let query = supabase
          .from('package_commits')
          .select('*', { count: 'exact' })
          .eq('watched_package_id', accessCheck.watchedPackageId)
          .order('timestamp', { ascending: false });
        if (watchtowerClearedAt) {
          query = query.gte('created_at', watchtowerClearedAt);
        }
        if (clearedShasSet.size > 0) {
          const clearedList = Array.from(clearedShasSet).map(s => `"${String(s).replace(/"/g, '\\"')}"`).join(',');
          query = query.not('sha', 'in', `(${clearedList})`);
        }
        const result = await query.range(offset, offset + limit - 1);
        commits = result.data;
        count = result.count;
        error = result.error;
      }
    } else {
      const result = await supabase
        .from('package_commits')
        .select('*', { count: 'exact' })
        .eq('watched_package_id', accessCheck.watchedPackageId)
        .order('timestamp', { ascending: false })
        .range(offset, offset + limit - 1);
      commits = result.data;
      count = result.count;
      error = result.error;
    }

    if (error) {
      throw error;
    }

    const totalFiltered = count ?? 0;
    const paged = commits || [];
    const commitShas = paged.map((c: { sha: string }) => c.sha);

    let touchedMap: Record<string, string[]> = {};
    if (commitShas.length > 0) {
      const { data: touchedRows } = await supabase
        .from('package_commit_touched_functions')
        .select('commit_sha, function_name')
        .eq('watched_package_id', accessCheck.watchedPackageId)
        .in('commit_sha', commitShas);
      for (const row of touchedRows || []) {
        if (!touchedMap[row.commit_sha]) touchedMap[row.commit_sha] = [];
        touchedMap[row.commit_sha].push(row.function_name);
      }
    }

    let importedFunctions: string[] = [];
    if (projectDependencyId) {
      const { data: pdfRows } = await supabase
        .from('project_dependency_functions')
        .select('function_name')
        .eq('project_dependency_id', projectDependencyId);
      importedFunctions = (pdfRows || []).map((r: { function_name: string }) => r.function_name);
    }
    const importedSet = new Set(importedFunctions);

    let anomalyMap: Record<string, { score: number; breakdown: any }> = {};
    if (commitShas.length > 0) {
      const { data: anomalies } = await supabase
        .from('package_anomalies')
        .select('commit_sha, anomaly_score, score_breakdown')
        .eq('watched_package_id', accessCheck.watchedPackageId)
        .in('commit_sha', commitShas);
      if (anomalies) {
        for (const anomaly of anomalies) {
          anomalyMap[anomaly.commit_sha] = {
            score: anomaly.anomaly_score,
            breakdown: anomaly.score_breakdown,
          };
        }
      }
    }

    const enrichedCommits = paged.map((commit: any) => {
      const touched = touchedMap[commit.sha] || [];
      const touchesImported = projectDependencyId
        ? touched.filter((fn: string) => importedSet.has(fn))
        : undefined;
      return {
        ...commit,
        touched_functions: touched.length > 0 ? touched : undefined,
        touches_imported_functions: touchesImported && touchesImported.length > 0 ? touchesImported : undefined,
        anomaly: anomalyMap[commit.sha] || null,
      };
    });

    const responseTotal = filterTouchesImported && projectDependencyId
      ? (count ?? 0)
      : (organizationId ? totalFiltered : (count || 0));

    res.json({
      commits: enrichedCommits,
      total: responseTotal,
      limit,
      offset,
    });
  } catch (error: any) {
    console.error('Error fetching watchtower commits:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch commits' });
  }
});

/**
 * GET /api/watchtower/:packageName/contributors
 * Get contributor profiles for a watched package
 */
router.get('/:packageName/contributors', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { packageName } = req.params;

    const accessCheck = await checkWatchtowerAccess(userId, packageName);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Get contributor profiles
    const { data: contributors, error } = await supabase
      .from('package_contributors')
      .select('*')
      .eq('watched_package_id', accessCheck.watchedPackageId)
      .order('total_commits', { ascending: false });

    if (error) {
      throw error;
    }

    res.json(contributors || []);
  } catch (error: any) {
    console.error('Error fetching watchtower contributors:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch contributors' });
  }
});

/**
 * GET /api/watchtower/:packageName/anomalies
 * Get all anomalies for a watched package sorted by score
 */
router.get('/:packageName/anomalies', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { packageName } = req.params;
    const minScore = parseFloat(req.query.min_score as string) || 0;

    const accessCheck = await checkWatchtowerAccess(userId, packageName);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // Build query
    let query = supabase
      .from('package_anomalies')
      .select(`
        *,
        contributor:package_contributors(author_email, author_name)
      `)
      .eq('watched_package_id', accessCheck.watchedPackageId)
      .order('anomaly_score', { ascending: false });

    // Filter by minimum score if specified
    if (minScore > 0) {
      query = query.gte('anomaly_score', minScore);
    }

    const { data: anomalies, error } = await query;

    if (error) {
      throw error;
    }

    // Get commit details for each anomaly
    const commitShas = (anomalies || []).map(a => a.commit_sha);
    let commitMap: Record<string, any> = {};

    if (commitShas.length > 0) {
      const { data: commits } = await supabase
        .from('package_commits')
        .select('sha, author, message, timestamp, lines_added, lines_deleted, files_changed')
        .eq('watched_package_id', accessCheck.watchedPackageId)
        .in('sha', commitShas);

      if (commits) {
        for (const commit of commits) {
          commitMap[commit.sha] = commit;
        }
      }
    }

    // Enrich anomalies with commit details
    const enrichedAnomalies = (anomalies || []).map(anomaly => ({
      ...anomaly,
      commit: commitMap[anomaly.commit_sha] || null,
    }));

    res.json(enrichedAnomalies);
  } catch (error: any) {
    console.error('Error fetching watchtower anomalies:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch anomalies' });
  }
});

/**
 * GET /api/watchtower/:packageName/summary
 * Get a summary of the watchtower analysis (for quick UI display)
 */
router.get('/:packageName/summary', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { packageName } = req.params;
    const projectDependencyId = req.query.project_dependency_id as string | undefined;

    const accessCheck = await checkWatchtowerAccess(userId, packageName, projectDependencyId);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    const cacheKey = getWatchtowerSummaryCacheKey(packageName, projectDependencyId);
    const forceRefresh = req.query.refresh === 'true';

    // Return cache only when not forcing refresh and cached value is not a "loading" state
    if (!forceRefresh) {
      const cached = await getCached<any>(cacheKey);
      if (cached !== null) {
        const status = cached.status;
        const checksLoading =
          status === 'ready' &&
          cached.registry_integrity_status == null &&
          cached.install_scripts_status == null &&
          cached.entropy_analysis_status == null;
        if (status !== 'pending' && status !== 'analyzing' && !checksLoading) {
          return res.json(cached);
        }
        // Cached value is pending/analyzing or checks still loading — skip cache, hit DB
      }
    }

    // Get the watched package summary via join with dependencies (latest_version / latest_release_date live on dependencies)
    const { data: watchedPkg, error: pkgError } = await supabase
      .from('watched_packages')
      .select(`
        id,
        status,
        dependency_id,
        dependencies!dependency_id (
          name,
          latest_version,
          latest_release_date
        )
      `)
      .eq('id', accessCheck.watchedPackageId)
      .single();

    if (pkgError || !watchedPkg) {
      return res.status(404).json({ error: 'Package analysis not found' });
    }

    // Resolve org watchlist row for quarantine flags and latest_allowed_version (project_dependency_id -> project -> organization_id)
    // Parallelized: pdRow first, then (projectRow + depRow) in parallel, then watchlistRow, then prRows
    let quarantine_next_release = false;
    let is_current_version_quarantined = false;
    let quarantine_until: string | null = null;
    let latest_allowed_version: string | null = null;
    let bump_pr_url: string | null = null;
    let decrease_pr_url: string | null = null;
    if (projectDependencyId) {
      const { data: pdRow } = await supabase
        .from('project_dependencies')
        .select('project_id')
        .eq('id', projectDependencyId)
        .single();
      if (pdRow?.project_id) {
        const [projectResult, depResult] = await Promise.all([
          supabase.from('projects').select('organization_id').eq('id', pdRow.project_id).single(),
          supabase.from('dependencies').select('id').eq('name', packageName).limit(1).single(),
        ]);
        const projectRow = projectResult.data as { organization_id?: string } | null;
        const depRow = depResult.data as { id?: string } | null;
        const packageDependencyId = depRow?.id;
        if (projectRow?.organization_id && packageDependencyId) {
          const { data: watchlistRow } = await supabase
            .from('organization_watchlist')
            .select('quarantine_next_release, is_current_version_quarantined, quarantine_until, latest_allowed_version')
            .eq('organization_id', projectRow.organization_id)
            .eq('dependency_id', packageDependencyId)
            .maybeSingle();
          if (watchlistRow) {
            quarantine_next_release = watchlistRow.quarantine_next_release ?? false;
            is_current_version_quarantined = watchlistRow.is_current_version_quarantined ?? false;
            quarantine_until = watchlistRow.quarantine_until ?? null;
            latest_allowed_version = (watchlistRow as any).latest_allowed_version ?? null;
          }
        }
        if (latest_allowed_version) {
          const { data: prRows } = await supabase
            .from('dependency_prs')
            .select('type, pr_url')
            .eq('project_id', pdRow.project_id)
            .eq('dependency_id', packageDependencyId)
            .eq('target_version', latest_allowed_version);
          if (prRows && Array.isArray(prRows)) {
            for (const row of prRows) {
              if ((row as any).type === 'bump') bump_pr_url = (row as any).pr_url ?? null;
              if ((row as any).type === 'decrease') decrease_pr_url = (row as any).pr_url ?? null;
            }
          }
        }
        // If no bump PR matched latest_allowed_version, check for any bump PR (so overview can show "View PR")
        if (!bump_pr_url) {
          const { data: anyBumpRows } = await supabase
            .from('dependency_prs')
            .select('target_version, pr_url')
            .eq('project_id', pdRow.project_id)
            .eq('dependency_id', packageDependencyId)
            .eq('type', 'bump');
          if (anyBumpRows && anyBumpRows.length > 0) {
            const sorted = [...anyBumpRows].sort((a, b) => {
              try {
                const va = semver.coerce((a as any).target_version);
                const vb = semver.coerce((b as any).target_version);
                if (!va || !vb) return 0;
                return semver.rcompare(va, vb);
              } catch {
                return 0;
              }
            });
            bump_pr_url = (sorted[0] as any).pr_url ?? null;
          }
        }
      }
    }

    // Run dependency_versions, counts, and top anomaly in parallel
    const versionQuery =
      watchedPkg.status === 'ready' && accessCheck.dependencyVersionId
        ? supabase
            .from('dependency_versions')
            .select('registry_integrity_status, registry_integrity_reason, install_scripts_status, install_scripts_reason, entropy_analysis_status, entropy_analysis_reason')
            .eq('id', accessCheck.dependencyVersionId)
            .single()
        : Promise.resolve({ data: null, error: null });

    const [
      versionResult,
      { count: commitCount },
      { count: contributorCount },
      { count: anomalyCount },
      { data: topAnomaly },
    ] = await Promise.all([
      versionQuery,
      supabase
        .from('package_commits')
        .select('id', { count: 'exact', head: true })
        .eq('watched_package_id', accessCheck.watchedPackageId),
      supabase
        .from('package_contributors')
        .select('id', { count: 'exact', head: true })
        .eq('watched_package_id', accessCheck.watchedPackageId),
      supabase
        .from('package_anomalies')
        .select('id', { count: 'exact', head: true })
        .eq('watched_package_id', accessCheck.watchedPackageId),
      supabase
        .from('package_anomalies')
        .select('anomaly_score')
        .eq('watched_package_id', accessCheck.watchedPackageId)
        .order('anomaly_score', { ascending: false })
        .limit(1)
        .single(),
    ]);

    const versionData = versionResult.data ?? {};

    const summary = {
      name: (watchedPkg.dependencies as any)?.name || packageName,
      status: watchedPkg.status,
      latest_version: (watchedPkg.dependencies as any)?.latest_version ?? null,
      latest_release_date: (watchedPkg.dependencies as any)?.latest_release_date ?? null,
      latest_allowed_version,
      quarantine_next_release,
      is_current_version_quarantined,
      quarantine_until,
      bump_pr_url,
      decrease_pr_url,
      // Status fields from dependency_versions
      registry_integrity_status: versionData.registry_integrity_status || null,
      registry_integrity_reason: versionData.registry_integrity_reason || null,
      install_scripts_status: versionData.install_scripts_status || null,
      install_scripts_reason: versionData.install_scripts_reason || null,
      entropy_analysis_status: versionData.entropy_analysis_status || null,
      entropy_analysis_reason: versionData.entropy_analysis_reason || null,
      // Counts
      commits_count: commitCount || 0,
      contributors_count: contributorCount || 0,
      anomalies_count: anomalyCount || 0,
      top_anomaly_score: topAnomaly?.anomaly_score || 0,
    };

    // Cache only when analysis is done and not in a loading state (status or integrity checks)
    const statusReady = watchedPkg.status !== 'pending' && watchedPkg.status !== 'analyzing';
    const checksReady =
      summary.registry_integrity_status != null ||
      summary.install_scripts_status != null ||
      summary.entropy_analysis_status != null;
    if (statusReady && (checksReady || watchedPkg.status !== 'ready')) {
      await setCached(cacheKey, summary, CACHE_TTL_SECONDS.WATCHTOWER_SUMMARY);
    }

    res.json(summary);
  } catch (error: any) {
    console.error('Error fetching watchtower summary:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch summary' });
  }
});


/**
 * POST /api/watchtower/analyze-commit
 * Analyze a commit diff using Aegis AI (ChatGPT)
 */
router.post('/analyze-commit', authenticateUser, async (req: AuthRequest, res) => {
  try {
    const userId = req.user!.id;
    const { packageName, commitSha, repoFullName } = req.body;

    if (!packageName || !commitSha || !repoFullName) {
      return res.status(400).json({ error: 'Missing required fields: packageName, commitSha, repoFullName' });
    }

    // Verify access
    const accessCheck = await checkWatchtowerAccess(userId, packageName);
    if (!accessCheck.hasAccess) {
      return res.status(accessCheck.error!.status).json({ error: accessCheck.error!.message });
    }

    // 1. Get installation ID for the project
    // We need to look up the project associated with the watched package or dependency
    // Since we verified validation, we can just get the project for the dependency
    const { data: project } = await supabase
      .from('projects')
      .select('installation_id')
      .eq('organization_id', (req.user as any).organization_id) // This might not be populated in AuthRequest?
      // Let's rely on the simpler method: just find one project that watches this package and has an installation ID
      // This is a simplification but valid for the user's context where they have access
      .limit(1)
      .single();

    // Get installation ID from a project in an org that has this package in its watchlist (by dependency_id)
    const { data: dependencyData, error: depError } = await supabase
      .from('project_dependencies')
      .select(`
            dependency_id,
            project:projects (
                id,
                installation_id,
                organization_id
            )
        `)
      .eq('name', packageName)
      .limit(1)
      .single();

    let projectId: string | undefined;
    let installationId: string | undefined;
    const projectRow = dependencyData?.project as any;
    const depId = (dependencyData as any)?.dependency_id;
    if (projectRow?.organization_id && depId) {
      const { data: watchRow } = await supabase
        .from('organization_watchlist')
        .select('id')
        .eq('organization_id', projectRow.organization_id)
        .eq('dependency_id', depId)
        .maybeSingle();
      if (watchRow) {
        projectId = projectRow.id;
        installationId = projectRow.installation_id;
      }
    }

    // Get the package's GitHub URL from npm registry
    // This is the source of truth since npm packages store their repo URL
    console.log(`[Watchtower Aegis] Fetching GitHub URL for ${packageName} from npm registry`);

    let packageRepoFullName: string;
    try {
      const npmResponse = await fetch(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`, {
        headers: { 'User-Agent': 'Deptex-App' },
      });

      if (!npmResponse.ok) {
        return res.status(400).json({ error: `Failed to fetch package info from npm: ${npmResponse.status}` });
      }

      const npmData = await npmResponse.json();
      const repoUrl = npmData.repository?.url || '';

      // Extract GitHub owner/repo from various URL formats
      const githubMatch = repoUrl.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?$/i);
      if (!githubMatch) {
        return res.status(400).json({
          error: `No GitHub repository found for ${packageName}. Repository URL: ${repoUrl || 'not specified'}`
        });
      }

      packageRepoFullName = `${githubMatch[1]}/${githubMatch[2]}`;
    } catch (err: any) {
      return res.status(500).json({ error: `Failed to lookup package repository: ${err.message}` });
    }

    console.log(`[Watchtower Aegis] Analyzing commit ${commitSha} from ${packageRepoFullName}`);

    let diff: string;

    if (installationId) {
      // Use GitHub App installation token for authenticated access
      const installationToken = await createInstallationToken(installationId);
      diff = await getCommitDiff(installationToken, packageRepoFullName, commitSha);
    } else {
      // Fallback to public repo access (uses GITHUB_PAT env var if available)
      // This works for public dependency repos that the user is tracking
      console.log(`[Watchtower] No installation_id, using public repo access for ${packageRepoFullName}`);
      diff = await getCommitDiffPublic(packageRepoFullName, commitSha);
    }

    // Truncate diff if too large to avoid token limits
    const MAX_DIFF_LENGTH = 15000;
    const truncatedDiff = diff.length > MAX_DIFF_LENGTH
      ? diff.substring(0, MAX_DIFF_LENGTH) + '\n...(diff truncated)...'
      : diff;

    // 4. Analyze with OpenAI
    const openai = getOpenAIClient();

    const prompt = `
You are Aegis, a security auditor for software dependencies. Your job is to detect security issues in code changes.

You are analyzing commits from OPEN SOURCE PACKAGES. Many patterns that seem dangerous are legitimate:
- Dev tools, browser extensions, and build tools use eval, dynamic code, and script injection legitimately
- Configuration injection in settings/preferences is normal
- Message passing between extension components is expected (postMessage, chrome.runtime.sendMessage, etc.)
- Dynamic imports and require() are standard patterns
- window.postMessage with '*' origin is NORMAL for devtools and extensions communicating with pages

Do NOT flag as suspicious:
- postMessage() calls in browser extensions, devtools, or debugging tools
- Message passing between iframe/window contexts (this is standard browser API usage)
- Console/logging utilities that format or relay log data
- Internal data serialization for debugging purposes

Classify the commit as one of three levels:

**SUSPICIOUS** - CONCRETE MALICIOUS CODE found:
- Data exfiltration to EXTERNAL HTTP servers (fetch/XMLHttpRequest to unknown domains)
- Credential/token harvesting (process.env, cookies, localStorage sent to external URLs)
- Obfuscated payloads (hex/base64 that decode to malicious code)
- Backdoor installation (reverse shells, unauthorized remote access)
- Malicious install scripts (curl | bash to untrusted URLs)

**CAUTION** - Potential security concerns worth reviewing:
- New HTTP requests (fetch/axios/XMLHttpRequest) to external URLs that seem suspicious
- Code that sends sensitive data (env vars, cookies, localStorage) to EXTERNAL endpoints
- Unusual obfuscation or encoding that's atypical for the project
- Disabled security features or bypassed checks
- Dependencies on suspicious or typosquatted packages

**SAFE** - No security concerns:
- Normal code patterns for the project type
- Standard library and browser API usage
- Message passing APIs (postMessage, chrome.runtime, etc.) 
- Routine bug fixes, features, or refactoring

Commit Context:
Package: ${packageName}
Repo: ${repoFullName}
SHA: ${commitSha}

Diff:
\`\`\`diff
${truncatedDiff}
\`\`\`

RESPONSE FORMAT:
Start with exactly one of: **SUSPICIOUS**, **CAUTION**, or **SAFE**

If SAFE: One brief sentence explaining why.

If CAUTION or SUSPICIOUS: Provide:
- **File:** \`filename\` (Line X)
- **Code:**
\`\`\`
[the concerning code snippet]
\`\`\`
- **Concern:** What this code does and why it's concerning
- Use bullet points for multiple issues
`;

    const completion = await openai.chat.completions.create({
      model: 'gpt-4-turbo-preview',
      messages: [
        { role: 'system', content: 'You are a helpful and vigilant security assistant.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.1,
    });

    const analysis = completion.choices[0].message.content;

    res.json({ analysis });

  } catch (error: any) {
    console.error('Error analyzing commit:', error);
    res.status(500).json({ error: error.message || 'Failed to analyze commit' });
  }
});

export default router;

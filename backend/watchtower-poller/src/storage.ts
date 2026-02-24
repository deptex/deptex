import { createClient } from '@supabase/supabase-js';
import { CommitDetails } from './incremental-analyzer';
import { ProcessedVulnerability } from './osv-checker';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

export interface WatchedPackageInfo {
  id: string;
  name: string;
  status: string;
  last_known_commit_sha: string | null;
  last_polled_at: string | null;
  github_url: string | null;
  analysis_data?: any;
  last_npm_version?: string | null;
  last_osv_check_at: string | null;
}

export interface ContributorProfile {
  id: string;
  authorEmail: string;
  authorName: string;
  totalCommits: number;
  avgLinesAdded: number;
  avgLinesDeleted: number;
  avgFilesChanged: number;
  stddevLinesAdded: number;
  stddevLinesDeleted: number;
  stddevFilesChanged: number;
  avgCommitMessageLength: number;
  stddevCommitMessageLength: number;
  insertToDeleteRatio: number;
  commitTimeHistogram: Record<string, number>;
  typicalDaysActive: Record<string, number>;
  commitTimeHeatmap: number[][];
  filesWorkedOn: Record<string, number>;
  firstCommitDate: Date;
  lastCommitDate: Date;
}

export interface AnomalyScoreBreakdown {
  factor: string;
  points: number;
  reason: string;
}

export interface AnomalyResult {
  commitSha: string;
  contributorEmail: string;
  totalScore: number;
  breakdown: AnomalyScoreBreakdown[];
}

/**
 * Get watched package info by ID (name and github_url come from dependencies table)
 */
export async function getWatchedPackageById(watchedPackageId: string): Promise<WatchedPackageInfo | null> {
  const { data, error } = await supabase
    .from('watched_packages')
    .select(`
      id,
      status,
      last_known_commit_sha,
      last_polled_at,
      dependencies!dependency_id (name, github_url)
    `)
    .eq('id', watchedPackageId)
    .single();

  if (error) {
    console.error(`Failed to get watched package ${watchedPackageId}:`, error);
    return null;
  }

  const dep = (data as any)?.dependencies;
  return {
    id: data.id,
    name: dep?.name ?? '',
    status: data.status,
    last_known_commit_sha: data.last_known_commit_sha ?? null,
    last_polled_at: data.last_polled_at ?? null,
    github_url: dep?.github_url ?? null,
    last_osv_check_at: (data as any).last_osv_check_at ?? null,
  } as WatchedPackageInfo;
}

/**
 * Get all watched packages that are ready for polling (name and github_url from dependencies)
 */
export async function getReadyWatchedPackages(): Promise<WatchedPackageInfo[]> {
  const { data, error } = await supabase
    .from('watched_packages')
    .select(`
      id,
      status,
      last_known_commit_sha,
      last_polled_at,
      dependencies!dependency_id (name, github_url)
    `)
    .eq('status', 'ready');

  if (error) {
    console.error('Failed to get ready watched packages:', error);
    return [];
  }

  return (data || []).map((row: any) => {
    const dep = row.dependencies;
    return {
      id: row.id,
      name: dep?.name ?? '',
      status: row.status,
      last_known_commit_sha: row.last_known_commit_sha ?? null,
      last_polled_at: row.last_polled_at ?? null,
      github_url: dep?.github_url ?? null,
      last_osv_check_at: row.last_osv_check_at ?? null,
      analysis_data: undefined,
    } as WatchedPackageInfo;
  });
}

/**
 * Update the last known commit SHA and polling timestamp.
 * GitHub URL lives on dependencies (via dependency_id), not on watched_packages.
 */
export async function updatePollingStatus(
  watchedPackageId: string,
  lastKnownCommitSha: string
): Promise<void> {
  const updateData = {
    last_known_commit_sha: lastKnownCommitSha,
    last_polled_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const { error } = await supabase
    .from('watched_packages')
    .update(updateData)
    .eq('id', watchedPackageId);

  if (error) {
    console.error(`Failed to update polling status for ${watchedPackageId}:`, error);
    throw new Error(`Database update failed: ${error.message}`);
  }

  console.log(`[${new Date().toISOString()}] ✅ Updated polling status for ${watchedPackageId}`);
}

/**
 * Store new commits (appends to existing commits, uses upsert to avoid duplicates)
 */
export async function storeNewCommits(
  watchedPackageId: string,
  commits: CommitDetails[]
): Promise<void> {
  if (commits.length === 0) {
    console.log(`[${new Date().toISOString()}] ⏭️ No new commits to store`);
    return;
  }

  console.log(`[${new Date().toISOString()}] 💾 Storing ${commits.length} new commits...`);

  // Prepare commit data for insertion
  const commitData = commits.map(commit => ({
    watched_package_id: watchedPackageId,
    sha: commit.sha,
    author: commit.author,
    author_email: commit.authorEmail,
    message: commit.message.substring(0, 10000), // Limit message length
    timestamp: commit.timestamp.toISOString(),
    lines_added: commit.linesAdded,
    lines_deleted: commit.linesDeleted,
    files_changed: commit.filesChanged,
    diff_data: commit.diffData || null,
  }));

  // Insert in batches using upsert to avoid duplicates
  const batchSize = 50;
  let insertedCount = 0;

  for (let i = 0; i < commitData.length; i += batchSize) {
    const batch = commitData.slice(i, i + batchSize);

    const { error } = await supabase
      .from('package_commits')
      .upsert(batch, {
        onConflict: 'watched_package_id,sha',
        ignoreDuplicates: true
      });

    if (error) {
      console.error(`Failed to insert commit batch:`, error);
      // Continue with other batches
    } else {
      insertedCount += batch.length;
    }
  }

  // Store touched functions for each commit
  const touchedRows: Array<{ watched_package_id: string; commit_sha: string; function_name: string }> = [];
  for (const commit of commits) {
    if (commit.touchedFunctions && commit.touchedFunctions.length > 0) {
      for (const fn of commit.touchedFunctions) {
        touchedRows.push({ watched_package_id: watchedPackageId, commit_sha: commit.sha, function_name: fn });
      }
    }
  }
  if (touchedRows.length > 0) {
    const touchedBatchSize = 100;
    for (let i = 0; i < touchedRows.length; i += touchedBatchSize) {
      const batch = touchedRows.slice(i, i + touchedBatchSize);
      const { error: touchedError } = await supabase
        .from('package_commit_touched_functions')
        .upsert(batch, { onConflict: 'watched_package_id,commit_sha,function_name' });
      if (touchedError) {
        console.warn(`Failed to insert touched functions batch:`, touchedError);
      }
    }
  }

  console.log(`[${new Date().toISOString()}] ✅ Stored ${insertedCount} commits`);

  // Cap total commits per package at 500 (keep newest by timestamp)
  const MAX_COMMITS_PER_PACKAGE = 500;
  const { count, error: countError } = await supabase
    .from('package_commits')
    .select('*', { count: 'exact', head: true })
    .eq('watched_package_id', watchedPackageId);

  if (countError || count == null || count <= MAX_COMMITS_PER_PACKAGE) {
    return;
  }

  const toRemove = count - MAX_COMMITS_PER_PACKAGE;
  const { data: oldestRows } = await supabase
    .from('package_commits')
    .select('id, sha')
    .eq('watched_package_id', watchedPackageId)
    .order('timestamp', { ascending: true })
    .range(0, toRemove - 1);

  if (oldestRows && oldestRows.length > 0) {
    const idsToDelete = oldestRows.map((r: { id: string }) => r.id);
    const shasToRemove = oldestRows.map((r: { sha: string }) => r.sha);

    const { error: deleteTouchedError } = await supabase
      .from('package_commit_touched_functions')
      .delete()
      .eq('watched_package_id', watchedPackageId)
      .in('commit_sha', shasToRemove);
    if (deleteTouchedError) {
      console.warn(`Failed to delete touched functions for capped commits:`, deleteTouchedError);
    }

    const { error: deleteError } = await supabase
      .from('package_commits')
      .delete()
      .in('id', idsToDelete);
    if (deleteError) {
      console.warn(`Failed to cap package commits:`, deleteError);
    } else {
      console.log(`[${new Date().toISOString()}] 📋 Capped to ${MAX_COMMITS_PER_PACKAGE} commits (removed ${oldestRows.length} oldest)`);
    }
  }
}

/**
 * Get existing contributor profiles for a package
 */
export async function getContributorProfiles(
  watchedPackageId: string
): Promise<Map<string, ContributorProfile>> {
  const profileMap = new Map<string, ContributorProfile>();

  const { data, error } = await supabase
    .from('package_contributors')
    .select('*')
    .eq('watched_package_id', watchedPackageId);

  if (error) {
    console.error('Failed to get contributor profiles:', error);
    return profileMap;
  }

  for (const row of data || []) {
    profileMap.set(row.author_email.toLowerCase(), {
      id: row.id,
      authorEmail: row.author_email,
      authorName: row.author_name,
      totalCommits: row.total_commits,
      avgLinesAdded: row.avg_lines_added,
      avgLinesDeleted: row.avg_lines_deleted,
      avgFilesChanged: row.avg_files_changed,
      stddevLinesAdded: row.stddev_lines_added,
      stddevLinesDeleted: row.stddev_lines_deleted,
      stddevFilesChanged: row.stddev_files_changed,
      avgCommitMessageLength: row.avg_commit_message_length,
      stddevCommitMessageLength: row.stddev_commit_message_length,
      insertToDeleteRatio: row.insert_to_delete_ratio,
      commitTimeHistogram: row.commit_time_histogram || {},
      typicalDaysActive: row.typical_days_active || {},
      commitTimeHeatmap: row.commit_time_heatmap || [],
      filesWorkedOn: row.files_worked_on || {},
      firstCommitDate: new Date(row.first_commit_date),
      lastCommitDate: new Date(row.last_commit_date),
    });
  }

  return profileMap;
}

/**
 * Get contributor ID by email
 */
export async function getContributorIdByEmail(
  watchedPackageId: string,
  email: string
): Promise<string | null> {
  const { data, error } = await supabase
    .from('package_contributors')
    .select('id')
    .eq('watched_package_id', watchedPackageId)
    .eq('author_email', email.toLowerCase())
    .single();

  if (error || !data) {
    return null;
  }

  return data.id;
}

/**
 * Store anomalies for new commits
 */
export async function storeAnomalies(
  watchedPackageId: string,
  anomalies: AnomalyResult[],
  contributorProfiles: Map<string, ContributorProfile>
): Promise<void> {
  if (anomalies.length === 0) {
    console.log(`[${new Date().toISOString()}] ⏭️ No anomalies to store`);
    return;
  }

  console.log(`[${new Date().toISOString()}] 💾 Storing ${anomalies.length} anomalies...`);

  // Prepare anomaly data for insertion
  const anomalyData = anomalies
    .filter(a => {
      // Only include anomalies where we have a contributor ID
      const profile = contributorProfiles.get(a.contributorEmail.toLowerCase());
      return profile && profile.id;
    })
    .map(a => {
      const profile = contributorProfiles.get(a.contributorEmail.toLowerCase())!;
      return {
        watched_package_id: watchedPackageId,
        commit_sha: a.commitSha,
        contributor_id: profile.id,
        anomaly_score: a.totalScore,
        score_breakdown: a.breakdown,
      };
    });

  if (anomalyData.length === 0) {
    console.log(`[${new Date().toISOString()}] ⏭️ No valid anomalies to store (missing contributor IDs)`);
    return;
  }

  // Insert using upsert to avoid duplicates
  const batchSize = 50;
  let insertedCount = 0;

  for (let i = 0; i < anomalyData.length; i += batchSize) {
    const batch = anomalyData.slice(i, i + batchSize);

    const { error } = await supabase
      .from('package_anomalies')
      .upsert(batch, {
        onConflict: 'watched_package_id,commit_sha',
        ignoreDuplicates: false // Update if exists
      });

    if (error) {
      console.error(`Failed to insert anomaly batch:`, error);
      // Continue with other batches
    } else {
      insertedCount += batch.length;
    }
  }

  console.log(`[${new Date().toISOString()}] ✅ Stored ${insertedCount} anomalies`);
}

/**
 * Update the analysis_data JSON with new commit/anomaly counts
 * @deprecated Schema refactor moved detailed analysis to dependency_versions.
 * Disabling this write to prevent errors/corruption on watched_packages table.
 */
export async function updateAnalysisData(
  watchedPackageId: string,
  newCommitsCount: number,
  newAnomaliesCount: number
): Promise<void> {
  // NO-OP: analysis_data column is deprecated on watched_packages
  console.log(`[Deprecation] Skipping legacy updateAnalysisData for ${watchedPackageId}`);
  /*
  // First get the current analysis_data
  const { data: currentData, error: fetchError } = await supabase
    .from('watched_packages')
    .select('analysis_data')
    .eq('id', watchedPackageId)
    .single();

  if (fetchError || !currentData) {
    console.warn(`Could not fetch current analysis_data for ${watchedPackageId}`);
    return;
  }

  const analysisData = currentData.analysis_data || {};
  
  // Update counts
  analysisData.commitsAnalyzed = (analysisData.commitsAnalyzed || 0) + newCommitsCount;
  analysisData.anomaliesDetected = (analysisData.anomaliesDetected || 0) + newAnomaliesCount;
  analysisData.lastPolledAt = new Date().toISOString();

  const { error: updateError } = await supabase
    .from('watched_packages')
    .update({
      analysis_data: analysisData,
      updated_at: new Date().toISOString(),
    })
    .eq('id', watchedPackageId);

  if (updateError) {
    console.warn(`Failed to update analysis_data for ${watchedPackageId}:`, updateError);
  }
  */
}

/**
 * Parse repository URL to get GitHub URL (from analysis_data or repository field)
 */
export function getGithubUrlFromPackage(pkg: WatchedPackageInfo): string | null {
  // First check if we have a cached github_url
  if (pkg.github_url) {
    return pkg.github_url;
  }

  // Try to get from analysis_data
  if (pkg.analysis_data?.githubUrl) {
    return pkg.analysis_data.githubUrl;
  }

  return null;
}

// ============================================================================
// VULNERABILITY STORAGE FUNCTIONS
// ============================================================================

/**
 * Get all known vulnerability OSV IDs for a watched package
 */
export async function getKnownVulnerabilityIds(
  watchedPackageId: string
): Promise<Set<string>> {
  const { data, error } = await supabase
    .from('watched_package_vulnerabilities')
    .select('osv_id')
    .eq('watched_package_id', watchedPackageId);

  if (error) {
    console.error(`Failed to get known vulnerability IDs for ${watchedPackageId}:`, error);
    return new Set();
  }

  return new Set((data || []).map(row => row.osv_id));
}

/**
 * Store new vulnerabilities for a watched package
 */
export async function storeNewVulnerabilities(
  watchedPackageId: string,
  vulnerabilities: ProcessedVulnerability[]
): Promise<number> {
  if (vulnerabilities.length === 0) {
    console.log(`[${new Date().toISOString()}] ⏭️ No new vulnerabilities to store`);
    return 0;
  }

  console.log(`[${new Date().toISOString()}] 💾 Storing ${vulnerabilities.length} new vulnerabilities...`);

  // Prepare vulnerability data for insertion
  const vulnData = vulnerabilities.map(vuln => ({
    watched_package_id: watchedPackageId,
    osv_id: vuln.osvId,
    severity: vuln.severity,
    summary: vuln.summary,
    details: vuln.details?.substring(0, 10000) || null, // Limit details length
    aliases: vuln.aliases,
    affected_versions: vuln.affectedVersions,
    fixed_versions: vuln.fixedVersions,
    published_at: vuln.publishedAt,
    modified_at: vuln.modifiedAt,
  }));

  // Insert using upsert to avoid duplicates
  const batchSize = 50;
  let insertedCount = 0;

  for (let i = 0; i < vulnData.length; i += batchSize) {
    const batch = vulnData.slice(i, i + batchSize);

    const { error } = await supabase
      .from('watched_package_vulnerabilities')
      .upsert(batch, {
        onConflict: 'watched_package_id,osv_id',
        ignoreDuplicates: true // Don't update existing, only insert new
      });

    if (error) {
      console.error(`Failed to insert vulnerability batch:`, error);
      // Continue with other batches
    } else {
      insertedCount += batch.length;
    }
  }

  console.log(`[${new Date().toISOString()}] ✅ Stored ${insertedCount} vulnerabilities`);
  return insertedCount;
}

/**
 * Update OSV check status for a watched package.
 * Only updates updated_at so this works even when last_osv_check_at/last_npm_version columns don't exist.
 */
export async function updateOsvCheckStatus(
  watchedPackageId: string,
  lastNpmVersion: string | null
): Promise<void> {
  const updateData: Record<string, any> = {
    updated_at: new Date().toISOString(),
  };

  // Explicitly check columns before update would be safer, but for now catch error
  try {
    const { error } = await supabase
      .from('watched_packages')
      .update(updateData)
      .eq('id', watchedPackageId);

    if (error) {
      console.warn(`Failed to update OSV check status for ${watchedPackageId} (likely schema mismatch):`, error.message);
    } else {
      console.log(`[${new Date().toISOString()}] ✅ Updated OSV check status for ${watchedPackageId}`);
    }
  } catch (err: any) {
    console.warn(`Exception updating OSV check status: ${err.message}`);
  }
}

/**
 * Update the analysis_data JSON with new vulnerability counts
 * @deprecated Schema refactor moved specific counts to dependency_versions/dependencies
 */
export async function updateAnalysisDataWithVulnerabilities(
  watchedPackageId: string,
  newVulnerabilitiesCount: number,
  isNewVersion: boolean,
  latestNpmVersion: string | null
): Promise<void> {
  // NO-OP: analysis_data writes are disabled
  console.log(`[Deprecation] Skipping legacy updateAnalysisDataWithVulnerabilities for ${watchedPackageId}`);
  /*
  // First get the current analysis_data
  const { data: currentData, error: fetchError } = await supabase
    .from('watched_packages')
    .select('analysis_data')
    .eq('id', watchedPackageId)
    .single();

  if (fetchError || !currentData) {
    console.warn(`Could not fetch current analysis_data for ${watchedPackageId}`);
    return;
  }

  const analysisData = currentData.analysis_data || {};
  
  // Update vulnerability info
  analysisData.vulnerabilitiesDetected = (analysisData.vulnerabilitiesDetected || 0) + newVulnerabilitiesCount;
  analysisData.lastOsvCheckAt = new Date().toISOString();
  
  if (latestNpmVersion) {
    analysisData.latestNpmVersion = latestNpmVersion;
  }
  
  if (isNewVersion) {
    analysisData.lastNewVersionDetectedAt = new Date().toISOString();
  }

  const { error: updateError } = await supabase
    .from('watched_packages')
    .update({
      analysis_data: analysisData,
      updated_at: new Date().toISOString(),
    })
    .eq('id', watchedPackageId);

  if (updateError) {
    console.warn(`Failed to update analysis_data with vulnerability info for ${watchedPackageId}:`, updateError);
  }
  */
}

// ============================================================================
// JOB 1: DEPENDENCY REFRESH (latest release + dependency_vulnerabilities)
// ============================================================================

export interface DistinctDependencyRow {
  id: string;
  name: string;
  latest_version: string | null;
  latest_release_date: string | null;
}

/**
 * Get dependency IDs that are direct project dependencies (source in 'dependencies' or 'devDependencies', is_direct = true).
 * Used to limit npm latest-version API calls to direct deps only.
 * Path: project_dependencies -> dependency_version_id -> dependency_versions -> dependency_id.
 */
export async function getDirectDependencyIds(): Promise<Set<string>> {
  const { data: pdRows, error: pdError } = await supabase
    .from('project_dependencies')
    .select('dependency_version_id')
    .eq('is_direct', true)
    .in('source', ['dependencies', 'devDependencies'])
    .not('dependency_version_id', 'is', null);

  if (pdError) {
    console.error('Failed to get direct project_dependencies:', pdError);
    return new Set();
  }

  const versionIds = [...new Set((pdRows || []).map((r: { dependency_version_id: string }) => r.dependency_version_id).filter(Boolean))];
  if (versionIds.length === 0) return new Set();

  const { data: dvRows, error: dvError } = await supabase
    .from('dependency_versions')
    .select('dependency_id')
    .in('id', versionIds);

  if (dvError) {
    console.error('Failed to get dependency_versions for direct deps:', dvError);
    return new Set();
  }

  return new Set((dvRows || []).map((r: { dependency_id: string }) => r.dependency_id).filter(Boolean));
}

/**
 * Get ALL dependencies in the table (id, name, latest_version, latest_release_date).
 * Used for vulnerability refresh (OSV) for every dependency; npm latest only for direct deps.
 */
export async function getAllDependencies(): Promise<DistinctDependencyRow[]> {
  const result: DistinctDependencyRow[] = [];
  const pageSize = 500;
  let offset = 0;

  while (true) {
    const { data, error } = await supabase
      .from('dependencies')
      .select('id, name, latest_version, latest_release_date')
      .range(offset, offset + pageSize - 1);

    if (error) {
      console.error('Failed to get all dependencies:', error);
      break;
    }
    if (!data?.length) break;

    for (const row of data) {
      result.push({
        id: row.id,
        name: row.name,
        latest_version: row.latest_version ?? null,
        latest_release_date: row.latest_release_date ?? null,
      });
    }
    if (data.length < pageSize) break;
    offset += pageSize;
  }

  return result;
}

/**
 * Invalidate dependency versions cache for all project dependencies using this dependency_id.
 * Uses same key pattern as backend/src/lib/cache so watchtower versions sidebar gets fresh data.
 */
async function invalidateDependencyVersionsCacheByDependencyId(dependencyId: string): Promise<void> {
  try {
    const { Redis } = await import('@upstash/redis');
    const redisUrl = process.env.UPSTASH_REDIS_URL;
    const redisToken = process.env.UPSTASH_REDIS_TOKEN;
    if (!redisUrl || !redisToken) return;

    const redis = new Redis({ url: redisUrl, token: redisToken });
    const { data: projectDeps } = await supabase
      .from('project_dependencies')
      .select('id, project_id, projects!inner(organization_id)')
      .eq('dependency_id', dependencyId);

    if (!projectDeps || projectDeps.length === 0) return;

    const keys: string[] = [];
    for (const pd of projectDeps) {
      const orgId = (pd.projects as any)?.organization_id;
      const projectId = pd.project_id;
      const projectDependencyId = pd.id;
      if (orgId && projectId && projectDependencyId) {
        keys.push(`dependency-versions:${orgId}:${projectId}:${projectDependencyId}`);
      }
    }
    if (keys.length > 0) {
      await Promise.all(keys.map((k) => redis.del(k)));
    }
  } catch (err: any) {
    console.warn(`[Cache] Failed to invalidate dependency versions cache by dependency_id:`, err?.message ?? err);
  }
}

/**
 * Ensure a dependency_version row exists for (dependency_id, version). Idempotent (insert or no-op if exists).
 */
export async function ensureDependencyVersion(dependencyId: string, version: string): Promise<void> {
  const { error } = await supabase
    .from('dependency_versions')
    .insert({
      dependency_id: dependencyId,
      version,
    });

  if (error) {
    if (error.code === '23505') {
      // Unique violation - row already exists, ignore
      return;
    }
    console.error(`Failed to ensure dependency_version for ${dependencyId}@${version}:`, error);
    throw new Error(`Database insert failed: ${error.message}`);
  }

  await invalidateDependencyVersionsCacheByDependencyId(dependencyId);
}

/**
 * Check if any organization has this dependency in watchlist with quarantine expired (is_current_version_quarantined and quarantine_until <= now).
 */
export async function hasQuarantineExpiredForDependency(dependencyId: string): Promise<boolean> {
  const now = new Date().toISOString();
  const { data, error } = await supabase
    .from('organization_watchlist')
    .select('id')
    .eq('dependency_id', dependencyId)
    .eq('is_current_version_quarantined', true)
    .or(`quarantine_until.is.null,quarantine_until.lte.${now}`)
    .limit(1);

  if (error) {
    console.error(`Failed to check quarantine expired for dependency ${dependencyId}:`, error);
    return false;
  }
  return (data?.length ?? 0) > 0;
}

/**
 * Update latest_version and latest_release_date for all dependency rows with the given name.
 */
export async function updateDependenciesLatestByName(
  name: string,
  latestVersion: string,
  latestReleaseDate: string | null
): Promise<void> {
  const { error } = await supabase
    .from('dependencies')
    .update({
      latest_version: latestVersion,
      latest_release_date: latestReleaseDate ? latestReleaseDate : null,
      updated_at: new Date().toISOString(),
    })
    .eq('name', name);

  if (error) {
    console.error(`Failed to update dependencies latest for ${name}:`, error);
    throw new Error(`Database update failed: ${error.message}`);
  }
}

export interface DependencyVulnerabilityInsert {
  dependency_id: string;
  osv_id: string;
  severity: string;
  summary: string | null;
  details: string | null;
  aliases: string[];
  affected_versions: unknown;
  fixed_versions: string[];
  published_at: string | null;
  modified_at: string | null;
}

/**
 * Upsert vulnerability rows into dependency_vulnerabilities (onConflict: dependency_id, osv_id).
 * GHSA can return multiple nodes per advisory (same osv_id, different ranges); dedupe so each
 * (dependency_id, osv_id) appears once per batch to avoid "cannot affect row a second time".
 */
export async function upsertDependencyVulnerabilities(
  inserts: DependencyVulnerabilityInsert[]
): Promise<void> {
  if (inserts.length === 0) return;

  const byKey = new Map<string, DependencyVulnerabilityInsert>();
  for (const row of inserts) {
    const key = `${row.dependency_id}\t${row.osv_id}`;
    const existing = byKey.get(key);
    // Prefer row that has fixed_versions (patched version info)
    if (!existing || (row.fixed_versions.length > 0 && existing.fixed_versions.length === 0)) {
      byKey.set(key, row);
    }
  }
  const deduped = Array.from(byKey.values());

  const batchSize = 50;
  for (let i = 0; i < deduped.length; i += batchSize) {
    const batch = deduped.slice(i, i + batchSize);
    const { error } = await supabase
      .from('dependency_vulnerabilities')
      .upsert(batch, { onConflict: 'dependency_id,osv_id' });

    if (error) {
      console.error('Failed to upsert dependency_vulnerabilities batch:', error);
      throw new Error(`Database upsert failed: ${error.message}`);
    }
  }
}

import { supabase } from './supabase';
import { CommitDetails } from './commit-extractor';
import { ContributorProfile } from './contributor-profile';
import { AnomalyResult } from './anomaly-detection';
import { RegistryIntegrityResult } from './registry-integrity';
import { ScriptCapabilitiesResult } from './script-capabilities';
import { EntropyAnalysisResult } from './entropy-analysis';

export interface FullAnalysisResults {
  name: string;
  latestVersion: string;
  publishedAt: string | null;
  hasInstallScripts: boolean;
  installScripts?: {
    preinstall?: string;
    postinstall?: string;
    install?: string;
  };
  maintainers?: Array<{ name: string; email?: string }>;
  repository?: string;
  githubUrl?: string;
  repoCloned?: boolean;

  // Security check results
  registryIntegrity: RegistryIntegrityResult;
  scriptCapabilities: ScriptCapabilitiesResult;
  entropyAnalysis: EntropyAnalysisResult;

  // Commit analysis summary
  commitsAnalyzed: number;
  contributorsFound: number;
  anomaliesDetected: number;
  topAnomalyScore: number;

  // Status summaries
  registryIntegrityStatus: 'pass' | 'warning' | 'fail';
  installScriptsStatus: 'pass' | 'warning' | 'fail';
  entropyAnalysisStatus: 'pass' | 'warning' | 'fail';
  maintainerAnalysisStatus: 'pass' | 'warning' | 'fail';
}

/**
 * Update the status of a watched package
 */
export async function updateWatchedPackageStatus(
  watchedPackageId: string,
  status: 'pending' | 'analyzing' | 'ready' | 'error',
  errorMessage?: string
): Promise<void> {
  const updateData: Record<string, any> = {
    status,
    updated_at: new Date().toISOString(),
  };

  if (errorMessage) {
    updateData.error_message = errorMessage;
  }

  const { error } = await supabase
    .from('watched_packages')
    .update(updateData)
    .eq('id', watchedPackageId);

  if (error) {
    console.error(`Failed to update watched package status:`, error);
    throw new Error(`Database update failed: ${error.message}`);
  }
}

/**
 * Get dependency_id for a watched package (used by worker to upsert current-version analysis).
 */
export async function getDependencyIdForWatchedPackage(watchedPackageId: string): Promise<string | null> {
  const { data, error } = await supabase
    .from('watched_packages')
    .select('dependency_id')
    .eq('id', watchedPackageId)
    .single();
  if (error || !data?.dependency_id) return null;
  return data.dependency_id as string;
}

/**
 * Get dependency_versions.id for (dependency_id, version). Used to link project_dependencies after upserting current version.
 */
export async function getDependencyVersionRowId(dependencyId: string, version: string): Promise<string | null> {
  const { data, error } = await supabase
    .from('dependency_versions')
    .select('id')
    .eq('dependency_id', dependencyId)
    .eq('version', version)
    .single();
  if (error || !data?.id) return null;
  return data.id as string;
}

/**
 * Set project_dependencies.dependency_version_id so the Watchtower UI finds analysis for the project's version.
 */
export async function setProjectDependencyVersionId(projectDependencyId: string, dependencyVersionId: string): Promise<void> {
  const { error } = await supabase
    .from('project_dependencies')
    .update({ dependency_version_id: dependencyVersionId })
    .eq('id', projectDependencyId);
  if (error) {
    console.warn(`Failed to set project_dependency dependency_version_id:`, error);
  }
}

/**
 * Return version strings that already have all 3 analysis checks done (registry, scripts, entropy) in dependency_versions.
 * Used by batch version job to skip re-analyzing versions we already have.
 */
export async function getVersionsWithExistingAnalysis(
  dependencyId: string,
  versions: string[]
): Promise<Set<string>> {
  if (versions.length === 0) return new Set();
  const { data, error } = await supabase
    .from('dependency_versions')
    .select('version')
    .eq('dependency_id', dependencyId)
    .in('version', versions)
    .not('registry_integrity_status', 'is', null)
    .not('install_scripts_status', 'is', null)
    .not('entropy_analysis_status', 'is', null);
  if (error) {
    console.warn(`[${new Date().toISOString()}] Failed to fetch existing analysis for ${dependencyId}:`, error.message);
    return new Set();
  }
  return new Set((data || []).map((r: { version: string }) => r.version));
}

/**
 * Upsert dependency_versions row for (dependency_id, version) with analysis results.
 * Used for both latest-version (from updateWatchedPackageResults) and current-version (from processJob).
 */
export async function upsertDependencyVersionAnalysis(
  dependencyId: string,
  version: string,
  results: FullAnalysisResults
): Promise<void> {
  const registryIntegrityReason = getRegistryIntegrityReason(results);
  const installScriptsReason = getInstallScriptsReason(results);
  const entropyAnalysisReason = getEntropyAnalysisReason(results);
  const payload = {
    dependency_id: dependencyId,
    version,
    registry_integrity_status: results.registryIntegrityStatus,
    registry_integrity_reason: registryIntegrityReason,
    install_scripts_status: results.installScriptsStatus,
    install_scripts_reason: installScriptsReason,
    entropy_analysis_status: results.entropyAnalysisStatus,
    entropy_analysis_reason: entropyAnalysisReason,
    analysis_data: results,
    analyzed_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    error_message: null,
  };
  const { error } = await supabase
    .from('dependency_versions')
    .upsert(payload, { onConflict: 'dependency_id,version' });
  if (error) {
    console.error(`Failed to upsert dependency_versions for ${results.name}@${version}:`, error);
    throw new Error(`Database update failed: ${error.message}`);
  }
  console.log(`[${new Date().toISOString()}] ✅ Updated dependency_versions for ${results.name}@${version}`);

  // Invalidate caches for this dependency (if cache module is available)
  try {
    const cacheModule = await import('../../src/lib/cache');
    // Invalidate latest safe version cache
    cacheModule.invalidateLatestSafeVersionCacheByDependencyId(dependencyId).catch((err: any) => {
      console.warn(`[Cache] Failed to invalidate latest safe version cache for dependency ${dependencyId}:`, err.message);
    });
    // Invalidate watchtower summary cache
    cacheModule.invalidateWatchtowerSummaryCache(results.name).catch((err: any) => {
      console.warn(`[Cache] Failed to invalidate watchtower summary cache for ${results.name}:`, err.message);
    });
  } catch {
    // Cache module not available in worker context - that's okay
  }
}

/**
 * Update the watched package with full analysis results (latest version).
 */
export async function updateWatchedPackageResults(
  watchedPackageId: string,
  results: FullAnalysisResults
): Promise<void> {
  // 1. Get the dependency_id for this watched package
  const { data: watchedPkg, error: fetchError } = await supabase
    .from('watched_packages')
    .select('dependency_id')
    .eq('id', watchedPackageId)
    .single();

  if (fetchError || !watchedPkg?.dependency_id) {
    console.error(`Failed to find dependency_id for watched package ${watchedPackageId}:`, fetchError);
    // Fallback: update watched_packages anyway to clear 'analyzing' status to 'ready'
    await supabase.from('watched_packages').update({ status: 'ready' }).eq('id', watchedPackageId);
    return;
  }

  const dependencyId = watchedPkg.dependency_id;

  console.log(`[${new Date().toISOString()}] 💾 Saving analysis to dependency_versions...`);
  console.log(`   - Registry Integrity: ${results.registryIntegrityStatus}`);
  console.log(`   - Scripts: ${results.installScriptsStatus}`);
  console.log(`   - Entropy: ${results.entropyAnalysisStatus}`);

  // 2. Upsert dependency_versions for latest version
  await upsertDependencyVersionAnalysis(dependencyId, results.latestVersion, results);

  // 3. Update watched_packages status to 'ready'
  const { error: wpError } = await supabase
    .from('watched_packages')
    .update({
      status: 'ready',
      updated_at: new Date().toISOString()
    })
    .eq('id', watchedPackageId);

  if (wpError) {
    console.error(`Failed to update watched package status:`, wpError);
    // Non-fatal, as we saved the results
  }
}

/**
 * Update dependency_versions row by (dependency_id, version) with analysis results.
 * Used by auto-bump worker after analyzePackageVersion. Uses upsert so row is created if missing.
 */
export async function updateDependencyVersionAnalysis(
  dependencyId: string,
  version: string,
  results: FullAnalysisResults
): Promise<void> {
  await upsertDependencyVersionAnalysis(dependencyId, version, results);
}

/**
 * Store package commits in the database
 */
export async function storePackageCommits(
  watchedPackageId: string,
  commits: CommitDetails[]
): Promise<void> {
  if (commits.length === 0) {
    console.log(`[${new Date().toISOString()}] ⏭️ No commits to store`);
    return;
  }

  console.log(`[${new Date().toISOString()}] 💾 Storing ${commits.length} commits...`);

  // First, delete any existing commits and their touched functions for this package
  const { error: deleteTouchedError } = await supabase
    .from('package_commit_touched_functions')
    .delete()
    .eq('watched_package_id', watchedPackageId);
  if (deleteTouchedError) {
    console.warn(`Failed to delete existing touched functions:`, deleteTouchedError);
  }

  const { error: deleteError } = await supabase
    .from('package_commits')
    .delete()
    .eq('watched_package_id', watchedPackageId);

  if (deleteError) {
    console.warn(`Failed to delete existing commits:`, deleteError);
  }

  // Prepare commit data for insertion (guard against invalid dates from git log parsing)
  const safeTimestamp = (d: Date): string => {
    if (d && !isNaN(d.getTime())) return d.toISOString();
    return new Date(0).toISOString();
  };
  const commitData = commits.map(commit => ({
    watched_package_id: watchedPackageId,
    sha: commit.sha,
    author: commit.author,
    author_email: commit.authorEmail,
    message: commit.message.substring(0, 10000), // Limit message length
    timestamp: safeTimestamp(commit.timestamp),
    lines_added: commit.linesAdded,
    lines_deleted: commit.linesDeleted,
    files_changed: commit.filesChanged,
    diff_data: commit.diffData || null,
  }));

  // Insert in batches to avoid payload limits
  const batchSize = 50;
  for (let i = 0; i < commitData.length; i += batchSize) {
    const batch = commitData.slice(i, i + batchSize);
    const { error } = await supabase
      .from('package_commits')
      .insert(batch);

    if (error) {
      console.error(`Failed to insert commit batch:`, error);
      // Continue with other batches
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

  // Set last_known_commit_sha to the latest (most recent) commit so poller knows where we are
  const latestSha = commits[0]?.sha;
  if (latestSha) {
    const { error: updateError } = await supabase
      .from('watched_packages')
      .update({
        last_known_commit_sha: latestSha,
        updated_at: new Date().toISOString(),
      })
      .eq('id', watchedPackageId);
    if (updateError) {
      console.warn(`Failed to update last_known_commit_sha for ${watchedPackageId}:`, updateError);
    }
  }

  console.log(`[${new Date().toISOString()}] ✅ Stored ${commits.length} commits`);
}

/**
 * Store contributor profiles in the database
 */
export async function storeContributorProfiles(
  watchedPackageId: string,
  contributors: ContributorProfile[]
): Promise<Map<string, string>> {
  const emailToIdMap = new Map<string, string>();

  if (contributors.length === 0) {
    console.log(`[${new Date().toISOString()}] ⏭️ No contributors to store`);
    return emailToIdMap;
  }

  console.log(`[${new Date().toISOString()}] 💾 Storing ${contributors.length} contributor profiles...`);

  // First, delete any existing contributors for this package
  const { error: deleteError } = await supabase
    .from('package_contributors')
    .delete()
    .eq('watched_package_id', watchedPackageId);

  if (deleteError) {
    console.warn(`Failed to delete existing contributors:`, deleteError);
  }

  // Prepare contributor data for insertion
  const contributorData = contributors.map(c => ({
    watched_package_id: watchedPackageId,
    author_email: c.authorEmail,
    author_name: c.authorName,
    total_commits: c.totalCommits,
    avg_lines_added: c.avgLinesAdded,
    avg_lines_deleted: c.avgLinesDeleted,
    avg_files_changed: c.avgFilesChanged,
    stddev_lines_added: c.stddevLinesAdded,
    stddev_lines_deleted: c.stddevLinesDeleted,
    stddev_files_changed: c.stddevFilesChanged,
    avg_commit_message_length: c.avgCommitMessageLength,
    stddev_commit_message_length: c.stddevCommitMessageLength,
    insert_to_delete_ratio: c.insertToDeleteRatio,
    commit_time_histogram: c.commitTimeHistogram,
    typical_days_active: c.typicalDaysActive,
    commit_time_heatmap: c.commitTimeHeatmap,
    files_worked_on: c.filesWorkedOn,
    first_commit_date: c.firstCommitDate.toISOString(),
    last_commit_date: c.lastCommitDate.toISOString(),
  }));

  // Insert contributors and get their IDs
  const { data, error } = await supabase
    .from('package_contributors')
    .insert(contributorData)
    .select('id, author_email');

  if (error) {
    console.error(`Failed to insert contributors:`, error);
    throw new Error(`Database insert failed: ${error.message}`);
  }

  // Build email to ID map
  if (data) {
    for (const row of data) {
      emailToIdMap.set(row.author_email.toLowerCase(), row.id);
    }
  }

  console.log(`[${new Date().toISOString()}] ✅ Stored ${contributors.length} contributor profiles`);
  return emailToIdMap;
}

/**
 * Store anomaly detection results in the database
 */
export async function storeAnomalies(
  watchedPackageId: string,
  anomalies: AnomalyResult[],
  emailToIdMap: Map<string, string>
): Promise<void> {
  if (anomalies.length === 0) {
    console.log(`[${new Date().toISOString()}] ⏭️ No anomalies to store`);
    return;
  }

  console.log(`[${new Date().toISOString()}] 💾 Storing ${anomalies.length} anomalies...`);

  // First, delete any existing anomalies for this package
  const { error: deleteError } = await supabase
    .from('package_anomalies')
    .delete()
    .eq('watched_package_id', watchedPackageId);

  if (deleteError) {
    console.warn(`Failed to delete existing anomalies:`, deleteError);
  }

  // Prepare anomaly data for insertion
  const anomalyData = anomalies
    .filter(a => {
      // Only include anomalies where we have a contributor ID
      const contributorId = emailToIdMap.get(a.contributorEmail.toLowerCase());
      return !!contributorId;
    })
    .map(a => ({
      watched_package_id: watchedPackageId,
      commit_sha: a.commitSha,
      contributor_id: emailToIdMap.get(a.contributorEmail.toLowerCase()),
      anomaly_score: a.totalScore,
      score_breakdown: a.breakdown,
    }));

  if (anomalyData.length === 0) {
    console.log(`[${new Date().toISOString()}] ⏭️ No valid anomalies to store (missing contributor IDs)`);
    return;
  }

  // Insert in batches
  const batchSize = 50;
  for (let i = 0; i < anomalyData.length; i += batchSize) {
    const batch = anomalyData.slice(i, i + batchSize);
    const { error } = await supabase
      .from('package_anomalies')
      .insert(batch);

    if (error) {
      console.error(`Failed to insert anomaly batch:`, error);
      // Continue with other batches
    }
  }

  console.log(`[${new Date().toISOString()}] ✅ Stored ${anomalyData.length} anomalies`);
}

/**
 * Generate human-readable reason for registry integrity status
 */
function getRegistryIntegrityReason(results: FullAnalysisResults): string | null {
  if (results.registryIntegrityStatus === 'pass') {
    return null;
  }

  const integrity = results.registryIntegrity;

  // Check for errors first
  if (integrity.error) {
    return integrity.error;
  }

  // Check for modified files
  if (integrity.modifiedFiles && integrity.modifiedFiles.length > 0) {
    const isOnlyInNpmSuspicious = (f: { reason?: string }) => f.reason?.includes('possible supply chain risk');
    const isOnlyInNpmBuildArtifact = (f: { reason?: string }) => f.reason?.includes('likely build artifact');
    const onlyInNpmSuspicious = integrity.modifiedFiles.filter(isOnlyInNpmSuspicious);
    const onlyInNpmBuildArtifact = integrity.modifiedFiles.filter(isOnlyInNpmBuildArtifact);
    const contentDiffers = integrity.modifiedFiles.filter(
      f => !isOnlyInNpmSuspicious(f) && !isOnlyInNpmBuildArtifact(f)
    );
    const fileList = integrity.modifiedFiles.slice(0, 3).map(f => f.path).join(', ');
    if (onlyInNpmSuspicious.length > 0) {
      return onlyInNpmSuspicious.length <= 3
        ? `${onlyInNpmSuspicious.length} file(s) in npm but NOT in git (possible supply chain risk): ${onlyInNpmSuspicious.slice(0, 3).map(f => f.path).join(', ')}`
        : `${onlyInNpmSuspicious.length} file(s) in npm but NOT in git source (possible supply chain risk): ${fileList}...`;
    }
    if (onlyInNpmBuildArtifact.length > 0) {
      return onlyInNpmBuildArtifact.length <= 3
        ? `${onlyInNpmBuildArtifact.length} file(s) in npm but not in git (likely build artifacts): ${onlyInNpmBuildArtifact.slice(0, 3).map(f => f.path).join(', ')}`
        : `${onlyInNpmBuildArtifact.length} file(s) in npm but not in git (likely build artifacts e.g. cjs/umd/esm): ${fileList}...`;
    }
    if (contentDiffers.length <= 3) {
      return `Content differs from git: ${fileList}`;
    }
    return `${contentDiffers.length} file(s) differ between npm and git source (may be build artifacts): ${fileList}...`;
  }

  return 'Registry integrity check could not verify code matches git source';
}

/**
 * Generate human-readable reason for install scripts status
 */
function getInstallScriptsReason(results: FullAnalysisResults): string | null {
  if (results.installScriptsStatus === 'pass') {
    return null;
  }

  const scripts = results.scriptCapabilities;
  const reasons: string[] = [];

  // Check for dangerous patterns first (most severe)
  if (scripts.hasDangerousPatterns && scripts.dangerousPatterns.length > 0) {
    reasons.push(`Dangerous patterns: ${scripts.dangerousPatterns.slice(0, 3).join(', ')}`);
  }

  // Check for network + shell combination
  if (scripts.hasNetworkAccess && scripts.hasShellExecution) {
    reasons.push('Scripts have both network access and shell execution');
  } else if (scripts.hasNetworkAccess) {
    reasons.push('Scripts have network access');
  } else if (scripts.hasShellExecution) {
    reasons.push('Scripts have shell execution capabilities');
  }

  // Check for lifecycle hooks
  if (scripts.detectedScripts.length > 0) {
    const hooks = scripts.detectedScripts.map(s => s.stage).join(', ');
    reasons.push(`Lifecycle hooks detected: ${hooks}`);
  }

  return reasons.length > 0 ? reasons.join('. ') : 'Install scripts require manual review';
}

/**
 * Generate human-readable reason for entropy analysis status
 */
function getEntropyAnalysisReason(results: FullAnalysisResults): string | null {
  if (results.entropyAnalysisStatus === 'pass') {
    return null;
  }

  const entropy = results.entropyAnalysis;

  if (entropy.highEntropyFiles.length === 0) {
    return null;
  }

  // Find files in unexpected locations (not in dist/build/etc)
  const expectedDirs = ['dist', 'build', 'bundle', 'min', 'minified', 'vendor'];
  const unexpectedFiles = entropy.highEntropyFiles.filter(f => {
    return !expectedDirs.some(dir =>
      f.path.toLowerCase().includes(`/${dir}/`) ||
      f.path.toLowerCase().startsWith(`${dir}/`)
    );
  });

  if (unexpectedFiles.length > 0) {
    const count = unexpectedFiles.length;
    const maxEntropy = Math.max(...unexpectedFiles.map(f => f.entropy));
    const topFile = unexpectedFiles.find(f => f.entropy === maxEntropy);
    if (count === 1) {
      return `High-entropy file in source: ${topFile?.path} (entropy: ${maxEntropy.toFixed(1)})`;
    }
    return `${count} high-entropy file(s) in unexpected locations (max entropy: ${maxEntropy.toFixed(1)})`;
  }

  // All high entropy files are in expected locations
  return `${entropy.highEntropyFiles.length} minified/bundled file(s) detected`;
}

// ============================================================================
// AUTO-BUMP: candidate projects, watchlist, dependency latest version
// ============================================================================

export interface CandidateProject {
  project_id: string;
  organization_id: string;
  current_version: string;
}

type PdRow = { project_id: string; version: string; files_importing_count?: number | null };

/**
 * Get projects that have this package as a direct dependency and auto_bump = true.
 * Excludes zombie packages (files_importing_count === 0) and projects that already have a removal PR.
 * Prefer dependency_id (canonical); fallback to name if no rows have dependency_id set (legacy).
 * Includes both prod and dev direct deps (source in 'dependencies', 'devDependencies').
 */
export async function getCandidateProjectsForAutoBump(
  dependencyId: string,
  packageName: string
): Promise<CandidateProject[]> {
  let pdRows: PdRow[] | null = null;
  let pdError: { message: string } | null = null;

  const byDependencyId = await supabase
    .from('project_dependencies')
    .select('project_id, version, files_importing_count')
    .eq('dependency_id', dependencyId)
    .eq('is_direct', true)
    .in('source', ['dependencies', 'devDependencies']);
  pdError = byDependencyId.error;
  pdRows = byDependencyId.data as PdRow[] | null;
  // #region agent log
  const _byDepIdCount = byDependencyId.data?.length ?? 0;
  let _byNameCount = 0;
  // #endregion

  if (!pdError && pdRows?.length === 0) {
    const byName = await supabase
      .from('project_dependencies')
      .select('project_id, version, files_importing_count')
      .eq('name', packageName)
      .eq('is_direct', true)
      .in('source', ['dependencies', 'devDependencies']);
    _byNameCount = byName.data?.length ?? 0;
    if (!byName.error && byName.data?.length) {
      pdRows = byName.data as PdRow[];
    }
  }

  if (pdError) {
    console.warn(`[${new Date().toISOString()}] getCandidateProjectsForAutoBump query error for ${packageName}:`, pdError.message);
    return [];
  }
  if (!pdRows?.length) {
    console.log(`[${new Date().toISOString()}] No project_dependencies rows for dependency_id=${dependencyId} (${packageName}) with is_direct=true and source in dependencies/devDependencies (and name fallback had no rows)`);
    return [];
  }

  // Exclude zombie packages (not imported anywhere)
  pdRows = pdRows.filter((r) => (r.files_importing_count ?? 0) > 0);
  if (pdRows.length === 0) {
    console.log(`[${new Date().toISOString()}] No non-zombie project_dependencies for ${packageName} (all have files_importing_count 0)`);
    return [];
  }

  const projectIds = [...new Set(pdRows.map((r) => r.project_id))];
  // Include projects where auto_bump is true OR null (default on); exclude only explicit false
  const { data: projects, error: projError } = await supabase
    .from('projects')
    .select('id, organization_id')
    .in('id', projectIds)
    .or('auto_bump.eq.true,auto_bump.is.null');
  // #region agent log
  fetch('http://127.0.0.1:7243/ingest/abaca787-5416-40c4-b6fe-aea97fa8dfd8', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'storage.ts:getCandidateProjectsForAutoBump', message: 'query counts', data: { packageName, dependencyId, byDependencyIdRowCount: _byDepIdCount, byNameRowCount: _byNameCount, pdRowsCount: pdRows?.length ?? 0, projectIdsCount: projectIds.length, projectsWithAutoBumpCount: projects?.length ?? 0 }, timestamp: Date.now(), sessionId: 'debug-session', hypothesisId: 'A', runId: 'post-fix' }) }).catch(() => {});
  // #endregion

  if (projError) {
    console.warn(`[${new Date().toISOString()}] getCandidateProjectsForAutoBump projects query error:`, projError.message);
    return [];
  }
  if (!projects?.length) {
    console.log(`[${new Date().toISOString()}] Found ${pdRows.length} project_dependencies for ${packageName} but 0 projects with auto_bump true or null (project_ids: ${projectIds.slice(0, 3).join(', ')}${projectIds.length > 3 ? '...' : ''})`);
    return [];
  }

  // Exclude projects that already have a removal PR for this package
  const { data: removalPrRows, error: removalError } = await supabase
    .from('dependency_prs')
    .select('project_id')
    .in('project_id', projectIds)
    .eq('dependency_id', dependencyId)
    .eq('type', 'remove');
  const projectIdsWithRemovalPr = new Set<string>();
  if (!removalError && removalPrRows?.length) {
    for (const row of removalPrRows as { project_id: string }[]) {
      projectIdsWithRemovalPr.add(row.project_id);
    }
  }
  const projectsWithoutRemovalPr = projects.filter(
    (p: { id: string }) => !projectIdsWithRemovalPr.has(p.id)
  );
  if (projectsWithoutRemovalPr.length === 0) {
    console.log(`[${new Date().toISOString()}] All candidate projects for ${packageName} already have a removal PR open`);
    return [];
  }

  const versionByProject = new Map<string, string>();
  for (const r of pdRows) {
    versionByProject.set(r.project_id, r.version);
  }

  return projectsWithoutRemovalPr.map((p: { id: string; organization_id: string }) => ({
    project_id: p.id,
    organization_id: p.organization_id,
    current_version: versionByProject.get(p.id) ?? '',
  }));
}

/**
 * Get latest_version for a dependency (for quarantine_expired target and quarantine_until).
 */
export async function getDependencyLatestVersion(dependencyId: string): Promise<string | null> {
  const { data, error } = await supabase
    .from('dependencies')
    .select('latest_version')
    .eq('id', dependencyId)
    .single();
  if (error || !data) return null;
  return (data as { latest_version: string | null }).latest_version ?? null;
}

/**
 * Get latest_release_date for a dependency (for quarantine_until = latest_release_date + 7 days).
 */
export async function getDependencyLatestReleaseDate(dependencyId: string): Promise<string | null> {
  const { data, error } = await supabase
    .from('dependencies')
    .select('latest_release_date')
    .eq('id', dependencyId)
    .single();
  if (error || !data) return null;
  const d = (data as { latest_release_date: string | null }).latest_release_date;
  return d ?? null;
}

export interface WatchlistRow {
  id: string;
  organization_id: string;
  dependency_id: string;
  quarantine_next_release: boolean;
  is_current_version_quarantined: boolean;
  quarantine_until: string | null;
  latest_allowed_version: string | null;
}

export async function getWatchlistRow(
  organizationId: string,
  dependencyId: string
): Promise<WatchlistRow | null> {
  const { data, error } = await supabase
    .from('organization_watchlist')
    .select('id, organization_id, dependency_id, quarantine_next_release, is_current_version_quarantined, quarantine_until, latest_allowed_version')
    .eq('organization_id', organizationId)
    .eq('dependency_id', dependencyId)
    .maybeSingle();
  if (error || !data) return null;
  return data as WatchlistRow;
}

/**
 * Case A: set quarantine for next release (quarantine_until = latest_release_date + 7 days).
 */
export async function updateWatchlistQuarantineNextRelease(
  watchlistId: string,
  quarantineUntil: string
): Promise<void> {
  const { error } = await supabase
    .from('organization_watchlist')
    .update({
      quarantine_next_release: false,
      is_current_version_quarantined: true,
      quarantine_until: quarantineUntil,
    })
    .eq('id', watchlistId);
  if (error) throw new Error(`Failed to update watchlist quarantine: ${error.message}`);

  // Invalidate watchtower summary cache
  try {
    const { data: watchlist } = await supabase
      .from('organization_watchlist')
      .select('dependency_id, dependencies!inner(name)')
      .eq('id', watchlistId)
      .single();
    if (watchlist?.dependencies) {
      const packageName = (watchlist.dependencies as any).name;
      const { invalidateWatchtowerSummaryCache } = await import('../../src/lib/cache');
      await invalidateWatchtowerSummaryCache(packageName).catch(() => {});
    }
  } catch {
    // Cache invalidation failed - non-fatal
  }
}

/**
 * Case B2: clear quarantine and set latest_allowed_version.
 */
export async function updateWatchlistClearQuarantineAndSetLatest(
  watchlistId: string,
  latestAllowedVersion: string
): Promise<void> {
  const { error } = await supabase
    .from('organization_watchlist')
    .update({
      is_current_version_quarantined: false,
      quarantine_until: null,
      latest_allowed_version: latestAllowedVersion,
    })
    .eq('id', watchlistId);
  if (error) throw new Error(`Failed to clear quarantine: ${error.message}`);

  // Invalidate watchtower summary cache
  try {
    const { data: watchlist } = await supabase
      .from('organization_watchlist')
      .select('dependency_id, dependencies!inner(name)')
      .eq('id', watchlistId)
      .single();
    if (watchlist?.dependencies) {
      const packageName = (watchlist.dependencies as any).name;
      const { invalidateWatchtowerSummaryCache } = await import('../../src/lib/cache');
      await invalidateWatchtowerSummaryCache(packageName).catch(() => {});
    }
  } catch {
    // Cache invalidation failed - non-fatal
  }
}

/**
 * Case C (or not in watchlist): set latest_allowed_version only (when creating PR).
 */
export async function updateWatchlistSetLatestAllowed(
  watchlistId: string,
  latestAllowedVersion: string
): Promise<void> {
  const { error } = await supabase
    .from('organization_watchlist')
    .update({ latest_allowed_version: latestAllowedVersion })
    .eq('id', watchlistId);
  if (error) throw new Error(`Failed to set latest_allowed_version: ${error.message}`);
}

/**
 * Store error on dependency_version when watchtower analysis fails.
 */
export async function setDependencyVersionError(
  dependencyId: string,
  version: string,
  errorMessage: string
): Promise<void> {
  await supabase
    .from('dependency_versions')
    .update({
      error_message: errorMessage,
      updated_at: new Date().toISOString(),
    })
    .eq('dependency_id', dependencyId)
    .eq('version', version);
}

export interface DependencyVulnerabilityRow {
  osv_id: string;
  affected_versions: unknown;
  fixed_versions: string[];
}

/**
 * Get all vulnerability rows for a dependency (for checking if target version is safe to bump to).
 */
export async function getDependencyVulnerabilities(dependencyId: string): Promise<DependencyVulnerabilityRow[]> {
  const { data, error } = await supabase
    .from('dependency_vulnerabilities')
    .select('osv_id, affected_versions, fixed_versions')
    .eq('dependency_id', dependencyId);
  if (error) return [];
  return (data ?? []) as DependencyVulnerabilityRow[];
}


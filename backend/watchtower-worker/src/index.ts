import 'dotenv/config';
import semver from 'semver';
import { supabase } from './supabase';
import { analyzePackage, analyzePackageVersion, cleanupTempDir } from './analyzer';
import {
  updateWatchedPackageStatus,
  updateWatchedPackageResults,
  upsertDependencyVersionAnalysis,
  getDependencyIdForWatchedPackage,
  getDependencyVersionRowId,
  setProjectDependencyVersionId,
  storePackageCommits,
  storeContributorProfiles,
  storeAnomalies,
  updateDependencyVersionAnalysis,
  getCandidateProjectsForAutoBump,
  getDependencyLatestVersion,
  getWatchlistRow,
  updateWatchlistQuarantineNextRelease,
  updateWatchlistClearQuarantineAndSetLatest,
  updateWatchlistSetLatestAllowed,
  setDependencyVersionError,
  getVersionsWithExistingAnalysis,
  getDependencyVulnerabilities,
} from './storage';
import { isVersionAffected, isVersionFixed } from './semver-affected';
import { createBumpPrForProject } from './create-bump-pr';

const MACHINE_ID = process.env.FLY_MACHINE_ID || `watchtower-${process.pid}-${Date.now()}`;
const HEARTBEAT_INTERVAL_MS = 60_000;
const IDLE_SHUTDOWN_MS = 60_000;
const MAX_MACHINE_RUNTIME_MS = 4 * 60 * 60 * 1000; // 4-hour watchdog

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:3001';
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY;

interface WatchtowerJobRow {
  id: string;
  status: string;
  job_type: string;
  priority: number;
  payload: Record<string, any>;
  organization_id: string | null;
  project_id: string | null;
  dependency_id: string | null;
  package_name: string;
  attempt: number;
  max_attempts: number;
  machine_id: string | null;
  heartbeat_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export interface WatchtowerJob {
  packageName: string;
  watchedPackageId: string;
  projectDependencyId: string;
  currentVersion?: string;
}

export interface NewVersionJob {
  type: 'new_version' | 'quarantine_expired';
  dependency_id: string;
  name: string;
  new_version?: string;
  latest_release_date?: string | null;
}

export interface BatchVersionAnalysisJob {
  type: 'batch_version_analysis';
  dependency_id: string;
  packageName: string;
  versions: string[];
}

interface WatchtowerEvent {
  event_type: 'security_analysis_failure' | 'supply_chain_anomaly' | 'new_version_available';
  organization_id: string;
  project_id?: string;
  package_name: string;
  payload: Record<string, any>;
  priority: 'critical' | 'high' | 'normal' | 'low';
}

async function emitWatchtowerEvent(event: WatchtowerEvent): Promise<void> {
  if (!BACKEND_URL || !INTERNAL_API_KEY) return;
  try {
    await fetch(`${BACKEND_URL}/api/internal/watchtower-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Api-Key': INTERNAL_API_KEY,
      },
      body: JSON.stringify(event),
    });
  } catch {
    // Fire-and-forget
  }
}

async function sendHeartbeat(jobId: string): Promise<void> {
  await supabase
    .from('watchtower_jobs')
    .update({ heartbeat_at: new Date().toISOString(), updated_at: new Date().toISOString() })
    .eq('id', jobId);
}

async function completeJob(jobId: string): Promise<void> {
  await supabase
    .from('watchtower_jobs')
    .update({ status: 'completed', completed_at: new Date().toISOString(), updated_at: new Date().toISOString() })
    .eq('id', jobId);
}

async function failJob(jobId: string, errorMessage: string): Promise<void> {
  await supabase
    .from('watchtower_jobs')
    .update({ status: 'failed', error_message: errorMessage, completed_at: new Date().toISOString(), updated_at: new Date().toISOString() })
    .eq('id', jobId);
}

async function claimJob(): Promise<WatchtowerJobRow | null> {
  const { data } = await supabase.rpc('claim_watchtower_job', { p_machine_id: MACHINE_ID });
  return (data as WatchtowerJobRow[] | null)?.[0] ?? null;
}

export async function isTargetVersionVulnerable(dependencyId: string, targetVersion: string): Promise<boolean> {
  const vulns = await getDependencyVulnerabilities(dependencyId);
  for (const v of vulns) {
    if (isVersionAffected(targetVersion, v.affected_versions) && !isVersionFixed(targetVersion, v.fixed_versions)) {
      return true;
    }
  }
  return false;
}

export async function runAutoBumpPrLogic(
  dependencyId: string,
  packageName: string,
  targetVersion: string,
  latestReleaseDate: string | null,
  organizationId?: string
): Promise<void> {
  const candidates = await getCandidateProjectsForAutoBump(dependencyId, packageName);
  if (candidates.length === 0) {
    console.log(`[${new Date().toISOString()}] No candidate projects for ${packageName}@${targetVersion}`);
    return;
  }
  const now = new Date();
  const quarantineUntilIso = latestReleaseDate
    ? new Date(new Date(latestReleaseDate).getTime() + 7 * 24 * 60 * 60 * 1000).toISOString()
    : new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();

  for (const proj of candidates) {
    try {
      const watchlist = await getWatchlistRow(proj.organization_id, dependencyId);
      const orgHasPackageOnWatchtower = watchlist != null;

      if (orgHasPackageOnWatchtower) {
        if (watchlist!.quarantine_next_release) {
          await updateWatchlistQuarantineNextRelease(watchlist!.id, quarantineUntilIso);
          console.log(`[${new Date().toISOString()}] Quarantine set for ${packageName} (org ${proj.organization_id}) until ${quarantineUntilIso}`);
          continue;
        }
        if (watchlist!.is_current_version_quarantined && !watchlist!.quarantine_next_release) {
          const quarantineExpired = !watchlist!.quarantine_until || new Date(watchlist!.quarantine_until) <= now;
          if (!quarantineExpired) continue;
          await updateWatchlistClearQuarantineAndSetLatest(watchlist!.id, targetVersion);
        } else {
          await updateWatchlistSetLatestAllowed(watchlist!.id, targetVersion);
        }
      }

      const result = await createBumpPrForProject(
        proj.organization_id,
        proj.project_id,
        packageName,
        targetVersion,
        proj.current_version || undefined
      );
      if ('error' in result && result.error) {
        console.warn(`[${new Date().toISOString()}] create-bump-pr failed for ${proj.project_id}: ${result.error}`);
      } else {
        console.log(`[${new Date().toISOString()}] Created bump PR for ${packageName}@${targetVersion} (project ${proj.project_id})`);
      }
      await new Promise((r) => setTimeout(r, 500));
    } catch (e: any) {
      console.warn(`[${new Date().toISOString()}] Auto-bump failed for project ${proj.project_id}:`, e.message);
    }
  }
}

export async function processNewVersionJob(job: NewVersionJob, orgId?: string): Promise<{ success: boolean; error?: string }> {
  const { type, dependency_id, name } = job;
  let targetVersion: string;
  let latestReleaseDate: string | null = null;

  if (type === 'quarantine_expired') {
    targetVersion = (await getDependencyLatestVersion(dependency_id)) ?? '';
    if (!targetVersion) {
      return { success: false, error: 'No latest_version' };
    }
  } else {
    targetVersion = job.new_version ?? '';
    latestReleaseDate = job.latest_release_date ?? null;
    if (!targetVersion) {
      return { success: false, error: 'Missing new_version' };
    }

    let tmpDir: string | undefined;
    try {
      const analysisResult = await analyzePackageVersion(name, targetVersion);
      tmpDir = analysisResult.tmpDir;
      if (!analysisResult.success) {
        await setDependencyVersionError(dependency_id, targetVersion, analysisResult.error ?? 'Analysis failed');
        if (orgId) {
          emitWatchtowerEvent({
            event_type: 'security_analysis_failure',
            organization_id: orgId,
            package_name: name,
            payload: { version: targetVersion, error: analysisResult.error },
            priority: 'high',
          });
        }
        return { success: false, error: analysisResult.error };
      }
      const data = analysisResult.data!;
      const failed =
        data.registryIntegrityStatus === 'fail' ||
        data.installScriptsStatus === 'fail' ||
        data.entropyAnalysisStatus === 'fail';
      if (failed) {
        await setDependencyVersionError(
          dependency_id,
          targetVersion,
          `Checks failed: registry=${data.registryIntegrityStatus} scripts=${data.installScriptsStatus} entropy=${data.entropyAnalysisStatus}`
        );
        if (orgId) {
          emitWatchtowerEvent({
            event_type: 'security_analysis_failure',
            organization_id: orgId,
            package_name: name,
            payload: {
              version: targetVersion,
              registry: data.registryIntegrityStatus,
              scripts: data.installScriptsStatus,
              entropy: data.entropyAnalysisStatus,
            },
            priority: 'high',
          });
        }
        return { success: false, error: 'One or more checks failed' };
      }
      await updateDependencyVersionAnalysis(dependency_id, targetVersion, data);

      if (orgId) {
        emitWatchtowerEvent({
          event_type: 'new_version_available',
          organization_id: orgId,
          package_name: name,
          payload: { version: targetVersion, checks: 'all_passed' },
          priority: 'low',
        });
      }
    } finally {
      if (tmpDir) cleanupTempDir(tmpDir);
    }
  }

  if (await isTargetVersionVulnerable(dependency_id, targetVersion)) {
    console.log(`[${new Date().toISOString()}] Skipping auto-bump for ${name}@${targetVersion}: target version is vulnerable`);
    return { success: true };
  }

  await runAutoBumpPrLogic(dependency_id, name, targetVersion, latestReleaseDate, orgId);
  return { success: true };
}

async function processBatchVersionJob(job: BatchVersionAnalysisJob): Promise<{ success: boolean; error?: string }> {
  const { dependency_id, packageName, versions } = job;
  const existing = await getVersionsWithExistingAnalysis(dependency_id, versions);
  const toAnalyze = versions.filter((v) => !existing.has(v));
  console.log(`[${new Date().toISOString()}] Batch analysis for ${packageName} (${toAnalyze.length}/${versions.length} versions)`);

  let successCount = 0;
  let failCount = 0;

  for (const version of toAnalyze) {
    let tmpDir: string | undefined;
    try {
      const result = await analyzePackageVersion(packageName, version);
      tmpDir = result.tmpDir;

      if (result.success && result.data) {
        await upsertDependencyVersionAnalysis(dependency_id, version, result.data);
        successCount++;
      } else {
        failCount++;
        await setDependencyVersionError(dependency_id, version, result.error ?? 'Analysis failed');
      }
    } catch (e: any) {
      failCount++;
      console.warn(`[${new Date().toISOString()}] ${packageName}@${version} error: ${e.message}`);
    } finally {
      if (tmpDir) cleanupTempDir(tmpDir);
    }
  }

  console.log(`[${new Date().toISOString()}] Batch complete for ${packageName}: ${successCount} succeeded, ${failCount} failed`);
  return { success: true };
}

function isStableVersion(version: string): boolean {
  if (!semver.valid(version)) return false;
  return !semver.prerelease(version);
}

async function getPreviousVersions(packageName: string, excludeVersions: string[], count: number = 20): Promise<string[]> {
  try {
    const encodedName = encodeURIComponent(packageName);
    const response = await fetch(`https://registry.npmjs.org/${encodedName}`);
    if (!response.ok) return [];
    const packageData = await response.json() as { versions?: Record<string, unknown>; time?: Record<string, string> };
    if (!packageData.versions || !packageData.time) return [];

    const excludeSet = new Set(excludeVersions);
    const allEntries = Object.keys(packageData.versions)
      .filter((v) => !excludeSet.has(v) && packageData.time![v])
      .map((v) => ({ version: v, time: new Date(packageData.time![v]).getTime(), stable: isStableVersion(v) }))
      .sort((a, b) => b.time - a.time);

    const stable = allEntries.filter((e) => e.stable).slice(0, count);
    if (stable.length >= count) return stable.map((e) => e.version);
    const extra = allEntries.filter((e) => !e.stable).slice(0, count - stable.length);
    return [...stable, ...extra].map((e) => e.version);
  } catch (e: any) {
    console.warn(`[${new Date().toISOString()}] Failed to fetch previous versions for ${packageName}: ${e.message}`);
    return [];
  }
}

async function processFullAnalysisJob(job: WatchtowerJobRow): Promise<{ success: boolean; error?: string }> {
  const payload = job.payload as { watchedPackageId?: string; projectDependencyId?: string; currentVersion?: string };
  const watchedPackageId = payload.watchedPackageId;
  const projectDependencyId = payload.projectDependencyId;
  const currentVersion = payload.currentVersion;

  if (!watchedPackageId) {
    return { success: false, error: 'Missing watchedPackageId in payload' };
  }

  let tmpDir: string | undefined;
  let currentVersionTmpDir: string | undefined;

  try {
    await updateWatchedPackageStatus(watchedPackageId, 'analyzing');

    const analysisResult = await analyzePackage(job.package_name);
    tmpDir = analysisResult.tmpDir;

    if (!analysisResult.success) {
      throw new Error(analysisResult.error || 'Analysis failed');
    }

    await updateWatchedPackageResults(watchedPackageId, analysisResult.data!);

    if (analysisResult.commits?.length) {
      await storePackageCommits(watchedPackageId, analysisResult.commits);
    }

    let emailToIdMap = new Map<string, string>();
    if (analysisResult.contributors?.length) {
      emailToIdMap = await storeContributorProfiles(watchedPackageId, analysisResult.contributors);
    }

    if (analysisResult.anomalies?.length) {
      await storeAnomalies(watchedPackageId, analysisResult.anomalies, emailToIdMap);

      const highAnomalies = analysisResult.anomalies.filter((a) => (a.totalScore ?? 0) >= 60);
      if (highAnomalies.length > 0 && job.organization_id) {
        for (const anomaly of highAnomalies.slice(0, 3)) {
          emitWatchtowerEvent({
            event_type: 'supply_chain_anomaly',
            organization_id: job.organization_id,
            project_id: job.project_id || undefined,
            package_name: job.package_name,
            payload: {
              commit_sha: anomaly.commitSha,
              author: anomaly.contributorEmail,
              anomaly_score: anomaly.totalScore,
            },
            priority: 'normal',
          });
        }
      }
    }

    // Check for security failures and emit events
    const data = analysisResult.data!;
    const anyFailed =
      data.registryIntegrityStatus === 'fail' ||
      data.installScriptsStatus === 'fail' ||
      data.entropyAnalysisStatus === 'fail';
    if (anyFailed && job.organization_id) {
      emitWatchtowerEvent({
        event_type: 'security_analysis_failure',
        organization_id: job.organization_id,
        project_id: job.project_id || undefined,
        package_name: job.package_name,
        payload: {
          registry: data.registryIntegrityStatus,
          scripts: data.installScriptsStatus,
          entropy: data.entropyAnalysisStatus,
        },
        priority: 'high',
      });
    }

    if (currentVersion && currentVersion !== analysisResult.data!.latestVersion) {
      const dependencyId = await getDependencyIdForWatchedPackage(watchedPackageId);
      if (dependencyId) {
        const currentResult = await analyzePackageVersion(job.package_name, currentVersion);
        currentVersionTmpDir = currentResult.tmpDir;
        if (currentResult.success && currentResult.data) {
          await upsertDependencyVersionAnalysis(dependencyId, currentVersion, currentResult.data);
          if (projectDependencyId) {
            const depVersionId = await getDependencyVersionRowId(dependencyId, currentVersion);
            if (depVersionId) {
              await setProjectDependencyVersionId(projectDependencyId, depVersionId);
            }
          }
        }
      }
    }

    // Queue batch version analysis
    try {
      const latestVersion = analysisResult.data!.latestVersion;
      const excludeVersions = [latestVersion];
      if (currentVersion && currentVersion !== latestVersion) {
        excludeVersions.push(currentVersion);
      }
      const dependencyId = await getDependencyIdForWatchedPackage(watchedPackageId);
      if (dependencyId) {
        const previousVersions = await getPreviousVersions(job.package_name, excludeVersions, 20);
        if (previousVersions.length > 0) {
          await supabase.from('watchtower_jobs').insert({
            job_type: 'batch_version_analysis',
            priority: 20,
            payload: { dependency_id: dependencyId, packageName: job.package_name, versions: previousVersions },
            organization_id: job.organization_id,
            project_id: job.project_id,
            dependency_id: dependencyId,
            package_name: job.package_name,
          });
        }
      }
    } catch (batchErr: any) {
      console.warn(`[${new Date().toISOString()}] Failed to queue batch version analysis: ${batchErr.message}`);
    }

    return { success: true };
  } catch (error: any) {
    console.error(`Error processing full analysis for ${job.package_name}:`, error);
    await updateWatchedPackageStatus(watchedPackageId, 'error', error.message);
    return { success: false, error: error.message };
  } finally {
    if (tmpDir) cleanupTempDir(tmpDir);
    if (currentVersionTmpDir) cleanupTempDir(currentVersionTmpDir);
  }
}

async function processPollSweepJob(job: WatchtowerJobRow): Promise<{ success: boolean; error?: string }> {
  const payload = job.payload as { watched_package_id?: string; last_known_commit_sha?: string };
  const watchedPackageId = payload.watched_package_id;
  if (!watchedPackageId) return { success: false, error: 'Missing watched_package_id' };

  try {
    const { data: pkg } = await supabase
      .from('watched_packages')
      .select('id, name, analysis_data, status')
      .eq('id', watchedPackageId)
      .single();

    if (!pkg || pkg.status !== 'ready') {
      return { success: true };
    }

    const analysisResult = await analyzePackage(pkg.name);
    if (!analysisResult.success) {
      console.warn(`[${new Date().toISOString()}] Poll sweep for ${pkg.name} failed: ${analysisResult.error}`);
      return { success: false, error: analysisResult.error };
    }

    if (analysisResult.tmpDir) cleanupTempDir(analysisResult.tmpDir);

    await updateWatchedPackageResults(watchedPackageId, analysisResult.data!);

    if (analysisResult.commits?.length) {
      await storePackageCommits(watchedPackageId, analysisResult.commits);
    }

    let emailToIdMap = new Map<string, string>();
    if (analysisResult.contributors?.length) {
      emailToIdMap = await storeContributorProfiles(watchedPackageId, analysisResult.contributors);
    }
    if (analysisResult.anomalies?.length) {
      await storeAnomalies(watchedPackageId, analysisResult.anomalies, emailToIdMap);
    }

    await supabase
      .from('watched_packages')
      .update({ last_polled_at: new Date().toISOString() })
      .eq('id', watchedPackageId);

    return { success: true };
  } catch (e: any) {
    console.error(`[${new Date().toISOString()}] Poll sweep error for ${job.package_name}:`, e.message);
    return { success: false, error: e.message };
  }
}

async function routeJob(job: WatchtowerJobRow): Promise<{ success: boolean; error?: string }> {
  switch (job.job_type) {
    case 'full_analysis':
      return processFullAnalysisJob(job);
    case 'new_version': {
      const payload = job.payload as NewVersionJob;
      return processNewVersionJob(
        {
          type: payload.type || 'new_version',
          dependency_id: job.dependency_id || payload.dependency_id || '',
          name: job.package_name,
          new_version: payload.new_version,
          latest_release_date: payload.latest_release_date,
        },
        job.organization_id || undefined
      );
    }
    case 'batch_version_analysis': {
      const payload = job.payload as BatchVersionAnalysisJob;
      return processBatchVersionJob({
        type: 'batch_version_analysis',
        dependency_id: job.dependency_id || payload.dependency_id || '',
        packageName: job.package_name,
        versions: payload.versions || [],
      });
    }
    case 'poll_sweep':
      return processPollSweepJob(job);
    default:
      return { success: false, error: `Unknown job type: ${job.job_type}` };
  }
}

async function runWorker(): Promise<void> {
  const startTime = Date.now();
  console.log(`[${new Date().toISOString()}] Watchtower Worker starting (Supabase polling, scale-to-zero)`);
  console.log(`[${new Date().toISOString()}] Machine ID: ${MACHINE_ID}`);

  let idleStart = Date.now();
  let pollCount = 0;

  while (true) {
    // 4-hour watchdog
    if (Date.now() - startTime > MAX_MACHINE_RUNTIME_MS) {
      console.log(`[${new Date().toISOString()}] 4-hour watchdog reached, shutting down`);
      process.exit(0);
    }

    try {
      pollCount++;
      const job = await claimJob();

      if (!job) {
        if (Date.now() - idleStart >= IDLE_SHUTDOWN_MS) {
          console.log(`[${new Date().toISOString()}] Idle for ${IDLE_SHUTDOWN_MS / 1000}s, shutting down`);
          process.exit(0);
        }
        await new Promise((r) => setTimeout(r, 5000));
        continue;
      }

      idleStart = Date.now();
      console.log(`[${new Date().toISOString()}] Claimed ${job.job_type} job for ${job.package_name} (id: ${job.id}, attempt: ${job.attempt})`);

      const heartbeatTimer = setInterval(() => sendHeartbeat(job.id), HEARTBEAT_INTERVAL_MS);

      try {
        const result = await routeJob(job);
        if (result.success) {
          await completeJob(job.id);
          console.log(`[${new Date().toISOString()}] Completed ${job.job_type} for ${job.package_name}`);
        } else {
          await failJob(job.id, result.error || 'Unknown error');
          console.error(`[${new Date().toISOString()}] Failed ${job.job_type} for ${job.package_name}: ${result.error}`);
        }
      } catch (err: any) {
        await failJob(job.id, err.message);
        console.error(`[${new Date().toISOString()}] Unhandled error for ${job.package_name}: ${err.message}`);
      } finally {
        clearInterval(heartbeatTimer);
      }
    } catch (error: any) {
      console.error('Error in worker loop:', error);
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
}

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  process.exit(0);
});

if (process.env.NODE_ENV !== 'test') {
  runWorker().catch((error) => {
    console.error('Fatal error in worker:', error);
    process.exit(1);
  });
}

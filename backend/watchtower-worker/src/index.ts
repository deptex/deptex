import 'dotenv/config';
import semver from 'semver';
import { Redis } from '@upstash/redis';
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
  getDependencyLatestReleaseDate,
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

const redisUrl = process.env.UPSTASH_REDIS_URL;
const redisToken = process.env.UPSTASH_REDIS_TOKEN;

// Guard Redis initialization so tests can import this module without env vars
let redis: Redis | null = null;
if (redisUrl && redisToken) {
  redis = new Redis({
    url: redisUrl,
    token: redisToken,
  });
}

// Use different queue name for local development to avoid conflicts with deployed workers
const QUEUE_NAME = process.env.WATCHTOWER_QUEUE_NAME ||
  (process.env.NODE_ENV === 'production' ? 'watchtower-jobs' : 'watchtower-jobs-local');
const NEW_VERSION_QUEUE_NAME = process.env.WATCHTOWER_NEW_VERSION_QUEUE_NAME ||
  (process.env.NODE_ENV === 'production' ? 'watchtower-new-version-jobs' : 'watchtower-new-version-jobs-local');
const BATCH_VERSION_QUEUE_NAME = process.env.WATCHTOWER_BATCH_VERSION_QUEUE_NAME ||
  (process.env.NODE_ENV === 'production' ? 'watchtower-batch-version-jobs' : 'watchtower-batch-version-jobs-local');
const WORKER_ID = `watchtower-worker-${process.pid}-${Date.now()}`;

export interface BatchVersionAnalysisJob {
  type: 'batch_version_analysis';
  dependency_id: string;
  packageName: string;
  versions: string[]; // up to 20 previous versions to analyze
}

export interface NewVersionJob {
  type: 'new_version' | 'quarantine_expired';
  dependency_id: string;
  name: string;
  new_version?: string;
  latest_release_date?: string | null;
}

// Test Redis connection on startup
async function testRedisConnection(): Promise<boolean> {
  if (!redis) return false;
  try {
    console.log(`[${new Date().toISOString()}] 🔌 Testing Redis connection...`);
    const pingResult = await redis.ping();
    console.log(`[${new Date().toISOString()}] ✅ Redis connection successful (ping: ${pingResult})`);
    
    // Check queue length
    const queueLength = await redis.llen(QUEUE_NAME);
    console.log(`[${new Date().toISOString()}] 📊 Current queue length: ${queueLength} jobs`);
    
    if (queueLength > 0) {
      console.log(`[${new Date().toISOString()}] ⚠️  Found ${queueLength} job(s) waiting in queue - will process them now`);
    }
    
    return true;
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Redis connection failed:`, error.message);
    return false;
  }
}

export interface WatchtowerJob {
  packageName: string;
  watchedPackageId: string;
  projectDependencyId: string;
  /** Version the project is using; worker runs integrity checks on this and on latest. */
  currentVersion?: string;
}

/**
 * Returns true if the target version is affected by any known vulnerability and not fixed.
 * We must not auto-bump to a vulnerable version.
 */
export async function isTargetVersionVulnerable(dependencyId: string, targetVersion: string): Promise<boolean> {
  const vulns = await getDependencyVulnerabilities(dependencyId);
  for (const v of vulns) {
    if (isVersionAffected(targetVersion, v.affected_versions) && !isVersionFixed(targetVersion, v.fixed_versions)) {
      return true;
    }
  }
  return false;
}

/**
 * Run PR and quarantine logic for a dependency + target version (after analysis passes or quarantine expired).
 * - Candidates = projects that have this dependency as direct AND have auto_bump on (true or null); see getCandidateProjectsForAutoBump.
 * - Only creates bump PR when org does NOT have this package on Watchtower (no watchlist row) = "auto bump".
 * - When org HAS package on Watchtower (watchlist exists), we apply quarantine rules instead; PR only after quarantine allows.
 */
export async function runAutoBumpPrLogic(
  dependencyId: string,
  packageName: string,
  targetVersion: string,
  latestReleaseDate: string | null
): Promise<void> {
  const candidates = await getCandidateProjectsForAutoBump(dependencyId, packageName);
  // #region agent log
  fetch('http://127.0.0.1:7243/ingest/abaca787-5416-40c4-b6fe-aea97fa8dfd8', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'index.ts:runAutoBumpPrLogic:after-getCandidates', message: 'candidate count', data: { packageName, targetVersion, candidateCount: candidates.length, projectIds: candidates.slice(0, 3).map(c => c.project_id) }, timestamp: Date.now(), sessionId: 'debug-session', hypothesisId: 'A' }) }).catch(() => {});
  // #endregion
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
        // Org has this package on Watchtower: apply quarantine/watchlist rules; only create PR when allowed.
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
      // Org does NOT have this package on Watchtower (watchlist === null): auto-bump = create PR.

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

/**
 * Process a new_version or quarantine_expired job (auto-bump pipeline).
 */
export async function processNewVersionJob(job: NewVersionJob): Promise<{ success: boolean; error?: string }> {
  const { type, dependency_id, name } = job;
  // #region agent log
  fetch('http://127.0.0.1:7243/ingest/abaca787-5416-40c4-b6fe-aea97fa8dfd8', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'index.ts:processNewVersionJob:entry', message: 'auto-bump job received', data: { type, dependency_id, name, new_version: job.new_version }, timestamp: Date.now(), sessionId: 'debug-session', hypothesisId: 'D' }) }).catch(() => {});
  // #endregion
  let targetVersion: string;
  let latestReleaseDate: string | null = null;

  if (type === 'quarantine_expired') {
    targetVersion = (await getDependencyLatestVersion(dependency_id)) ?? '';
    if (!targetVersion) {
      console.warn(`[${new Date().toISOString()}] No latest_version for dependency ${dependency_id}, skipping quarantine_expired`);
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
        return { success: false, error: analysisResult.error };
      }
      const data = analysisResult.data!;
      const failed =
        data.registryIntegrityStatus === 'fail' ||
        data.installScriptsStatus === 'fail' ||
        data.entropyAnalysisStatus === 'fail';
      // #region agent log
      fetch('http://127.0.0.1:7243/ingest/abaca787-5416-40c4-b6fe-aea97fa8dfd8', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'index.ts:processNewVersionJob:after-analysis', message: 'analysis result', data: { name, targetVersion, failed, registry: data.registryIntegrityStatus, scripts: data.installScriptsStatus, entropy: data.entropyAnalysisStatus }, timestamp: Date.now(), sessionId: 'debug-session', hypothesisId: 'E' }) }).catch(() => {});
      // #endregion
      if (failed) {
        await setDependencyVersionError(
          dependency_id,
          targetVersion,
          `Checks failed: registry=${data.registryIntegrityStatus} scripts=${data.installScriptsStatus} entropy=${data.entropyAnalysisStatus}`
        );
        return { success: false, error: 'One or more checks failed' };
      }
      await updateDependencyVersionAnalysis(dependency_id, targetVersion, data);
    } finally {
      if (tmpDir) cleanupTempDir(tmpDir);
    }
  }

  // Do not auto-bump to a version that is known vulnerable.
  if (await isTargetVersionVulnerable(dependency_id, targetVersion)) {
    console.log(`[${new Date().toISOString()}] ⚠️ Skipping auto-bump for ${name}@${targetVersion}: target version is affected by a known vulnerability`);
    return { success: true };
  }

  await runAutoBumpPrLogic(dependency_id, name, targetVersion, latestReleaseDate);
  return { success: true };
}

/**
 * Process a batch version analysis job — runs the three checks on up to 20 previous versions.
 * This is a low-priority background job that never blocks primary analysis or auto-bump.
 */
async function processBatchVersionJob(job: BatchVersionAnalysisJob): Promise<{ success: boolean; error?: string }> {
  const { dependency_id, packageName, versions } = job;
  const existing = await getVersionsWithExistingAnalysis(dependency_id, versions);
  const toAnalyze = versions.filter((v) => !existing.has(v));
  if (existing.size > 0) {
    console.log(`[${new Date().toISOString()}] 📦 Skipping ${existing.size} version(s) already in DB for ${packageName}`);
  }
  console.log(`[${new Date().toISOString()}] 📦 Processing batch version analysis for ${packageName} (${toAnalyze.length} versions)`);

  let successCount = 0;
  let failCount = 0;

  for (const version of toAnalyze) {
    let tmpDir: string | undefined;
    try {
      console.log(`[${new Date().toISOString()}] 🔍 Analyzing ${packageName}@${version}...`);
      const result = await analyzePackageVersion(packageName, version);
      tmpDir = result.tmpDir;

      if (result.success && result.data) {
        await upsertDependencyVersionAnalysis(dependency_id, version, result.data);
        successCount++;
        console.log(`[${new Date().toISOString()}] ✅ ${packageName}@${version} analysis stored`);
      } else {
        failCount++;
        await setDependencyVersionError(dependency_id, version, result.error ?? 'Analysis failed');
        console.warn(`[${new Date().toISOString()}] ⚠️ ${packageName}@${version} analysis failed: ${result.error}`);
      }
    } catch (e: any) {
      failCount++;
      console.warn(`[${new Date().toISOString()}] ⚠️ ${packageName}@${version} error: ${e.message}`);
    } finally {
      if (tmpDir) cleanupTempDir(tmpDir);
    }
  }

  console.log(`[${new Date().toISOString()}] 📦 Batch complete for ${packageName}: ${successCount} succeeded, ${failCount} failed`);
  return { success: true };
}

/** True if version is a stable release (no canary/experimental/alpha/beta/rc). */
function isStableVersion(version: string): boolean {
  if (!semver.valid(version)) return false;
  return !semver.prerelease(version);
}

/**
 * Fetch the previous N stable versions (by publish date) from npm registry, excluding specified versions.
 * Prefers stable releases over canary/experimental so projects using 19.1.x etc. get analyzed.
 */
async function getPreviousVersions(
  packageName: string,
  excludeVersions: string[],
  count: number = 20
): Promise<string[]> {
  try {
    const encodedName = encodeURIComponent(packageName);
    const response = await fetch(`https://registry.npmjs.org/${encodedName}`);
    if (!response.ok) return [];

    const packageData = await response.json() as {
      versions?: Record<string, unknown>;
      time?: Record<string, string>;
    };

    if (!packageData.versions || !packageData.time) return [];

    const excludeSet = new Set(excludeVersions);
    // Prefer stable versions; only include prereleases if we need more to reach count
    const allEntries = Object.keys(packageData.versions)
      .filter((v) => !excludeSet.has(v) && packageData.time![v])
      .map((v) => ({ version: v, time: new Date(packageData.time![v]).getTime(), stable: isStableVersion(v) }))
      .sort((a, b) => b.time - a.time);

    const stable = allEntries.filter((e) => e.stable).slice(0, count);
    if (stable.length >= count) return stable.map((e) => e.version);
    // Fill with prereleases if we need more
    const extra = allEntries.filter((e) => !e.stable).slice(0, count - stable.length);
    return [...stable, ...extra].map((e) => e.version);
  } catch (e: any) {
    console.warn(`[${new Date().toISOString()}] Failed to fetch previous versions for ${packageName}: ${e.message}`);
    return [];
  }
}

/**
 * Process a single Watchtower job
 */
async function processJob(job: WatchtowerJob): Promise<{ success: boolean; error?: string }> {
  const startTime = new Date().toISOString();
  console.log(`[${startTime}] 🚀 Processing Watchtower job for ${job.packageName}`);

  let tmpDir: string | undefined;
  let currentVersionTmpDir: string | undefined;

  try {
    // Update status to analyzing
    await updateWatchedPackageStatus(job.watchedPackageId, 'analyzing');

    // Analyze the package (full pipeline: npm metadata, tarball, git, all checks)
    console.log(`[${new Date().toISOString()}] 🔍 Running full analysis for ${job.packageName}...`);
    const analysisResult = await analyzePackage(job.packageName);

    // Store the temp directory path for cleanup
    tmpDir = analysisResult.tmpDir;

    if (!analysisResult.success) {
      throw new Error(analysisResult.error || 'Analysis failed');
    }

    // Store main analysis results in watched_packages table
    console.log(`[${new Date().toISOString()}] 💾 Storing analysis results...`);
    await updateWatchedPackageResults(job.watchedPackageId, analysisResult.data!);

    // Store commits if available
    if (analysisResult.commits && analysisResult.commits.length > 0) {
      console.log(`[${new Date().toISOString()}] 💾 Storing ${analysisResult.commits.length} commits...`);
      await storePackageCommits(job.watchedPackageId, analysisResult.commits);
    }

    // Store contributor profiles if available
    let emailToIdMap = new Map<string, string>();
    if (analysisResult.contributors && analysisResult.contributors.length > 0) {
      console.log(`[${new Date().toISOString()}] 💾 Storing ${analysisResult.contributors.length} contributor profiles...`);
      emailToIdMap = await storeContributorProfiles(job.watchedPackageId, analysisResult.contributors);
    }

    // Store anomalies if available
    if (analysisResult.anomalies && analysisResult.anomalies.length > 0) {
      console.log(`[${new Date().toISOString()}] 💾 Storing ${analysisResult.anomalies.length} anomalies...`);
      await storeAnomalies(job.watchedPackageId, analysisResult.anomalies, emailToIdMap);
    }

    // Run integrity checks on current version (project's version) if different from latest, and store + link
    if (job.currentVersion && job.currentVersion !== analysisResult.data!.latestVersion) {
      const dependencyId = await getDependencyIdForWatchedPackage(job.watchedPackageId);
      if (dependencyId) {
        console.log(`[${new Date().toISOString()}] 🔍 Analyzing current version ${job.currentVersion} (project's version)...`);
        const currentResult = await analyzePackageVersion(job.packageName, job.currentVersion);
        currentVersionTmpDir = currentResult.tmpDir;
        if (currentResult.success && currentResult.data) {
          await upsertDependencyVersionAnalysis(dependencyId, job.currentVersion, currentResult.data);
          if (job.projectDependencyId) {
            const depVersionId = await getDependencyVersionRowId(dependencyId, job.currentVersion);
            if (depVersionId) {
              await setProjectDependencyVersionId(job.projectDependencyId, depVersionId);
            }
          }
        }
      }
    }

    // Queue batch version analysis for the previous 20 versions (low-priority background job)
    try {
      const latestVersion = analysisResult.data!.latestVersion;
      const excludeVersions = [latestVersion];
      if (job.currentVersion && job.currentVersion !== latestVersion) {
        excludeVersions.push(job.currentVersion);
      }
      const dependencyId = await getDependencyIdForWatchedPackage(job.watchedPackageId);
      if (dependencyId) {
        const previousVersions = await getPreviousVersions(job.packageName, excludeVersions, 20);
        if (previousVersions.length > 0) {
          const batchJob: BatchVersionAnalysisJob = {
            type: 'batch_version_analysis',
            dependency_id: dependencyId,
            packageName: job.packageName,
            versions: previousVersions,
          };
          await redis.rpush(BATCH_VERSION_QUEUE_NAME, JSON.stringify(batchJob));
          console.log(`[${new Date().toISOString()}] 📦 Queued batch version analysis for ${job.packageName} (${previousVersions.length} versions)`);
        }
      }
    } catch (batchErr: any) {
      // Non-fatal: don't fail the main job if batch queueing fails
      console.warn(`[${new Date().toISOString()}] ⚠️ Failed to queue batch version analysis: ${batchErr.message}`);
    }

    console.log(`[${new Date().toISOString()}] ✅ Successfully processed Watchtower job for ${job.packageName}`);
    return { success: true };
  } catch (error: any) {
    console.error(`Error processing job for ${job.packageName}:`, error);
    
    // Update status to error
    await updateWatchedPackageStatus(job.watchedPackageId, 'error', error.message);
    
    return { success: false, error: error.message };
  } finally {
    // Clean up temp directories
    if (tmpDir) {
      console.log(`[${new Date().toISOString()}] 🧹 Cleaning up temp directory...`);
      cleanupTempDir(tmpDir);
    }
    if (currentVersionTmpDir) {
      cleanupTempDir(currentVersionTmpDir);
    }
  }
}

/**
 * Main worker loop - continuously polls Redis for jobs
 */
async function runWorker(): Promise<void> {
  if (!redis) {
    console.error('Redis not initialized. Set UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN.');
    process.exit(1);
  }
  const startTime = new Date().toISOString();
  console.log(`[${startTime}] ========================================`);
  console.log(`[${startTime}] Watchtower Worker starting...`);
  console.log(`[${startTime}] ========================================`);
  console.log(`[${startTime}] Queue name: ${QUEUE_NAME}`);
  console.log(`[${startTime}] Auto-bump queue: ${NEW_VERSION_QUEUE_NAME}`);
  console.log(`[${startTime}] Batch version queue: ${BATCH_VERSION_QUEUE_NAME}`);
  console.log(`[${startTime}] Redis URL configured: ${!!redisUrl}`);
  console.log(`[${startTime}] Redis Token configured: ${!!redisToken}`);
  
  // Test Redis connection
  const redisConnected = await testRedisConnection();
  if (!redisConnected) {
    console.error(`[${startTime}] ❌ Cannot start worker - Redis connection failed`);
    process.exit(1);
  }
  
  console.log(`[${startTime}] ✅ Worker ready, starting to poll for jobs...`);
  console.log(`[${startTime}] Worker ID: ${WORKER_ID} (PID: ${process.pid})`);
  console.log(`[${startTime}] ========================================`);

  let pollCount = 0;

  while (true) {
    try {
      pollCount++;
      const pollStartTime = new Date().toISOString();
      
      // Only log every 10th poll to reduce noise
      if (pollCount % 10 === 1) {
        console.log(`[${pollStartTime}] 🔄 Poll #${pollCount} on queue '${QUEUE_NAME}'`);
      }
      
      // Poll: first new-version queue (auto-bump), then main watchtower queue, then batch version queue (lowest priority)
      let jobData: string | WatchtowerJob | NewVersionJob | BatchVersionAnalysisJob | null = null;
      let isNewVersionJob = false;
      let isBatchVersionJob = false;

      const newVersionLength = await redis.llen(NEW_VERSION_QUEUE_NAME);
      if (newVersionLength > 0) {
        jobData = await redis.lpop(NEW_VERSION_QUEUE_NAME) as string | NewVersionJob | null;
        isNewVersionJob = true;
        // #region agent log
        const _j = typeof jobData === 'string' ? JSON.parse(jobData) : jobData;
        fetch('http://127.0.0.1:7243/ingest/abaca787-5416-40c4-b6fe-aea97fa8dfd8', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ location: 'index.ts:worker-loop:popped-new-version-job', message: 'job popped from new-version queue', data: { queueLength: newVersionLength, type: (_j as any)?.type, name: (_j as any)?.name, dependency_id: (_j as any)?.dependency_id }, timestamp: Date.now(), sessionId: 'debug-session', hypothesisId: 'D' }) }).catch(() => {});
        // #endregion
      }
      if (!jobData) {
        const queueLengthBefore = await redis.llen(QUEUE_NAME);
        if (queueLengthBefore > 0) {
          console.log(`[${new Date().toISOString()}] 📬 Found ${queueLengthBefore} job(s) in queue, processing...`);
          jobData = await redis.lpop(QUEUE_NAME) as string | WatchtowerJob | null;
        }
      } else {
        console.log(`[${new Date().toISOString()}] 📬 Processing auto-bump job from ${NEW_VERSION_QUEUE_NAME}`);
      }
      // Lowest priority: batch version analysis queue
      if (!jobData) {
        const batchLength = await redis.llen(BATCH_VERSION_QUEUE_NAME);
        if (batchLength > 0) {
          console.log(`[${new Date().toISOString()}] 📬 Found ${batchLength} batch version job(s), processing...`);
          jobData = await redis.lpop(BATCH_VERSION_QUEUE_NAME) as string | BatchVersionAnalysisJob | null;
          isBatchVersionJob = true;
        }
      }

      if (jobData) {
        if (isNewVersionJob) {
          let job: NewVersionJob;
          if (typeof jobData === 'string') {
            job = JSON.parse(jobData) as NewVersionJob;
          } else {
            job = jobData as NewVersionJob;
          }
          const jobResult = await processNewVersionJob(job);
          if (!jobResult.success) {
            console.error(`[${new Date().toISOString()}] Auto-bump job failed: ${jobResult.error}`);
          } else {
            console.log(`[${new Date().toISOString()}] ✅ Auto-bump job completed for ${job.name}`);
          }
        } else if (isBatchVersionJob) {
          let job: BatchVersionAnalysisJob;
          if (typeof jobData === 'string') {
            job = JSON.parse(jobData) as BatchVersionAnalysisJob;
          } else {
            job = jobData as BatchVersionAnalysisJob;
          }
          const jobResult = await processBatchVersionJob(job);
          if (!jobResult.success) {
            console.error(`[${new Date().toISOString()}] Batch version job failed: ${jobResult.error}`);
          } else {
            console.log(`[${new Date().toISOString()}] ✅ Batch version job completed for ${job.packageName}`);
          }
        } else {
          let job: WatchtowerJob;
          if (typeof jobData === 'string') {
            job = JSON.parse(jobData) as WatchtowerJob;
          } else if (typeof jobData === 'object' && jobData !== null) {
            job = jobData as WatchtowerJob;
          } else {
            throw new Error(`Unexpected jobData type: ${typeof jobData}`);
          }
          const jobResult = await processJob(job);
          if (!jobResult.success) {
            console.error(`[${new Date().toISOString()}] Job failed: ${jobResult.error}`);
          } else {
            console.log(`[${new Date().toISOString()}] ✅ Job completed successfully for ${job.packageName}`);
          }
        }
      } else {
        // No job available, wait before polling again
        await new Promise((resolve) => setTimeout(resolve, 5000));
      }
    } catch (error: any) {
      console.error('Error in worker loop:', error);
      // Wait a bit before retrying to avoid tight error loops
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  process.exit(0);
});

// Start the worker (skip when running under test runner)
if (process.env.NODE_ENV !== 'test') {
  runWorker().catch((error) => {
    console.error('Fatal error in worker:', error);
    process.exit(1);
  });
}

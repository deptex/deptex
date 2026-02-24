import 'dotenv/config';
import {
  testRedisConnection,
  getDueDailyPollJob,
  scheduleDailyPollJob,
  hasDailyPollScheduled,
  getNextDailyPollRunAt,
  TWENTY_FOUR_HOURS_MS,
} from './scheduler';
import { runDependencyRefresh } from './dependency-refresh';
import { checkForNewCommits, parseRepositoryUrl } from './remote-check';
import { analyzeNewCommits, cleanupTempDir } from './incremental-analyzer';
import { calculateAnomaliesForCommits } from './anomaly-detection';
import {
  getReadyWatchedPackages,
  updatePollingStatus,
  storeNewCommits,
  getContributorProfiles,
  storeAnomalies,
  updateAnalysisData,
  getGithubUrlFromPackage,
  WatchedPackageInfo,
} from './storage';

const WORKER_ID = `watchtower-poller-${process.pid}-${Date.now()}`;
const CHECK_INTERVAL_MS = 60000; // Check every 60s for due Daily poll job

/**
 * Process one watched package: check for new commits, analyze, store. Uses DB row (no queue).
 */
async function processOneWatchedPackage(pkg: WatchedPackageInfo): Promise<{ success: boolean; error?: string }> {
  const startTime = new Date().toISOString();
  console.log(`[${startTime}] ========================================`);
  console.log(`[${startTime}] 🔍 Polling ${pkg.name} (${pkg.id})`);
  console.log(`[${startTime}] ========================================`);

  let tmpDir: string | undefined;

  try {
    let githubUrl = getGithubUrlFromPackage(pkg);
    if (!githubUrl && pkg.analysis_data?.repository) {
      githubUrl = parseRepositoryUrl(pkg.analysis_data.repository);
    }
    if (!githubUrl) {
      console.log(`[${new Date().toISOString()}] ⚠️ No GitHub URL for ${pkg.name}, skipping`);
      return { success: true };
    }

    console.log(`[${new Date().toISOString()}] 🔗 GitHub URL: ${githubUrl}`);
    console.log(`[${new Date().toISOString()}] 📌 Last known SHA: ${pkg.last_known_commit_sha || '(none)'}`);

    const remoteCheck = await checkForNewCommits(githubUrl, pkg.last_known_commit_sha);
    if (remoteCheck.error) {
      console.error(`[${new Date().toISOString()}] ❌ Failed to check remote: ${remoteCheck.error}`);
      return { success: false, error: remoteCheck.error };
    }

    let newCommitsCount = 0;
    let anomaliesCount = 0;
    let currentHeadSha = pkg.last_known_commit_sha || remoteCheck.currentSha!;

    if (!remoteCheck.hasChanges) {
      console.log(`[${new Date().toISOString()}] ✅ No new commits detected`);
    } else {
      console.log(`[${new Date().toISOString()}] 📬 New commits detected! Current HEAD: ${remoteCheck.currentSha}`);

      const analysisResult = await analyzeNewCommits(
        githubUrl,
        pkg.name,
        pkg.last_known_commit_sha
      );
      tmpDir = analysisResult.tmpDir;

      if (!analysisResult.success) {
        console.error(`[${new Date().toISOString()}] ❌ Analysis failed: ${analysisResult.error}`);
        return { success: false, error: analysisResult.error };
      }

      const newCommits = analysisResult.newCommits;
      currentHeadSha = analysisResult.currentHeadSha!;
      console.log(`[${new Date().toISOString()}] 📊 Found ${newCommits.length} new commits`);

      if (newCommits.length > 0) {
        await storeNewCommits(pkg.id, newCommits);
        newCommitsCount = newCommits.length;

        const contributorProfiles = await getContributorProfiles(pkg.id);
        console.log(`[${new Date().toISOString()}] 👥 Found ${contributorProfiles.size} contributor profiles`);

        if (contributorProfiles.size > 0) {
          const anomalies = calculateAnomaliesForCommits(newCommits, contributorProfiles);
          console.log(`[${new Date().toISOString()}] ⚠️ Found ${anomalies.length} anomalous commits`);
          if (anomalies.length > 0) {
            await storeAnomalies(pkg.id, anomalies, contributorProfiles);
          }
          anomaliesCount = anomalies.length;
        } else {
          console.log(`[${new Date().toISOString()}] ⏭️ Skipping anomaly detection (no contributor profiles)`);
        }
        await updateAnalysisData(pkg.id, newCommits.length, anomaliesCount);
      }
    }

    await updatePollingStatus(pkg.id, currentHeadSha);

    console.log(`[${new Date().toISOString()}] ✅ Done ${pkg.name} — commits: ${newCommitsCount}, anomalies: ${anomaliesCount}, HEAD: ${currentHeadSha}`);
    return { success: true };
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Error polling ${pkg.name}:`, error);
    return { success: false, error: error.message };
  } finally {
    if (tmpDir) {
      cleanupTempDir(tmpDir);
    }
  }
}

/**
 * Poll sweep: get all ready watched packages from the DB and poll each in a row.
 * Source of truth is watched_packages table.
 */
async function runPollSweep(): Promise<void> {
  const startTime = new Date().toISOString();
  console.log(`[${startTime}] ========================================`);
  console.log(`[${startTime}] 📦 Poll sweep — fetching ready watched_packages from DB...`);
  console.log(`[${startTime}] ========================================`);

  const packages = await getReadyWatchedPackages();
  console.log(`[${new Date().toISOString()}] 📋 Found ${packages.length} ready watched package(s)`);

  for (const pkg of packages) {
    await processOneWatchedPackage(pkg);
  }

  console.log(`[${new Date().toISOString()}] ✅ Poll sweep complete (${packages.length} packages)`);
}

/**
 * Run the Daily poll job: (1) dependency refresh (all direct deps, new versions, bumps), (2) poll all watched_packages from DB.
 */
async function runDailyPollJob(): Promise<void> {
  const startTime = new Date().toISOString();
  console.log(`[${startTime}] ========================================`);
  console.log(`[${startTime}] 📬 Daily poll job triggered`);
  console.log(`[${startTime}] ========================================`);

  // 1) Check all direct dependencies for new versions, create bumps
  try {
    await runDependencyRefresh();
  } catch (err: any) {
    console.error(`[${new Date().toISOString()}] ❌ Dependency refresh failed:`, err?.message ?? err);
  }

  // 2) Check all watched_packages (from DB), poll each
  try {
    await runPollSweep();
  } catch (err: any) {
    console.error(`[${new Date().toISOString()}] ❌ Poll sweep failed:`, err?.message ?? err);
  }

  console.log(`[${new Date().toISOString()}] ✅ Daily poll job complete`);
}

/**
 * Main worker loop:
 * Redis queue has one job type: "Daily poll" (delayed). When it becomes due we run it, then reschedule it for 24h later.
 * The job does: (1) dependency refresh (all deps, new versions), (2) poll all watched_packages from DB.
 */
async function runWorker(): Promise<void> {
  const startTime = new Date().toISOString();
  console.log(`[${startTime}] ========================================`);
  console.log(`[${startTime}] Watchtower Poller starting...`);
  console.log(`[${startTime}] ========================================`);
  console.log(`[${startTime}] Worker ID: ${WORKER_ID}`);
  console.log(`[${startTime}] Queue: single "Daily poll" job; when due → dependency refresh, then poll watched_packages from DB`);
  console.log(`[${startTime}] ========================================`);

  const redisConnected = await testRedisConnection();
  if (!redisConnected) {
    console.error(`[${startTime}] ❌ Cannot start worker - Redis connection failed`);
    process.exit(1);
  }

  // If no Daily poll job is scheduled yet, schedule one to run now
  if (!(await hasDailyPollScheduled())) {
    console.log(`[${startTime}] 📅 No Daily poll job in queue; scheduling one to run now`);
    await scheduleDailyPollJob(Date.now());
  }

  let checkCount = 0;

  while (true) {
    try {
      checkCount++;
      const job = await getDueDailyPollJob();

      if (job) {
        await runDailyPollJob();
        await scheduleDailyPollJob(Date.now() + TWENTY_FOUR_HOURS_MS);
      } else if (checkCount % 10 === 1) {
        const next = await getNextDailyPollRunAt();
        if (next != null) {
          const min = Math.round((next - Date.now()) / 60000);
          console.log(`[${new Date().toISOString()}] 📅 Next Daily poll in ~${min} min`);
        }
      }

      await new Promise((resolve) => setTimeout(resolve, CHECK_INTERVAL_MS));
    } catch (error: any) {
      console.error('Error in worker loop:', error);
      await new Promise((resolve) => setTimeout(resolve, CHECK_INTERVAL_MS));
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

// Start the worker
runWorker().catch((error) => {
  console.error('Fatal error in worker:', error);
  process.exit(1);
});

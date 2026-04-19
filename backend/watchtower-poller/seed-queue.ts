/**
 * Seed Queue Script
 * 
 * This script initializes the watchtower-poller queue with all watched packages.
 * Run this once to start the polling cycle, then the jobs will self-reschedule daily.
 * 
 * Usage:
 *   cd backend/watchtower-poller
 *   npx tsx seed-queue.ts
 * 
 * Options:
 *   --immediate    Schedule all jobs to run immediately (default)
 *   --staggered    Stagger jobs over 24 hours to spread the load
 *   --dry-run      Show what would be scheduled without actually scheduling
 */

import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';
import { Redis } from '@upstash/redis';

// Environment validation
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const redisUrl = process.env.UPSTASH_REDIS_URL;
const redisToken = process.env.UPSTASH_REDIS_TOKEN;

if (!supabaseUrl || !supabaseServiceKey) {
  console.error('❌ SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
  process.exit(1);
}

if (!redisUrl || !redisToken) {
  console.error('❌ UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN must be set');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);
const redis = new Redis({ url: redisUrl, token: redisToken });

const POLL_QUEUE_NAME = process.env.WATCHTOWER_POLL_QUEUE_NAME || 
  (process.env.NODE_ENV === 'production' ? 'watchtower-poll-schedule' : 'watchtower-poll-schedule-local');

interface WatchedPackage {
  id: string;
  name: string;
  status: string;
  github_url: string | null;
  analysis_data?: {
    githubUrl?: string;
    repository?: string;
  } | null;
}

interface PollJob {
  watchedPackageId: string;
  packageName: string;
  githubUrl: string;
}

/**
 * Parse repository URL to get GitHub URL
 */
function parseRepositoryUrl(repoUrl: string | undefined): string | null {
  if (!repoUrl) return null;

  let url = repoUrl.trim();

  if (url.startsWith('{')) {
    try {
      const parsed = JSON.parse(url);
      url = parsed.url || '';
    } catch {
      return null;
    }
  }

  if (url.startsWith('git+')) url = url.substring(4);
  if (url.startsWith('git://')) url = 'https://' + url.substring(6);
  if (url.startsWith('github:')) url = 'https://github.com/' + url.substring(7);
  if (/^[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+$/.test(url)) url = 'https://github.com/' + url;

  if (!url.includes('github.com')) return null;
  if (url.endsWith('.git')) url = url.slice(0, -4);
  if (!url.startsWith('https://')) return null;

  return url + '.git';
}

/**
 * Get GitHub URL from a watched package
 */
function getGithubUrl(pkg: WatchedPackage): string | null {
  if (pkg.github_url) return pkg.github_url;
  if (pkg.analysis_data?.githubUrl) return pkg.analysis_data.githubUrl;
  if (pkg.analysis_data?.repository) return parseRepositoryUrl(pkg.analysis_data.repository);
  return null;
}

/**
 * Main seed function
 */
async function seedQueue(options: { staggered: boolean; dryRun: boolean }) {
  console.log('========================================');
  console.log('🌱 Watchtower Poller - Seed Queue');
  console.log('========================================');
  console.log(`Queue name: ${POLL_QUEUE_NAME}`);
  console.log(`Mode: ${options.staggered ? 'Staggered (24h spread)' : 'Immediate'}`);
  console.log(`Dry run: ${options.dryRun ? 'Yes' : 'No'}`);
  console.log('');

  // Test connections
  console.log('🔌 Testing connections...');
  
  try {
    await redis.ping();
    console.log('✅ Redis connection OK');
  } catch (error: any) {
    console.error('❌ Redis connection failed:', error.message);
    process.exit(1);
  }

  // Get all ready watched packages (name and github_url from dependencies table)
  console.log('');
  console.log('📦 Fetching watched packages...');
  
  const { data: rawPackages, error } = await supabase
    .from('watched_packages')
    .select(`
      id,
      status,
      dependencies!dependency_id (name, github_url)
    `)
    .eq('status', 'ready');

  if (error) {
    console.error('❌ Failed to fetch packages:', error.message);
    process.exit(1);
  }

  const packages = (rawPackages || []).map((row: any) => {
    const dep = row.dependencies;
    return {
      id: row.id,
      name: dep?.name ?? '',
      status: row.status,
      github_url: dep?.github_url ?? null,
    } as WatchedPackage;
  });

  if (packages.length === 0) {
    console.log('⚠️ No watched packages found with status "ready"');
    console.log('   Add packages to watch first, then run this script again.');
    process.exit(0);
  }

  console.log(`✅ Found ${packages.length} watched packages`);
  console.log('');

  // Check existing queue
  const existingCount = await redis.zcard(POLL_QUEUE_NAME);
  if (existingCount > 0) {
    console.log(`⚠️ Queue already has ${existingCount} jobs`);
    console.log('   This will add new jobs for any packages not already scheduled.');
    console.log('');
  }

  // Get existing job package IDs to avoid duplicates
  const existingJobs = await redis.zrange(POLL_QUEUE_NAME, 0, -1);
  const existingPackageIds = new Set<string>();
  
  for (const jobData of existingJobs) {
    try {
      const job = typeof jobData === 'string' ? JSON.parse(jobData) : jobData;
      if (job.watchedPackageId) {
        existingPackageIds.add(job.watchedPackageId);
      }
    } catch {
      // Skip malformed jobs
    }
  }

  // Prepare jobs
  const jobsToAdd: { job: PollJob; score: number }[] = [];
  const skipped: string[] = [];
  const noGithub: string[] = [];
  
  const now = Date.now();
  const staggerInterval = options.staggered ? (24 * 60 * 60 * 1000) / packages.length : 0;

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i] as WatchedPackage;
    
    // Skip if already scheduled
    if (existingPackageIds.has(pkg.id)) {
      skipped.push(pkg.name);
      continue;
    }

    // Get GitHub URL
    const githubUrl = getGithubUrl(pkg);
    if (!githubUrl) {
      noGithub.push(pkg.name);
      continue;
    }

    const job: PollJob = {
      watchedPackageId: pkg.id,
      packageName: pkg.name,
      githubUrl,
    };

    // Calculate schedule time
    const score = options.staggered ? now + (i * staggerInterval) : now;
    
    jobsToAdd.push({ job, score });
  }

  // Display summary
  console.log('📊 Summary:');
  console.log(`   To schedule: ${jobsToAdd.length}`);
  console.log(`   Already scheduled: ${skipped.length}`);
  console.log(`   No GitHub URL: ${noGithub.length}`);
  console.log('');

  if (skipped.length > 0 && skipped.length <= 10) {
    console.log('   Skipped (already scheduled):');
    skipped.forEach(name => console.log(`     - ${name}`));
    console.log('');
  }

  if (noGithub.length > 0) {
    console.log('   Skipped (no GitHub URL):');
    noGithub.forEach(name => console.log(`     - ${name}`));
    console.log('');
  }

  if (jobsToAdd.length === 0) {
    console.log('✅ No new jobs to add');
    process.exit(0);
  }

  // Show jobs to be added
  console.log('📋 Jobs to add:');
  for (const { job, score } of jobsToAdd.slice(0, 10)) {
    const scheduleTime = new Date(score).toISOString();
    console.log(`   - ${job.packageName} @ ${scheduleTime}`);
  }
  if (jobsToAdd.length > 10) {
    console.log(`   ... and ${jobsToAdd.length - 10} more`);
  }
  console.log('');

  // Execute if not dry run
  if (options.dryRun) {
    console.log('🔍 Dry run - no changes made');
    process.exit(0);
  }

  console.log('📤 Adding jobs to queue...');
  
  let addedCount = 0;
  for (const { job, score } of jobsToAdd) {
    try {
      const jobJson = JSON.stringify(job);
      await redis.zadd(POLL_QUEUE_NAME, { score, member: jobJson });
      addedCount++;
    } catch (error: any) {
      console.error(`   ❌ Failed to add ${job.packageName}: ${error.message}`);
    }
  }

  console.log('');
  console.log('========================================');
  console.log(`✅ Successfully added ${addedCount} jobs to queue`);
  console.log('========================================');
  console.log('');
  console.log('Next steps:');
  console.log('  1. Start the poller worker: npm run dev');
  console.log('  2. Jobs will process when their scheduled time arrives');
  console.log('  3. Each job will automatically reschedule for the next day');
}

// Parse command line arguments
const args = process.argv.slice(2);
const options = {
  staggered: args.includes('--staggered'),
  dryRun: args.includes('--dry-run'),
};

// Run
seedQueue(options).catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

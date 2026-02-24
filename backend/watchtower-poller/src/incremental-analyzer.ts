import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import simpleGit from 'simple-git';
import { getTouchedFunctionsForCommit } from './touched-functions';

const execAsync = promisify(exec);

// Depth levels to try when looking for the previous commit
const DEPTH_LEVELS = [100, 500, 1000, 2000, 5000];
const MAX_DEPTH = 5000;

export interface CommitDetails {
  sha: string;
  author: string;
  authorEmail: string;
  message: string;
  timestamp: Date;
  linesAdded: number;
  linesDeleted: number;
  filesChanged: number;
  diffData?: {
    filesChanged: string[];
    stats: {
      filesChanged: number;
      insertions: number;
      deletions: number;
      files: Array<{ name: string; insertions: number; deletions: number }>;
    };
  };
  touchedFunctions?: string[];
}

export interface IncrementalAnalysisResult {
  success: boolean;
  newCommits: CommitDetails[];
  currentHeadSha: string | null;
  depthUsed: number;
  tmpDir?: string;
  error?: string;
}

/**
 * Create a unique temp directory for this analysis
 */
function createTempDir(packageName: string): string {
  const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(7);
  const tmpDir = path.join(os.tmpdir(), `watchtower-poll-${safeName}-${timestamp}-${random}`);
  fs.mkdirSync(tmpDir, { recursive: true });
  return tmpDir;
}

/**
 * Clean up temporary directory
 */
export function cleanupTempDir(tmpDir: string): void {
  try {
    if (fs.existsSync(tmpDir)) {
      console.log(`[${new Date().toISOString()}] 🧹 Cleaning up temp directory: ${tmpDir}`);
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  } catch (error) {
    console.warn(`Failed to cleanup temp directory ${tmpDir}:`, error);
  }
}

/**
 * Check if a commit exists in the cloned repository
 */
async function commitExists(repoPath: string, sha: string): Promise<boolean> {
  try {
    await execAsync(`git cat-file -e ${sha}^{commit}`, {
      cwd: repoPath,
      timeout: 10000,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Clone repository with a specific depth
 */
async function cloneWithDepth(githubUrl: string, targetDir: string, depth: number): Promise<void> {
  console.log(`[${new Date().toISOString()}] 📥 Cloning ${githubUrl} with depth ${depth}...`);
  
  const git = simpleGit();
  await git.clone(githubUrl, targetDir, [
    '--depth', depth.toString(),
    '--single-branch',
  ]);
  
  console.log(`[${new Date().toISOString()}] ✅ Cloned successfully with depth ${depth}`);
}

/**
 * Deepen an existing shallow clone
 */
async function deepenClone(repoPath: string, newDepth: number): Promise<void> {
  console.log(`[${new Date().toISOString()}] 📥 Deepening clone to depth ${newDepth}...`);
  
  await execAsync(`git fetch --depth=${newDepth}`, {
    cwd: repoPath,
    timeout: 300000, // 5 minutes
  });
  
  console.log(`[${new Date().toISOString()}] ✅ Deepened to ${newDepth} commits`);
}

/**
 * Extract commits between two SHAs using git log
 * Returns commits from oldSha (exclusive) to newSha (inclusive)
 */
async function extractCommitsBetween(
  repoPath: string,
  oldSha: string,
  newSha: string = 'HEAD'
): Promise<CommitDetails[]> {
  console.log(`[${new Date().toISOString()}] 🔍 Extracting commits from ${oldSha.substring(0, 8)}..${newSha.substring(0, 8)}`);

  // Use git log with the range syntax: oldSha..newSha
  // This gets all commits reachable from newSha but not from oldSha
  const gitLogCmd = `git log ${oldSha}..${newSha} --pretty=format:"%H|%an|%ae|%ad|%s" --numstat --date=iso`;
  
  const { stdout, stderr } = await execAsync(gitLogCmd, {
    cwd: repoPath,
    timeout: 300000, // 5 minutes
    maxBuffer: 50 * 1024 * 1024, // 50MB buffer
  });

  if (stderr && !stderr.includes('warning')) {
    console.warn(`Git log stderr: ${stderr}`);
  }

  const commits = parseGitLogOutput(stdout);
  console.log(`[${new Date().toISOString()}] 📊 Found ${commits.length} new commits`);
  
  return commits;
}

/**
 * Extract all commits from HEAD (for initial analysis or when oldSha not found)
 */
async function extractAllCommits(repoPath: string, maxCommits: number = 100): Promise<CommitDetails[]> {
  console.log(`[${new Date().toISOString()}] 🔍 Extracting up to ${maxCommits} commits from HEAD`);

  const gitLogCmd = `git log --pretty=format:"%H|%an|%ae|%ad|%s" --numstat --max-count=${maxCommits} --date=iso`;
  
  const { stdout, stderr } = await execAsync(gitLogCmd, {
    cwd: repoPath,
    timeout: 300000,
    maxBuffer: 50 * 1024 * 1024,
  });

  if (stderr && !stderr.includes('warning')) {
    console.warn(`Git log stderr: ${stderr}`);
  }

  const commits = parseGitLogOutput(stdout);
  console.log(`[${new Date().toISOString()}] 📊 Extracted ${commits.length} commits`);
  
  return commits;
}

/**
 * Parse git log output into structured commit data
 */
function parseGitLogOutput(output: string): CommitDetails[] {
  const commits: CommitDetails[] = [];
  const lines = output.trim().split('\n');
  
  let currentCommit: Partial<CommitDetails> | null = null;
  let currentStats: { added: number; deleted: number; files: number } = { added: 0, deleted: 0, files: 0 };

  for (const line of lines) {
    const trimmedLine = line.trim();
    
    if (!trimmedLine) continue;

    // Check if this is a commit header line (contains |)
    if (trimmedLine.includes('|') && trimmedLine.match(/^[a-f0-9]{40}\|/)) {
      // Save previous commit if exists
      if (currentCommit && currentCommit.sha) {
        commits.push({
          ...currentCommit,
          linesAdded: currentStats.added,
          linesDeleted: currentStats.deleted,
          filesChanged: currentStats.files,
        } as CommitDetails);
      }

      // Parse new commit header
      const parts = trimmedLine.split('|');
      if (parts.length >= 5) {
        const [sha, author, authorEmail, dateStr, ...messageParts] = parts;
        const message = messageParts.join('|');

        currentCommit = {
          sha: sha.trim(),
          author: author.trim(),
          authorEmail: authorEmail.trim(),
          message: message.trim(),
          timestamp: new Date(dateStr.trim()),
        };

        // Reset stats for new commit
        currentStats = { added: 0, deleted: 0, files: 0 };
      }
    } else if (currentCommit) {
      // This is a file stat line (numstat format: added\tdeleted\tfilename)
      const statParts = trimmedLine.split('\t');
      if (statParts.length >= 2) {
        const added = parseInt(statParts[0]) || 0;
        const deleted = parseInt(statParts[1]) || 0;

        // Skip binary files (show as -)
        if (statParts[0] !== '-' && statParts[1] !== '-') {
          currentStats.added += added;
          currentStats.deleted += deleted;
          currentStats.files += 1;
        }
      }
    }
  }

  // Don't forget the last commit
  if (currentCommit && currentCommit.sha) {
    commits.push({
      ...currentCommit,
      linesAdded: currentStats.added,
      linesDeleted: currentStats.deleted,
      filesChanged: currentStats.files,
    } as CommitDetails);
  }

  return commits;
}

/**
 * Get the current HEAD SHA of a local repository
 */
async function getLocalHeadSha(repoPath: string): Promise<string> {
  const { stdout } = await execAsync('git rev-parse HEAD', {
    cwd: repoPath,
    timeout: 10000,
  });
  return stdout.trim();
}

/**
 * Enrich each commit with touchedFunctions (export names touched by the commit).
 */
async function enrichCommitsWithTouchedFunctions(repoPath: string, commits: CommitDetails[]): Promise<void> {
  if (commits.length === 0) return;
  console.log(`[${new Date().toISOString()}] 🔍 Extracting touched functions for ${commits.length} commits...`);
  for (const commit of commits) {
    try {
      commit.touchedFunctions = await getTouchedFunctionsForCommit(repoPath, commit.sha);
    } catch (error: any) {
      console.warn(`⚠️ Failed to extract touched functions for commit ${commit.sha}: ${error.message}`);
      commit.touchedFunctions = [];
    }
  }
}

/**
 * Perform incremental analysis of a repository
 * 
 * 1. Clone with initial depth
 * 2. Check if previousSha exists in the clone
 * 3. If not, iteratively increase depth until found or max reached
 * 4. Extract commits between previousSha and HEAD
 * 
 * @param githubUrl The GitHub clone URL
 * @param packageName Package name (for temp dir naming)
 * @param previousSha The last known commit SHA (null for first poll)
 * @returns Analysis result with new commits
 */
export async function analyzeNewCommits(
  githubUrl: string,
  packageName: string,
  previousSha: string | null
): Promise<IncrementalAnalysisResult> {
  const tmpDir = createTempDir(packageName);
  
  try {
    console.log(`[${new Date().toISOString()}] ========================================`);
    console.log(`[${new Date().toISOString()}] 🔍 Incremental analysis for ${packageName}`);
    console.log(`[${new Date().toISOString()}] ========================================`);
    console.log(`[${new Date().toISOString()}] 📁 Temp directory: ${tmpDir}`);
    console.log(`[${new Date().toISOString()}] 🔗 GitHub URL: ${githubUrl}`);
    console.log(`[${new Date().toISOString()}] 📌 Previous SHA: ${previousSha || '(none - first poll)'}`);

    let depthUsed = DEPTH_LEVELS[0];
    
    // Clone with initial depth
    await cloneWithDepth(githubUrl, tmpDir, depthUsed);
    
    // Get current HEAD
    const currentHeadSha = await getLocalHeadSha(tmpDir);
    console.log(`[${new Date().toISOString()}] 📌 Current HEAD: ${currentHeadSha}`);

    // If no previous SHA, this is the first poll - clone with 500 depth and extract up to 500 commits
    if (!previousSha) {
      console.log(`[${new Date().toISOString()}] 📋 First poll - extracting up to 500 recent commits`);
      const firstPollDepth = 500;
      if (depthUsed < firstPollDepth) {
        await deepenClone(tmpDir, firstPollDepth);
        depthUsed = firstPollDepth;
      }
      const commits = await extractAllCommits(tmpDir, 500);
      await enrichCommitsWithTouchedFunctions(tmpDir, commits);
      return {
        success: true,
        newCommits: commits,
        currentHeadSha,
        depthUsed,
        tmpDir,
      };
    }

    // Check if HEAD is the same as previous (no changes)
    if (currentHeadSha === previousSha) {
      console.log(`[${new Date().toISOString()}] ✅ No new commits (HEAD unchanged)`);
      return {
        success: true,
        newCommits: [],
        currentHeadSha,
        depthUsed,
        tmpDir,
      };
    }

    // Try to find the previous SHA, increasing depth if needed
    let foundPreviousSha = await commitExists(tmpDir, previousSha);
    
    if (!foundPreviousSha) {
      console.log(`[${new Date().toISOString()}] ⚠️ Previous SHA not found at depth ${depthUsed}, increasing depth...`);
      
      for (const depth of DEPTH_LEVELS.slice(1)) {
        if (depth <= depthUsed) continue;
        
        await deepenClone(tmpDir, depth);
        depthUsed = depth;
        
        foundPreviousSha = await commitExists(tmpDir, previousSha);
        
        if (foundPreviousSha) {
          console.log(`[${new Date().toISOString()}] ✅ Found previous SHA at depth ${depth}`);
          break;
        }
        
        console.log(`[${new Date().toISOString()}] ⚠️ Still not found at depth ${depth}`);
      }
    }

    let newCommits: CommitDetails[];
    
    if (foundPreviousSha) {
      // Extract commits between previous and current
      newCommits = await extractCommitsBetween(tmpDir, previousSha, currentHeadSha);
    } else {
      // Previous SHA not found even at max depth
      // This could happen if the repository was force-pushed or rebased
      console.log(`[${new Date().toISOString()}] ⚠️ Previous SHA not found even at max depth ${MAX_DEPTH}`);
      console.log(`[${new Date().toISOString()}] 📋 Extracting recent commits instead`);
      
      newCommits = await extractAllCommits(tmpDir, 500);
    }

    await enrichCommitsWithTouchedFunctions(tmpDir, newCommits);

    console.log(`[${new Date().toISOString()}] ========================================`);
    console.log(`[${new Date().toISOString()}] ✅ Analysis complete: ${newCommits.length} new commits`);
    console.log(`[${new Date().toISOString()}] ========================================`);

    return {
      success: true,
      newCommits,
      currentHeadSha,
      depthUsed,
      tmpDir,
    };
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Incremental analysis failed:`, error.message);
    
    return {
      success: false,
      newCommits: [],
      currentHeadSha: null,
      depthUsed: 0,
      tmpDir,
      error: error.message,
    };
  }
}

import simpleGit from 'simple-git';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * Parse a repository URL from npm package metadata into a GitHub clone URL
 * Handles various formats:
 * - git+https://github.com/owner/repo.git
 * - git://github.com/owner/repo.git
 * - https://github.com/owner/repo.git
 * - https://github.com/owner/repo
 * - github:owner/repo
 * - owner/repo (shorthand)
 */
export function parseRepositoryUrl(repoUrl: string | undefined): string | null {
  if (!repoUrl) {
    return null;
  }

  let url = repoUrl.trim();

  // Handle object format that might have been stringified
  if (url.startsWith('{')) {
    try {
      const parsed = JSON.parse(url);
      url = parsed.url || '';
    } catch {
      return null;
    }
  }

  // Remove git+ prefix
  if (url.startsWith('git+')) {
    url = url.substring(4);
  }

  // Convert git:// to https://
  if (url.startsWith('git://')) {
    url = 'https://' + url.substring(6);
  }

  // Handle github: shorthand
  if (url.startsWith('github:')) {
    url = 'https://github.com/' + url.substring(7);
  }

  // Handle shorthand owner/repo format
  if (/^[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+$/.test(url)) {
    url = 'https://github.com/' + url;
  }

  // Validate it's a GitHub URL
  if (!url.includes('github.com')) {
    console.warn(`Repository URL is not GitHub: ${url}`);
    return null;
  }

  // Remove .git suffix if present for consistency, then add it back
  if (url.endsWith('.git')) {
    url = url.slice(0, -4);
  }

  // Ensure it's https
  if (!url.startsWith('https://')) {
    return null;
  }

  return url + '.git';
}

/**
 * Clone a public GitHub repository to a temporary directory
 * Uses depth 5000 to get enough history for analysis
 */
export async function cloneRepository(
  repoUrl: string,
  packageName: string
): Promise<string> {
  // Create a temporary directory for this clone
  const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
  const tempDir = path.join(
    os.tmpdir(),
    `watchtower-clone-${safeName}-${Date.now()}-${Math.random().toString(36).substring(7)}`
  );
  
  // Create parent directory first
  fs.mkdirSync(tempDir, { recursive: true });

  try {
    console.log(`[${new Date().toISOString()}] 📥 Cloning ${repoUrl} to ${tempDir}...`);
    
    const git = simpleGit();
    
    // Clone with depth 5000 to get enough history for analysis
    await git.clone(repoUrl, tempDir, [
      '--depth', '5000',
      '--single-branch'
    ]);

    console.log(`[${new Date().toISOString()}] ✅ Successfully cloned repository to ${tempDir}`);
    return tempDir;
  } catch (error: any) {
    // Clean up on error
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    throw new Error(`Failed to clone repository: ${error.message}`);
  }
}

/**
 * Clean up a cloned repository directory
 */
export function cleanupRepository(repoPath: string): void {
  try {
    if (fs.existsSync(repoPath)) {
      console.log(`[${new Date().toISOString()}] 🧹 Cleaning up repository at ${repoPath}...`);
      fs.rmSync(repoPath, { recursive: true, force: true });
      console.log(`[${new Date().toISOString()}] ✅ Repository cleaned up`);
    }
  } catch (error) {
    console.warn(`Failed to cleanup repository at ${repoPath}:`, error);
  }
}

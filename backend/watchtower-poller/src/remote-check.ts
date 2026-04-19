import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface RemoteHeadResult {
  sha: string | null;
  branch: string | null;
  error?: string;
}

/**
 * Get the HEAD SHA of a remote repository without cloning it
 * Uses `git ls-remote` which is very fast and doesn't require downloading the repo
 * 
 * @param githubUrl The GitHub clone URL (e.g., https://github.com/owner/repo.git)
 * @returns The HEAD SHA and default branch name, or null if failed
 */
export async function getRemoteHeadSha(githubUrl: string): Promise<RemoteHeadResult> {
  try {
    // Get HEAD reference
    const { stdout, stderr } = await execAsync(`git ls-remote ${githubUrl} HEAD`, {
      timeout: 30000, // 30 second timeout
    });

    if (stderr && !stderr.includes('warning')) {
      console.warn(`git ls-remote stderr: ${stderr}`);
    }

    // Parse the output - format is: "<sha>\tHEAD"
    const match = stdout.trim().match(/^([a-f0-9]{40})\s+HEAD$/m);
    
    if (!match) {
      return {
        sha: null,
        branch: null,
        error: `Could not parse HEAD SHA from output: ${stdout.substring(0, 100)}`,
      };
    }

    const sha = match[1];

    // Try to get the default branch name
    let branch: string | null = null;
    try {
      const { stdout: refsOutput } = await execAsync(`git ls-remote --symref ${githubUrl} HEAD`, {
        timeout: 30000,
      });
      
      // Parse output like: "ref: refs/heads/main\tHEAD"
      const branchMatch = refsOutput.match(/ref: refs\/heads\/([^\t\n]+)\s+HEAD/);
      if (branchMatch) {
        branch = branchMatch[1];
      }
    } catch {
      // Branch detection is optional, continue without it
    }

    return { sha, branch };
  } catch (error: any) {
    return {
      sha: null,
      branch: null,
      error: `Failed to get remote HEAD: ${error.message}`,
    };
  }
}

/**
 * Check if the remote repository has new commits compared to a known SHA
 * 
 * @param githubUrl The GitHub clone URL
 * @param lastKnownSha The last commit SHA we have on record
 * @returns Object indicating if there are changes and the current HEAD SHA
 */
export async function checkForNewCommits(
  githubUrl: string,
  lastKnownSha: string | null
): Promise<{
  hasChanges: boolean;
  currentSha: string | null;
  branch: string | null;
  error?: string;
}> {
  const result = await getRemoteHeadSha(githubUrl);

  if (result.error || !result.sha) {
    return {
      hasChanges: false,
      currentSha: null,
      branch: null,
      error: result.error,
    };
  }

  // If we don't have a last known SHA, consider it as "has changes"
  // This happens on the first poll after initial analysis
  if (!lastKnownSha) {
    return {
      hasChanges: true,
      currentSha: result.sha,
      branch: result.branch,
    };
  }

  // Compare SHAs
  const hasChanges = result.sha !== lastKnownSha;

  return {
    hasChanges,
    currentSha: result.sha,
    branch: result.branch,
  };
}

/**
 * Parse a repository URL from npm package metadata into a GitHub clone URL
 * Handles various formats (copied from watchtower-worker for consistency)
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

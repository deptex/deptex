import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const GITHUB_API_BASE = 'https://api.github.com';

const base64Url = (input: Buffer | string) => {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
};

/**
 * Get the GitHub App private key from env var or file path
 */
function getPrivateKey(): string {
  // First try direct env var
  if (process.env.GITHUB_APP_PRIVATE_KEY) {
    return process.env.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g, '\n');
  }

  // Then try file path
  const keyPath = process.env.GITHUB_APP_PRIVATE_KEY_PATH;
  if (keyPath) {
    // Resolve relative to backend root (parent of src/lib)
    const resolvedPath = path.resolve(__dirname, '../../', keyPath);
    if (fs.existsSync(resolvedPath)) {
      return fs.readFileSync(resolvedPath, 'utf8');
    }
    throw new Error(`GitHub App private key file not found at: ${resolvedPath}`);
  }

  throw new Error('GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH must be set');
}

export function createGitHubAppJwt(): string {
  const appId = process.env.GITHUB_APP_ID;

  if (!appId) {
    throw new Error('GITHUB_APP_ID is not configured');
  }

  const privateKey = getPrivateKey();

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now - 30,
    exp: now + 9 * 60,
    iss: appId,
  };

  const header = { alg: 'RS256', typ: 'JWT' };
  const unsignedToken = `${base64Url(JSON.stringify(header))}.${base64Url(
    JSON.stringify(payload)
  )}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsignedToken);
  signer.end();

  const signature = signer.sign(privateKey);

  return `${unsignedToken}.${base64Url(signature)}`;
}

/** Get installation details including account login and avatar. Uses App JWT. */
export async function getInstallationAccount(installationId: string): Promise<{ login: string; account_type?: string; avatar_url?: string } | null> {
  const jwt = createGitHubAppJwt();
  const response = await fetch(`${GITHUB_API_BASE}/app/installations/${installationId}`, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
    },
  });
  if (!response.ok) return null;
  const data = (await response.json()) as { account?: { login?: string; type?: string; avatar_url?: string } };
  const login = data.account?.login;
  const accountType = data.account?.type;
  const avatarUrl = data.account?.avatar_url;
  return login ? { login, account_type: accountType, avatar_url: avatarUrl } : null;
}

export async function createInstallationToken(installationId: string): Promise<string> {
  const jwt = createGitHubAppJwt();
  const response = await fetch(
    `${GITHUB_API_BASE}/app/installations/${installationId}/access_tokens`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-App',
      },
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to create installation token: ${response.status} ${errorText}`);
  }

  const data = (await response.json()) as { token: string };
  return data.token;
}

export async function listInstallationRepositories(installationToken: string) {
  const response = await fetch(`${GITHUB_API_BASE}/installation/repositories?per_page=100`, {
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to list repositories: ${response.status} ${errorText}`);
  }

  const data = (await response.json()) as {
    repositories: Array<{
      id: number;
      full_name: string;
      default_branch: string;
      private: boolean;
    }>;
  };

  return data.repositories || [];
}

export async function getRepositoryFileContent(
  installationToken: string,
  repoFullName: string,
  path: string,
  ref?: string
): Promise<string> {
  const result = await getRepositoryFileWithSha(installationToken, repoFullName, path, ref);
  return result.content;
}

/**
 * Get file content and blob sha (for later update). Returns { content, sha }.
 */
export async function getRepositoryFileWithSha(
  installationToken: string,
  repoFullName: string,
  filePath: string,
  ref?: string
): Promise<{ content: string; sha: string }> {
  const url = new URL(`${GITHUB_API_BASE}/repos/${repoFullName}/contents/${filePath}`);
  if (ref) {
    url.searchParams.set('ref', ref);
  }

  const response = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to fetch ${filePath}: ${response.status} ${errorText}`);
  }

  const data = (await response.json()) as {
    content: string;
    encoding: string;
    sha: string;
  };

  if (data.encoding !== 'base64') {
    throw new Error(`Unexpected encoding for ${filePath}: ${data.encoding}`);
  }

  return {
    content: Buffer.from(data.content, 'base64').toString('utf-8'),
    sha: data.sha,
  };
}

/** Root directory listing: GET /repos/:owner/:repo/contents (no path) */
export async function getRepositoryRootContents(
  installationToken: string,
  repoFullName: string,
  ref?: string
): Promise<Array<{ name: string; path: string; type: string }>> {
  const url = new URL(`${GITHUB_API_BASE}/repos/${repoFullName}/contents`);
  if (ref) {
    url.searchParams.set('ref', ref);
  }
  const response = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
    },
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to list root contents: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as Array<{ name: string; path: string; type: string }>;
  return Array.isArray(data) ? data : [];
}

/** Recursive tree (all files/dirs) for monorepo scan. Uses Git Trees API. */
export async function getRepositoryTreeRecursive(
  installationToken: string,
  repoFullName: string,
  ref: string
): Promise<Array<{ path: string; type: string }>> {
  const commitSha = await getBranchSha(installationToken, repoFullName, ref);
  const commitUrl = `${GITHUB_API_BASE}/repos/${repoFullName}/git/commits/${commitSha}`;
  const commitRes = await fetch(commitUrl, {
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
    },
  });
  if (!commitRes.ok) {
    const errorText = await commitRes.text();
    throw new Error(`Failed to get commit: ${commitRes.status} ${errorText}`);
  }
  const commitData = (await commitRes.json()) as { tree: { sha: string } };
  const treeSha = commitData.tree?.sha;
  if (!treeSha) {
    throw new Error('Commit has no tree');
  }
  const treeUrl = `${GITHUB_API_BASE}/repos/${repoFullName}/git/trees/${treeSha}?recursive=1`;
  const treeRes = await fetch(treeUrl, {
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
    },
  });
  if (!treeRes.ok) {
    const errorText = await treeRes.text();
    throw new Error(`Failed to get tree: ${treeRes.status} ${errorText}`);
  }
  interface TreeResponse {
    tree?: Array<{ path: string; type: string }>;
  }
  const treeData = (await treeRes.json()) as TreeResponse;
  const tree = treeData.tree || [];
  return tree.map((node) => ({ path: node.path, type: node.type }));
}

/**
 * Clone a GitHub repository to a local directory
 * Uses the installation token for authentication
 */
export async function cloneRepository(
  installationToken: string,
  repoFullName: string,
  branch: string,
  targetDir: string
): Promise<void> {
  // Dynamic import to avoid requiring simple-git in the main backend
  const simpleGit = await import('simple-git');
  const git = simpleGit.default(targetDir);

  // Construct GitHub clone URL with token
  // Format: https://x-access-token:TOKEN@github.com/owner/repo.git
  const repoUrl = `https://x-access-token:${installationToken}@github.com/${repoFullName}.git`;

  try {
    // Clone the repository
    await git.clone(repoUrl, targetDir, ['--branch', branch, '--depth', '1']);
  } catch (error: any) {
    // If directory already exists or clone fails, try to pull instead
    if (error.message?.includes('already exists')) {
      const existingGit = simpleGit.default(targetDir);
      await existingGit.pull('origin', branch);
    } else {
      throw new Error(`Failed to clone repository: ${error.message}`);
    }
  }
}


export async function getCommitDiff(
  installationToken: string,
  repoFullName: string,
  sha: string
): Promise<string> {
  const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/commits/${sha}`, {
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github.v3.diff',
      'User-Agent': 'Deptex-App',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to fetch commit diff: ${response.status} ${errorText}`);
  }

  return response.text();
}

/**
 * Fetch commit diff from a public repository
 * Uses GITHUB_PAT env var if available, otherwise makes unauthenticated request (rate limited)
 */
export async function getCommitDiffPublic(
  repoFullName: string,
  sha: string
): Promise<string> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.v3.diff',
    'User-Agent': 'Deptex-App',
  };

  // Use PAT if available for higher rate limits
  const pat = process.env.GITHUB_PAT;
  if (pat) {
    headers['Authorization'] = `Bearer ${pat}`;
  }

  const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/commits/${sha}`, {
    headers,
  });

  if (!response.ok) {
    const errorText = await response.text();
    if (response.status === 403 && errorText.includes('rate limit')) {
      throw new Error('GitHub API rate limit exceeded. Configure GITHUB_PAT environment variable for higher limits.');
    }
    throw new Error(`Failed to fetch commit diff: ${response.status} ${errorText}`);
  }

  return response.text();
}

/**
 * Get the list of file paths changed between two refs (e.g. push before/after).
 * Uses Compare API: GET /repos/{owner}/{repo}/compare/{base}...{head}
 */
export async function getCompareChangedFiles(
  installationToken: string,
  repoFullName: string,
  baseRef: string,
  headRef: string
): Promise<string[]> {
  const comparePath = `${baseRef}...${headRef}`;
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${repoFullName}/compare/${encodeURIComponent(comparePath)}`,
    {
      headers: {
        Authorization: `Bearer ${installationToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-App',
      },
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to compare refs: ${response.status} ${errorText}`);
  }

  const data = (await response.json()) as {
    files?: Array<{ filename?: string; previous_filename?: string }>;
  };
  const files = data.files ?? [];
  const paths = new Set<string>();
  for (const f of files) {
    if (f.filename) paths.add(f.filename);
    if (f.previous_filename) paths.add(f.previous_filename);
  }
  return [...paths];
}

/**
 * Get the commit SHA of a branch (e.g. default branch) for creating a new branch from it.
 */
export async function getBranchSha(
  installationToken: string,
  repoFullName: string,
  branch: string
): Promise<string> {
  const branchName = branch.startsWith('refs/heads/') ? branch.slice('refs/heads/'.length) : branch;
  // Ref must be a single path segment; encode so "heads/deptex/bump-x" works
  const refEncoded = encodeURIComponent(`heads/${branchName}`);
  const url = `${GITHUB_API_BASE}/repos/${repoFullName}/git/ref/${refEncoded}`;
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
    },
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to get branch ref: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as { object: { sha: string } };
  return data.object.sha;
}

/**
 * Create a new branch from an existing branch's commit SHA.
 */
export async function createBranch(
  installationToken: string,
  repoFullName: string,
  newBranchName: string,
  fromSha: string
): Promise<void> {
  const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/git/refs`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      ref: `refs/heads/${newBranchName}`,
      sha: fromSha,
    }),
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to create branch: ${response.status} ${errorText}`);
  }
}

/**
 * Create or update a file on a branch. Content must be UTF-8; it will be base64-encoded.
 * For update, pass the current file sha (from getRepositoryFileWithSha).
 */
export async function createOrUpdateFileOnBranch(
  installationToken: string,
  repoFullName: string,
  branch: string,
  filePath: string,
  content: string,
  message: string,
  currentSha?: string
): Promise<void> {
  const body: { branch: string; message: string; content: string; sha?: string } = {
    branch,
    message,
    content: Buffer.from(content, 'utf-8').toString('base64'),
  };
  if (currentSha) {
    body.sha = currentSha;
  }
  const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/contents/${filePath}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to update file ${filePath}: ${response.status} ${errorText}`);
  }
}

/**
 * Create a pull request. Returns the PR HTML URL.
 */
export async function createPullRequest(
  installationToken: string,
  repoFullName: string,
  base: string,
  head: string,
  title: string,
  body: string
): Promise<{ html_url: string; number: number }> {
  const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/pulls`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ base, head, title, body }),
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to create pull request: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as { html_url: string; number: number };
  return data;
}

/**
 * List open pull requests whose head branch matches (e.g. owner:branch for same repo).
 * Returns array of { html_url, number }.
 */
export async function listPullRequestsByHead(
  installationToken: string,
  repoFullName: string,
  headRef: string
): Promise<{ html_url: string; number: number }[]> {
  const [owner] = repoFullName.split('/');
  const head = headRef.includes(':') ? headRef : `${owner}:${headRef}`;
  const params = new URLSearchParams({ state: 'open', head });
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${repoFullName}/pulls?${params.toString()}`,
    {
      headers: {
        Authorization: `Bearer ${installationToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-App',
      },
    }
  );
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to list pull requests: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as Array<{ html_url: string; number: number }>;
  return data;
}

/**
 * Get a pull request by number. Returns state (open/closed) and other fields.
 */
export async function getPullRequest(
  installationToken: string,
  repoFullName: string,
  prNumber: number
): Promise<{ state: string }> {
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${repoFullName}/pulls/${prNumber}`,
    {
      headers: {
        Authorization: `Bearer ${installationToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-App',
      },
    }
  );
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to get pull request: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as { state: string };
  return data;
}

/**
 * Close a pull request by number.
 */
export async function closePullRequest(
  installationToken: string,
  repoFullName: string,
  prNumber: number
): Promise<void> {
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${repoFullName}/pulls/${prNumber}`,
    {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${installationToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-App',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ state: 'closed' }),
    }
  );
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to close pull request: ${response.status} ${errorText}`);
  }
}

/** Check run output for create/update */
export interface CheckRunOutput {
  title: string;
  summary: string;
  text?: string;
}

/**
 * List check runs for a ref, optionally filtered by check name.
 * Returns runs with id, name, status, conclusion.
 */
export async function listCheckRunsForRef(
  installationToken: string,
  repoFullName: string,
  ref: string,
  checkName?: string
): Promise<{ id: number; name: string; status: string; conclusion: string | null }[]> {
  const params = new URLSearchParams();
  if (checkName) params.set('check_name', checkName);
  const query = params.toString() ? `?${params.toString()}` : '';
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${repoFullName}/commits/${encodeURIComponent(ref)}/check-runs${query}`,
    {
      headers: {
        Authorization: `Bearer ${installationToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-App',
      },
    }
  );
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to list check runs: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as {
    check_runs?: Array<{ id: number; name: string; status: string; conclusion: string | null }>;
  };
  return data.check_runs ?? [];
}

/**
 * Create a check run. Name and head_sha are required.
 * status defaults to 'completed'; pass conclusion for success/failure.
 */
export async function createCheckRun(
  installationToken: string,
  repoFullName: string,
  headSha: string,
  name: string,
  options: {
    status?: 'queued' | 'in_progress' | 'completed';
    conclusion?: 'success' | 'failure' | 'cancelled' | 'skipped' | 'neutral' | 'timed_out' | 'action_required';
    output?: CheckRunOutput;
  } = {}
): Promise<{ id: number; html_url: string }> {
  const { status = 'completed', conclusion, output } = options;
  const body: Record<string, unknown> = {
    name,
    head_sha: headSha,
    status,
  };
  if (conclusion) body.conclusion = conclusion;
  if (output) body.output = output;
  const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/check-runs`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-App',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to create check run: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as { id: number; html_url: string };
  return data;
}

/**
 * Update an existing check run by id.
 */
export async function updateCheckRun(
  installationToken: string,
  repoFullName: string,
  checkRunId: number,
  options: {
    status?: 'queued' | 'in_progress' | 'completed';
    conclusion?: 'success' | 'failure' | 'cancelled' | 'skipped' | 'neutral' | 'timed_out' | 'action_required';
    output?: CheckRunOutput;
  }
): Promise<void> {
  const { status, conclusion, output } = options;
  const body: Record<string, unknown> = {};
  if (status !== undefined) body.status = status;
  if (conclusion !== undefined) body.conclusion = conclusion;
  if (output !== undefined) body.output = output;
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${repoFullName}/check-runs/${checkRunId}`,
    {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${installationToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-App',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    }
  );
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to update check run: ${response.status} ${errorText}`);
  }
}

/**
 * Create a comment on an issue or pull request (PRs use the issues API for comments).
 */
export async function createIssueComment(
  installationToken: string,
  repoFullName: string,
  issueNumber: number,
  body: string
): Promise<{ id: number; html_url: string }> {
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${repoFullName}/issues/${issueNumber}/comments`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${installationToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-App',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ body }),
    }
  );
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to create comment: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as { id: number; html_url: string };
  return data;
}

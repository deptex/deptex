import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  fetchWithRetry,
  ProviderError,
  RateLimitedError,
  AuthExpiredError,
} from './provider-fetch';

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
  if (process.env.GITHUB_APP_PRIVATE_KEY) {
    return process.env.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g, '\n');
  }

  const keyPath = process.env.GITHUB_APP_PRIVATE_KEY_PATH;
  if (keyPath) {
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

/**
 * Module-scoped installation-token cache so a fresh `GitHubProvider` instance
 * built per HTTP request doesn't mint a new token every time, and so two
 * concurrent cold callers de-dupe onto a single mint.
 *
 * GitHub installation tokens are valid for 60 minutes; we cache for 45 to
 * leave headroom for clock skew + request duration.
 */
const INSTALLATION_TOKEN_TTL_MS = 45 * 60 * 1000;
const installationTokenCache = new Map<string, { token: string; expiresAt: number }>();
const installationTokenInflight = new Map<string, Promise<string>>();

/** Internal: actually hit the GitHub access_tokens endpoint. No caching. */
async function mintInstallationToken(installationId: string): Promise<string> {
  const jwt = createGitHubAppJwt();
  const response = await fetchWithRetry(
    'github',
    `/app/installations/${installationId}/access_tokens`,
    () =>
      fetch(`${GITHUB_API_BASE}/app/installations/${installationId}/access_tokens`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${jwt}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'Deptex-App',
        },
      }),
  );
  const data = (await response.json()) as { token: string };
  return data.token;
}

export async function createInstallationToken(installationId: string): Promise<string> {
  const cached = installationTokenCache.get(installationId);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.token;
  }
  const existing = installationTokenInflight.get(installationId);
  if (existing) return existing;
  const promise = (async () => {
    try {
      const token = await mintInstallationToken(installationId);
      installationTokenCache.set(installationId, {
        token,
        expiresAt: Date.now() + INSTALLATION_TOKEN_TTL_MS,
      });
      return token;
    } finally {
      installationTokenInflight.delete(installationId);
    }
  })();
  installationTokenInflight.set(installationId, promise);
  return promise;
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

/**
 * Shared fetch helper for any API call authed with an installation token.
 * Wraps every call in the rate-limit-aware retry pipeline. Throws
 * RateLimitedError / AuthExpiredError / ProviderError so route handlers can
 * map to user-facing copy without leaking upstream bodies.
 */
async function ghFetch(installationToken: string, apiPath: string, init: RequestInit = {}): Promise<Response> {
  const url = apiPath.startsWith('http') ? apiPath : `${GITHUB_API_BASE}${apiPath}`;
  return fetchWithRetry('github', apiPath, () =>
    fetch(url, {
      ...init,
      headers: {
        Authorization: `Bearer ${installationToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-App',
        ...(init.headers || {}),
      },
    }),
  );
}

export async function listInstallationRepositories(installationToken: string) {
  const repos: Array<{
    id: number;
    full_name: string;
    default_branch: string;
    private: boolean;
  }> = [];
  let page = 1;
  const perPage = 100;
  while (page <= 20) {
    const response = await ghFetch(
      installationToken,
      `/installation/repositories?per_page=${perPage}&page=${page}`,
    );
    const data = (await response.json()) as {
      total_count?: number;
      repositories: Array<{
        id: number;
        full_name: string;
        default_branch: string | null;
        private: boolean;
      }>;
    };
    for (const r of data.repositories || []) {
      // Skip empty repos (no default branch yet). Connecting them would
      // queue an extraction that fails at clone with no actionable error.
      if (!r.default_branch) continue;
      repos.push({
        id: r.id,
        full_name: r.full_name,
        default_branch: r.default_branch,
        private: r.private,
      });
    }
    if (!data.repositories || data.repositories.length < perPage) break;
    page++;
  }
  return repos;
}

export async function getRepositoryFileContent(
  installationToken: string,
  repoFullName: string,
  filePath: string,
  ref?: string
): Promise<string> {
  const result = await getRepositoryFileWithSha(installationToken, repoFullName, filePath, ref);
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
  const encodedPath = filePath.split('/').map(encodeURIComponent).join('/');
  const url = new URL(`${GITHUB_API_BASE}/repos/${repoFullName}/contents/${encodedPath}`);
  if (ref) {
    url.searchParams.set('ref', ref);
  }

  const response = await ghFetch(installationToken, url.toString());

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
  return getRepositoryDirectoryContents(installationToken, repoFullName, '', ref);
}

/** Single-level directory listing for a given path. Empty path lists the root. */
export async function getRepositoryDirectoryContents(
  installationToken: string,
  repoFullName: string,
  path: string,
  ref?: string
): Promise<Array<{ name: string; path: string; type: string }>> {
  const suffix = path ? `/${path.split('/').map(encodeURIComponent).join('/')}` : '';
  const url = new URL(`${GITHUB_API_BASE}/repos/${repoFullName}/contents${suffix}`);
  if (ref) {
    url.searchParams.set('ref', ref);
  }
  const response = await ghFetch(installationToken, url.toString());
  const data = (await response.json()) as Array<{ name: string; path: string; type: string }>;
  return Array.isArray(data) ? data : [];
}

export interface RecursiveTreeResult {
  entries: Array<{ path: string; type: string }>;
  truncated: boolean;
}

/** Recursive tree (all files/dirs) for monorepo scan. Uses Git Trees API. */
export async function getRepositoryTreeRecursive(
  installationToken: string,
  repoFullName: string,
  ref: string
): Promise<Array<{ path: string; type: string }>> {
  const result = await getRepositoryTreeRecursiveWithFlag(installationToken, repoFullName, ref);
  return result.entries;
}

export async function getRepositoryTreeRecursiveWithFlag(
  installationToken: string,
  repoFullName: string,
  ref: string
): Promise<RecursiveTreeResult> {
  const commitSha = await getBranchSha(installationToken, repoFullName, ref);
  const commitRes = await ghFetch(
    installationToken,
    `/repos/${repoFullName}/git/commits/${commitSha}`,
  );
  const commitData = (await commitRes.json()) as { tree: { sha: string } };
  const treeSha = commitData.tree?.sha;
  if (!treeSha) {
    throw new Error('Commit has no tree');
  }
  const treeRes = await ghFetch(
    installationToken,
    `/repos/${repoFullName}/git/trees/${treeSha}?recursive=1`,
  );
  interface TreeResponse {
    tree?: Array<{ path: string; type: string }>;
    truncated?: boolean;
  }
  const treeData = (await treeRes.json()) as TreeResponse;
  const tree = treeData.tree || [];
  // GitHub returns type as 'blob' | 'tree' | 'commit' (the last for submodules).
  // Map submodule entries to a distinct type so callers can skip them rather
  // than treating them as regular files.
  return {
    entries: tree.map((node) => ({
      path: node.path,
      type: node.type === 'tree' ? 'tree' : node.type === 'commit' ? 'submodule' : 'blob',
    })),
    truncated: treeData.truncated === true,
  };
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
  const simpleGit = await import('simple-git');
  const git = simpleGit.default(targetDir);

  const repoUrl = `https://x-access-token:${installationToken}@github.com/${repoFullName}.git`;

  try {
    await git.clone(repoUrl, targetDir, ['--branch', branch, '--depth', '1']);
  } catch (error: any) {
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
      throw new RateLimitedError('github', `/repos/${repoFullName}/commits/${sha}`, 60_000, 'public unauthenticated');
    }
    throw new ProviderError('github', response.status, `/repos/${repoFullName}/commits/${sha}`, errorText.slice(0, 200));
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
  const response = await ghFetch(
    installationToken,
    `/repos/${repoFullName}/compare/${encodeURIComponent(comparePath)}`,
  );

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
  const refEncoded = encodeURIComponent(`heads/${branchName}`);
  const response = await ghFetch(installationToken, `/repos/${repoFullName}/git/ref/${refEncoded}`);
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

/**
 * Create a new GitHub issue on a repo (used by the finding -> tracker flow).
 */
export async function createIssue(
  installationToken: string,
  repoFullName: string,
  params: { title: string; body: string; labels?: string[] }
): Promise<{ number: number; html_url: string; id: number }> {
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${repoFullName}/issues`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${installationToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-App',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ title: params.title, body: params.body, labels: params.labels }),
    }
  );
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to create issue: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as { number: number; html_url: string; id: number };
  return data;
}

/**
 * Fetch a single GitHub issue (used to poll its open/closed state for the
 * finding -> tracker chip when webhooks aren't available, e.g. local dev).
 */
export async function getIssue(
  installationToken: string,
  repoFullName: string,
  issueNumber: number
): Promise<{ number: number; state: 'open' | 'closed' }> {
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${repoFullName}/issues/${issueNumber}`,
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
    throw new Error(`Failed to fetch issue: ${response.status} ${errorText}`);
  }
  return (await response.json()) as { number: number; state: 'open' | 'closed' };
}

export async function listIssueComments(
  installationToken: string,
  repoFullName: string,
  issueNumber: number
): Promise<Array<{ id: number; body: string; user: { login: string; id: number } | null }>> {
  const allComments: Array<{ id: number; body: string; user: { login: string; id: number } | null }> = [];
  let page = 1;
  while (true) {
    const response = await fetch(
      `${GITHUB_API_BASE}/repos/${repoFullName}/issues/${issueNumber}/comments?per_page=100&page=${page}`,
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
      throw new Error(`Failed to list comments: ${response.status} ${errorText}`);
    }
    const data = (await response.json()) as Array<{ id: number; body: string; user: { login: string; id: number } | null }>;
    allComments.push(...data);
    if (data.length < 100) break;
    page++;
  }
  return allComments;
}

export async function updateIssueComment(
  installationToken: string,
  repoFullName: string,
  commentId: number,
  body: string
): Promise<void> {
  const response = await fetch(
    `${GITHUB_API_BASE}/repos/${repoFullName}/issues/comments/${commentId}`,
    {
      method: 'PATCH',
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
    throw new Error(`Failed to update comment: ${response.status} ${errorText}`);
  }
}

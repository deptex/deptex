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

function getPrivateKey(): string {
  if (process.env.GITHUB_APP_PRIVATE_KEY) {
    return process.env.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g, '\n');
  }
  const keyPath = process.env.GITHUB_APP_PRIVATE_KEY_PATH;
  if (keyPath) {
    const resolvedPath = path.isAbsolute(keyPath)
      ? keyPath
      : path.resolve(__dirname, '..', keyPath);
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
  const payload = { iat: now - 30, exp: now + 9 * 60, iss: appId };
  const header = { alg: 'RS256', typ: 'JWT' };
  const unsignedToken = `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(payload))}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsignedToken);
  signer.end();
  const signature = signer.sign(privateKey);
  return `${unsignedToken}.${base64Url(signature)}`;
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
        'User-Agent': 'Deptex-Worker',
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

export async function getBranchSha(
  installationToken: string,
  repoFullName: string,
  branch: string
): Promise<string> {
  const branchName = branch.startsWith('refs/heads/') ? branch.slice('refs/heads/'.length) : branch;
  const refEncoded = encodeURIComponent(`heads/${branchName}`);
  const url = `${GITHUB_API_BASE}/repos/${repoFullName}/git/ref/${refEncoded}`;
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-Worker',
    },
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to get branch ref: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as { object: { sha: string } };
  return data.object.sha;
}

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
      'User-Agent': 'Deptex-Worker',
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

export async function getRepositoryFileWithSha(
  installationToken: string,
  repoFullName: string,
  filePath: string,
  ref?: string
): Promise<{ content: string; sha: string }> {
  const url = new URL(`${GITHUB_API_BASE}/repos/${repoFullName}/contents/${filePath}`);
  if (ref) url.searchParams.set('ref', ref);
  const response = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-Worker',
    },
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to fetch ${filePath}: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as { content: string; encoding: string; sha: string };
  if (data.encoding !== 'base64') {
    throw new Error(`Unexpected encoding for ${filePath}: ${data.encoding}`);
  }
  return {
    content: Buffer.from(data.content, 'base64').toString('utf-8'),
    sha: data.sha,
  };
}

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
  if (currentSha) body.sha = currentSha;
  const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/contents/${filePath}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${installationToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Deptex-Worker',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to update file ${filePath}: ${response.status} ${errorText}`);
  }
}

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
      'User-Agent': 'Deptex-Worker',
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
        'User-Agent': 'Deptex-Worker',
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
        'User-Agent': 'Deptex-Worker',
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

/** List open PRs with the given head ref (e.g. branch name). Used when branch already exists to reuse existing PR. */
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
        'User-Agent': 'Deptex-Worker',
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

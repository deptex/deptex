import simpleGit from 'simple-git';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import crypto from 'crypto';

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
    const resolvedPath = path.resolve(__dirname, '../../', keyPath);
    if (fs.existsSync(resolvedPath)) {
      return fs.readFileSync(resolvedPath, 'utf8');
    }
    throw new Error(`GitHub App private key file not found at: ${resolvedPath}`);
  }
  throw new Error('GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH must be set');
}

function createGitHubAppJwt(): string {
  const appId = process.env.GITHUB_APP_ID;
  if (!appId) throw new Error('GITHUB_APP_ID is not configured');
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

async function createInstallationToken(installationId: string): Promise<string> {
  const jwt = createGitHubAppJwt();
  const response = await fetch(
    `${GITHUB_API_BASE}/app/installations/${installationId}/access_tokens`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-Extraction-Worker',
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

export async function cloneRepository(
  installationId: string,
  repoFullName: string,
  branch: string
): Promise<string> {
  const tempDir = path.join(
    os.tmpdir(),
    `deptex-extract-${Date.now()}-${Math.random().toString(36).substring(7)}`
  );
  fs.mkdirSync(tempDir, { recursive: true });
  try {
    const token = await createInstallationToken(installationId);
    const repoUrl = `https://x-access-token:${token}@github.com/${repoFullName}.git`;
    const git = simpleGit(tempDir);
    await git.clone(repoUrl, tempDir, ['--branch', branch, '--depth', '1', '--single-branch']);
    return tempDir;
  } catch (error: any) {
    if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
    throw new Error(`Failed to clone repository: ${error.message}`);
  }
}

export function cleanupRepository(repoPath: string): void {
  try {
    if (fs.existsSync(repoPath)) {
      fs.rmSync(repoPath, { recursive: true, force: true });
    }
  } catch (error) {
    console.warn(`Failed to cleanup repository at ${repoPath}:`, error);
  }
}

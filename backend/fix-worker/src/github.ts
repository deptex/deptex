import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const GITHUB_API_BASE = 'https://api.github.com';

const base64Url = (input: Buffer | string) => {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
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

export async function createInstallationToken(installationId: string): Promise<string> {
  const jwt = createGitHubAppJwt();
  const response = await fetch(
    `${GITHUB_API_BASE}/app/installations/${installationId}/access_tokens`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Deptex-Aegis-Fix',
      },
    },
  );
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to create installation token: ${response.status} ${errorText}`);
  }
  const data = (await response.json()) as { token: string };
  return data.token;
}

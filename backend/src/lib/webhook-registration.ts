/**
 * Register per-repo webhooks with GitLab and Bitbucket when a project connects a repository.
 * GitHub uses the App-level webhook and does not need per-repo registration.
 */

import * as crypto from 'crypto';

const GITLAB_API = '/api/v4';
const BITBUCKET_API = 'https://api.bitbucket.org/2.0';

export async function registerGitLabWebhook(
  baseUrl: string,
  accessToken: string,
  projectId: number,
  webhookUrl: string,
  secret: string
): Promise<{ id: number }> {
  const url = `${baseUrl.replace(/\/+$/, '')}${GITLAB_API}/projects/${encodeURIComponent(projectId)}/hooks`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': 'Deptex-App',
    },
    body: JSON.stringify({
      url: webhookUrl,
      token: secret,
      push_events: true,
      merge_requests_events: true,
      enable_ssl_verification: true,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitLab webhook registration failed (${res.status}): ${text}`);
  }
  const data = (await res.json()) as { id: number };
  return { id: data.id };
}

export async function registerBitbucketWebhook(
  accessToken: string,
  workspace: string,
  repoSlug: string,
  webhookUrl: string,
  secret: string
): Promise<{ uuid: string }> {
  const url = `${BITBUCKET_API}/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/hooks`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': 'Deptex-App',
    },
    body: JSON.stringify({
      description: 'Deptex',
      url: webhookUrl,
      active: true,
      secret,
      events: [
        'repo:push',
        'pullrequest:created',
        'pullrequest:updated',
        'pullrequest:fulfilled',
        'pullrequest:rejected',
      ],
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Bitbucket webhook registration failed (${res.status}): ${text}`);
  }
  const data = (await res.json()) as { uuid: string };
  return { uuid: data.uuid };
}

export function generateWebhookSecret(): string {
  return crypto.randomBytes(32).toString('hex');
}

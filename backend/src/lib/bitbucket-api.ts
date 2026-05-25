import type { RepoInfo, TreeEntry, GitProvider } from './git-provider';
import { supabase } from './supabase';

const BITBUCKET_API = 'https://api.bitbucket.org/2.0';
const BITBUCKET_TOKEN_URL = 'https://bitbucket.org/site/oauth2/access_token';

class BitbucketAuthExpiredError extends Error {}

async function bbFetchRaw(token: string, path: string): Promise<Response> {
  const url = path.startsWith('http') ? path : `${BITBUCKET_API}${path}`;
  console.log('[BB-DEBUG] bbFetch GET', url, ' tokenPrefix=', token.slice(0, 8) + '...');
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'Deptex-App',
    },
  });
  console.log('[BB-DEBUG] bbFetch response status=', response.status, response.statusText);
  if (response.status === 401) {
    const body = await response.text();
    throw new BitbucketAuthExpiredError(`401: ${body}`);
  }
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Bitbucket API error (${path}): ${response.status} ${errorText}`);
  }
  return response;
}

export class BitbucketProvider implements GitProvider {
  readonly provider = 'bitbucket' as const;
  private accessToken: string;
  private refreshToken: string | null;
  private integrationId: string | null;
  private workspace: string | undefined;

  constructor(
    accessToken: string,
    workspace?: string,
    refreshToken: string | null = null,
    integrationId: string | null = null,
  ) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.integrationId = integrationId;
    this.workspace = workspace;
  }

  private async refreshAccessToken(): Promise<void> {
    if (!this.refreshToken || !this.integrationId) {
      throw new Error('Bitbucket token expired and no refresh token / integration id available to refresh');
    }
    const clientId = process.env.BITBUCKET_CLIENT_ID;
    const clientSecret = process.env.BITBUCKET_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error('Bitbucket refresh requires BITBUCKET_CLIENT_ID/BITBUCKET_CLIENT_SECRET env');
    }
    console.log('[BB-DEBUG] refreshing access token for integration', this.integrationId);
    const tokenRes = await fetch(BITBUCKET_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: this.refreshToken,
      }),
    });
    const tokenData = (await tokenRes.json()) as {
      access_token?: string;
      refresh_token?: string;
      error?: string;
      error_description?: string;
    };
    if (tokenData.error || !tokenData.access_token) {
      throw new Error(`Bitbucket token refresh failed: ${tokenData.error_description || tokenData.error || 'no access_token in response'}`);
    }
    this.accessToken = tokenData.access_token;
    if (tokenData.refresh_token) this.refreshToken = tokenData.refresh_token;
    const { error: updErr } = await supabase
      .from('organization_integrations')
      .update({
        access_token: this.accessToken,
        refresh_token: this.refreshToken,
        updated_at: new Date().toISOString(),
      })
      .eq('id', this.integrationId);
    if (updErr) {
      console.warn('[BB-DEBUG] failed to persist refreshed Bitbucket token:', updErr.message);
    } else {
      console.log('[BB-DEBUG] persisted refreshed token to DB');
    }
  }

  private async bbFetch(path: string): Promise<Response> {
    try {
      return await bbFetchRaw(this.accessToken, path);
    } catch (err) {
      if (err instanceof BitbucketAuthExpiredError) {
        console.log('[BB-DEBUG] 401 received, attempting refresh + retry');
        await this.refreshAccessToken();
        return await bbFetchRaw(this.accessToken, path);
      }
      throw err;
    }
  }

  async listRepositories(): Promise<RepoInfo[]> {
    const repos: RepoInfo[] = [];

    // Bitbucket sunset every cross-workspace listing endpoint
    // (CHANGE-2770, April 2026). Integrations are now per-workspace and
    // the workspace slug must be captured at install time.
    if (!this.workspace) {
      throw new Error('Bitbucket integration is missing a workspace slug — reinstall the integration to select a workspace');
    }
    const workspaces: string[] = [this.workspace];

    for (const ws of workspaces) {
      let url: string | undefined = `/repositories/${encodeURIComponent(ws)}?pagelen=100&sort=-updated_on`;
      let pageCount = 0;
      while (url && pageCount < 10) {
        const res = await this.bbFetch(url);
        const data = (await res.json()) as {
          values: Array<{
            uuid: string;
            full_name: string;
            mainbranch?: { name: string };
            is_private: boolean;
          }>;
          next?: string;
        };

        console.log('[BB-DEBUG] workspace=', ws, 'page', pageCount, 'returned', data.values.length, 'repos:', JSON.stringify(data.values.map((r) => r.full_name)));

        for (const repo of data.values) {
          const numericId = Math.abs(hashString(repo.uuid));
          repos.push({
            id: numericId,
            full_name: repo.full_name,
            default_branch: repo.mainbranch?.name || 'main',
            private: repo.is_private,
          });
        }

        url = data.next;
        pageCount++;
      }
    }
    console.log('[BB-DEBUG] listRepositories DONE. total=', repos.length);
    return repos;
  }

  async getFileContent(repo: string, filePath: string, ref: string): Promise<string> {
    const [workspace, repoSlug] = repo.split('/');
    const res = await this.bbFetch(
      `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/${filePath}`
    );
    return res.text();
  }

  async getTreeRecursive(repo: string, ref: string): Promise<TreeEntry[]> {
    const [workspace, repoSlug] = repo.split('/');
    const entries: TreeEntry[] = [];
    let url: string | undefined = `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/?pagelen=100&max_depth=10`;
    let pageCount = 0;

    while (url && pageCount < 50) {
      const res = await this.bbFetch(url);
      const data = (await res.json()) as {
        values: Array<{ path: string; type: string }>;
        next?: string;
      };

      for (const entry of data.values) {
        entries.push({
          path: entry.path,
          type: entry.type === 'commit_directory' ? 'tree' : 'blob',
        });
      }

      url = data.next;
      pageCount++;
    }
    return entries;
  }

  async getRootContents(repo: string, ref: string): Promise<TreeEntry[]> {
    const [workspace, repoSlug] = repo.split('/');
    const res = await this.bbFetch(
      `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/?pagelen=100`
    );
    const data = (await res.json()) as {
      values: Array<{ path: string; type: string }>;
    };
    return data.values.map((entry) => ({
      path: entry.path,
      type: entry.type === 'commit_directory' ? 'tree' : 'blob',
    }));
  }

  getCloneUrl(repo: string): string {
    return `https://bitbucket.org/${repo}.git`;
  }

  async getCloneToken(): Promise<string> {
    return this.accessToken;
  }
}

function hashString(s: string): number {
  let hash = 0;
  for (let i = 0; i < s.length; i++) {
    const char = s.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return hash;
}

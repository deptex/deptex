import type { RepoInfo, TreeEntry, GitProvider } from './git-provider';
import { supabase } from './supabase';

const GITLAB_API = '/api/v4';

class GitLabAuthExpiredError extends Error {}

async function gitlabFetchRaw(baseUrl: string, token: string, path: string): Promise<Response> {
  const url = `${baseUrl}${GITLAB_API}${path}`;
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'Deptex-App',
    },
  });
  if (response.status === 401) {
    const body = await response.text();
    throw new GitLabAuthExpiredError(`401: ${body}`);
  }
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GitLab API error (${path}): ${response.status} ${errorText}`);
  }
  return response;
}

export class GitLabProvider implements GitProvider {
  readonly provider = 'gitlab' as const;
  private accessToken: string;
  private refreshToken: string | null;
  private integrationId: string | null;
  private baseUrl: string;

  constructor(
    accessToken: string,
    baseUrl: string = 'https://gitlab.com',
    refreshToken: string | null = null,
    integrationId: string | null = null,
  ) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.integrationId = integrationId;
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private async refreshAccessToken(): Promise<void> {
    if (!this.refreshToken || !this.integrationId) {
      throw new Error('GitLab token expired and no refresh token / integration id available to refresh');
    }
    const clientId = process.env.GITLAB_CLIENT_ID;
    const clientSecret = process.env.GITLAB_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error('GitLab refresh requires GITLAB_CLIENT_ID/GITLAB_CLIENT_SECRET env');
    }
    console.log('[GL-DEBUG] refreshing access token for integration', this.integrationId);
    const tokenRes = await fetch(`${this.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: this.refreshToken,
        grant_type: 'refresh_token',
      }),
    });
    const tokenData = (await tokenRes.json()) as {
      access_token?: string;
      refresh_token?: string;
      error?: string;
      error_description?: string;
    };
    if (tokenData.error || !tokenData.access_token) {
      throw new Error(`GitLab token refresh failed: ${tokenData.error_description || tokenData.error || 'no access_token in response'}`);
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
      console.warn('[GL-DEBUG] failed to persist refreshed GitLab token:', updErr.message);
    } else {
      console.log('[GL-DEBUG] persisted refreshed token to DB');
    }
  }

  private async gitlabFetch(path: string): Promise<Response> {
    try {
      return await gitlabFetchRaw(this.baseUrl, this.accessToken, path);
    } catch (err) {
      if (err instanceof GitLabAuthExpiredError) {
        console.log('[GL-DEBUG] 401 received, attempting refresh + retry');
        await this.refreshAccessToken();
        return await gitlabFetchRaw(this.baseUrl, this.accessToken, path);
      }
      throw err;
    }
  }

  async listRepositories(): Promise<RepoInfo[]> {
    const repos: RepoInfo[] = [];
    let page = 1;
    const perPage = 100;
    while (true) {
      const res = await this.gitlabFetch(
        `/projects?membership=true&min_access_level=20&per_page=${perPage}&page=${page}&order_by=last_activity_at&sort=desc`
      );
      const data = (await res.json()) as Array<{
        id: number;
        path_with_namespace: string;
        default_branch: string;
        visibility: string;
      }>;
      for (const project of data) {
        repos.push({
          id: project.id,
          full_name: project.path_with_namespace,
          default_branch: project.default_branch || 'main',
          private: project.visibility !== 'public',
        });
      }
      if (data.length < perPage) break;
      page++;
      if (page > 10) break;
    }
    return repos;
  }

  async getFileContent(repo: string, filePath: string, ref: string): Promise<string> {
    const projectId = encodeURIComponent(repo);
    const encodedPath = encodeURIComponent(filePath);
    const res = await this.gitlabFetch(
      `/projects/${projectId}/repository/files/${encodedPath}/raw?ref=${encodeURIComponent(ref)}`
    );
    return res.text();
  }

  async getTreeRecursive(repo: string, ref: string): Promise<TreeEntry[]> {
    const projectId = encodeURIComponent(repo);
    const entries: TreeEntry[] = [];
    let page = 1;
    const perPage = 100;
    while (true) {
      const res = await this.gitlabFetch(
        `/projects/${projectId}/repository/tree?ref=${encodeURIComponent(ref)}&recursive=true&per_page=${perPage}&page=${page}`
      );
      const data = (await res.json()) as Array<{ path: string; type: string }>;
      for (const entry of data) {
        entries.push({
          path: entry.path,
          type: entry.type === 'tree' ? 'tree' : 'blob',
        });
      }
      if (data.length < perPage) break;
      page++;
      if (page > 50) break;
    }
    return entries;
  }

  async getRootContents(repo: string, ref: string): Promise<TreeEntry[]> {
    const projectId = encodeURIComponent(repo);
    const res = await this.gitlabFetch(
      `/projects/${projectId}/repository/tree?ref=${encodeURIComponent(ref)}&per_page=100`
    );
    const data = (await res.json()) as Array<{ path: string; type: string; name: string }>;
    return data.map((entry) => ({
      path: entry.path,
      type: entry.type === 'tree' ? 'tree' : 'blob',
    }));
  }

  getCloneUrl(repo: string): string {
    return `${this.baseUrl}/${repo}.git`;
  }

  async getCloneToken(): Promise<string> {
    return this.accessToken;
  }
}

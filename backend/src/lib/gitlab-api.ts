import type { RepoInfo, TreeEntry, GitProvider } from './git-provider';
import { supabase } from './supabase';
import {
  fetchWithRetry,
  AuthExpiredError,
  ProviderError,
} from './provider-fetch';

const GITLAB_API = '/api/v4';

export class GitLabProvider implements GitProvider {
  readonly provider = 'gitlab' as const;
  private accessToken: string;
  private refreshToken: string | null;
  private integrationId: string | null;
  private baseUrl: string;
  /**
   * Single-flight refresh: if multiple concurrent calls hit a 401, they share
   * one POST /oauth/token rather than each firing their own. Without this, the
   * provider rotates the refresh_token on the winner and every loser holds a
   * stale token → integration permanently dead until reinstall.
   */
  private refreshPromise: Promise<void> | null = null;

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

  private async doRefreshAccessToken(): Promise<void> {
    if (!this.refreshToken || !this.integrationId) {
      throw new Error('GitLab token expired and no refresh token / integration id available to refresh');
    }
    const clientId = process.env.GITLAB_CLIENT_ID;
    const clientSecret = process.env.GITLAB_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error('GitLab refresh requires GITLAB_CLIENT_ID/GITLAB_CLIENT_SECRET env');
    }
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
    if (!tokenRes.ok) {
      const body = await tokenRes.text();
      throw new ProviderError('gitlab', tokenRes.status, '/oauth/token', body.slice(0, 200));
    }
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
      console.warn('Failed to persist refreshed GitLab token:', updErr.message);
    }
  }

  private async refreshAccessToken(): Promise<void> {
    if (this.refreshPromise) return this.refreshPromise;
    this.refreshPromise = this.doRefreshAccessToken().finally(() => {
      this.refreshPromise = null;
    });
    return this.refreshPromise;
  }

  private async gitlabFetch(apiPath: string): Promise<Response> {
    const doFetch = () =>
      fetch(`${this.baseUrl}${GITLAB_API}${apiPath}`, {
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          'User-Agent': 'Deptex-App',
        },
      });
    try {
      return await fetchWithRetry('gitlab', apiPath, doFetch);
    } catch (err) {
      if (err instanceof AuthExpiredError) {
        await this.refreshAccessToken();
        return await fetchWithRetry('gitlab', apiPath, doFetch);
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
        `/projects?membership=true&min_access_level=30&per_page=${perPage}&page=${page}&order_by=last_activity_at&sort=desc`
      );
      const data = (await res.json()) as Array<{
        id: number;
        path_with_namespace: string;
        default_branch: string | null;
        visibility: string;
      }>;
      for (const project of data) {
        // Skip empty repos (no default branch yet). Connecting them would
        // queue an extraction that fails at clone with no actionable error.
        if (!project.default_branch) continue;
        repos.push({
          id: project.id,
          full_name: project.path_with_namespace,
          default_branch: project.default_branch,
          private: project.visibility !== 'public',
        });
      }
      if (data.length < perPage) break;
      page++;
      if (page > 50) break;
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
          // GitLab returns 'tree' | 'blob' | 'commit' (submodule). Map
          // submodules to a distinct type so callers can skip them.
          type:
            entry.type === 'tree'
              ? 'tree'
              : entry.type === 'commit'
                ? 'submodule'
                : 'blob',
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
      type:
        entry.type === 'tree'
          ? 'tree'
          : entry.type === 'commit'
            ? 'submodule'
            : 'blob',
    }));
  }

  getCloneUrl(repo: string): string {
    return `${this.baseUrl}/${repo}.git`;
  }

  async getCloneToken(): Promise<string> {
    return this.accessToken;
  }
}

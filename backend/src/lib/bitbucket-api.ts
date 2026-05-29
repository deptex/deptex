import type { RepoInfo, TreeEntry, GitProvider } from './git-provider';
import { supabase } from './supabase';
import {
  fetchWithRetry,
  AuthExpiredError,
  ProviderError,
} from './provider-fetch';

const BITBUCKET_API = 'https://api.bitbucket.org/2.0';
const BITBUCKET_TOKEN_URL = 'https://bitbucket.org/site/oauth2/access_token';

/**
 * The integration row throws this when there's no workspace slug. Atlassian
 * sunset every cross-workspace listing endpoint in CHANGE-2770 (April 2026),
 * so an integration without a workspace can no longer enumerate anything.
 */
export class BitbucketWorkspaceMissingError extends Error {
  constructor() {
    super('Bitbucket integration is missing a workspace slug — reinstall the integration to select a workspace');
  }
}

export class BitbucketProvider implements GitProvider {
  readonly provider = 'bitbucket' as const;
  private accessToken: string;
  private refreshToken: string | null;
  private integrationId: string | null;
  private workspace: string | undefined;
  private refreshPromise: Promise<void> | null = null;

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

  private async doRefreshAccessToken(): Promise<void> {
    if (!this.refreshToken || !this.integrationId) {
      throw new Error('Bitbucket token expired and no refresh token / integration id available to refresh');
    }
    const clientId = process.env.BITBUCKET_CLIENT_ID;
    const clientSecret = process.env.BITBUCKET_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error('Bitbucket refresh requires BITBUCKET_CLIENT_ID/BITBUCKET_CLIENT_SECRET env');
    }
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
    if (!tokenRes.ok) {
      const body = await tokenRes.text();
      throw new ProviderError('bitbucket', tokenRes.status, '/site/oauth2/access_token', body.slice(0, 200));
    }
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
      console.warn('Failed to persist refreshed Bitbucket token:', updErr.message);
    }
  }

  private async refreshAccessToken(): Promise<void> {
    if (this.refreshPromise) return this.refreshPromise;
    this.refreshPromise = this.doRefreshAccessToken().finally(() => {
      this.refreshPromise = null;
    });
    return this.refreshPromise;
  }

  private async bbFetch(apiPath: string): Promise<Response> {
    const doFetch = () =>
      fetch(apiPath.startsWith('http') ? apiPath : `${BITBUCKET_API}${apiPath}`, {
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          'User-Agent': 'Deptex-App',
        },
      });
    try {
      return await fetchWithRetry('bitbucket', apiPath, doFetch);
    } catch (err) {
      if (err instanceof AuthExpiredError) {
        await this.refreshAccessToken();
        return await fetchWithRetry('bitbucket', apiPath, doFetch);
      }
      throw err;
    }
  }

  async listRepositories(): Promise<RepoInfo[]> {
    if (!this.workspace) {
      throw new BitbucketWorkspaceMissingError();
    }

    const repos: RepoInfo[] = [];
    let url: string | undefined = `/repositories/${encodeURIComponent(this.workspace)}?pagelen=100&sort=-updated_on`;
    let pageCount = 0;
    while (url && pageCount < 50) {
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

      for (const repo of data.values) {
        // Skip empty repos (no main branch yet); connecting them would queue
        // an extraction that fails at clone with no actionable error.
        if (!repo.mainbranch?.name) continue;
        const numericId = Math.abs(hashString(repo.uuid));
        repos.push({
          id: numericId,
          full_name: repo.full_name,
          default_branch: repo.mainbranch.name,
          private: repo.is_private,
        });
      }

      url = data.next;
      pageCount++;
    }
    return repos;
  }

  async getFileContent(repo: string, filePath: string, ref: string): Promise<string> {
    const [workspace, repoSlug] = repo.split('/');
    const encodedPath = filePath.split('/').map(encodeURIComponent).join('/');
    const res = await this.bbFetch(
      `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/${encodedPath}`
    );
    return res.text();
  }

  async getTreeRecursive(repo: string, ref: string): Promise<{ entries: TreeEntry[]; truncated: boolean }> {
    const [workspace, repoSlug] = repo.split('/');
    const entries: TreeEntry[] = [];
    const MAX_DEPTH = 25;
    const PAGE_CAP = 100;
    let url: string | undefined = `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/?pagelen=100&max_depth=${MAX_DEPTH}`;
    let pageCount = 0;
    let maxDepthSeen = 0;
    let truncated = false;

    while (url && pageCount < PAGE_CAP) {
      const res = await this.bbFetch(url);
      const data = (await res.json()) as {
        values: Array<{ path: string; type: string }>;
        next?: string;
      };

      for (const entry of data.values) {
        // Bitbucket: 'commit_directory' = subtree, 'commit_file' = file,
        // 'commit_submodule' = submodule (gitlink).
        let type: 'tree' | 'blob' | 'submodule' = 'blob';
        if (entry.type === 'commit_directory') type = 'tree';
        else if (entry.type === 'commit_submodule') type = 'submodule';
        entries.push({ path: entry.path, type });
        const depth = entry.path.split('/').length;
        if (depth > maxDepthSeen) maxDepthSeen = depth;
      }

      url = data.next;
      pageCount++;
    }
    // If we hit the page cap or any tree entry sits at exactly MAX_DEPTH, the
    // server may have truncated deeper subtrees. Both cases mean detection is
    // incomplete and the user should be told.
    if (pageCount >= PAGE_CAP || maxDepthSeen >= MAX_DEPTH) {
      truncated = true;
    }
    return { entries, truncated };
  }

  async getRootContents(repo: string, ref: string): Promise<TreeEntry[]> {
    return this.listDirectory(repo, ref, '');
  }

  async listDirectory(repo: string, ref: string, path: string): Promise<TreeEntry[]> {
    const [workspace, repoSlug] = repo.split('/');
    const pathSuffix = path ? `${path.split('/').map(encodeURIComponent).join('/')}/` : '';
    const res = await this.bbFetch(
      `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/${pathSuffix}?pagelen=100`
    );
    const data = (await res.json()) as {
      values: Array<{ path: string; type: string }>;
    };
    return data.values.map((entry) => {
      let type: 'tree' | 'blob' | 'submodule' = 'blob';
      if (entry.type === 'commit_directory') type = 'tree';
      else if (entry.type === 'commit_submodule') type = 'submodule';
      return { path: entry.path, type };
    });
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

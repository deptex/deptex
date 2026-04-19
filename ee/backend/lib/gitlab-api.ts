import type { RepoInfo, TreeEntry, GitProvider } from './git-provider';

const GITLAB_API = '/api/v4';

async function gitlabFetch(baseUrl: string, token: string, path: string): Promise<Response> {
  const url = `${baseUrl}${GITLAB_API}${path}`;
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'Deptex-App',
    },
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GitLab API error (${path}): ${response.status} ${errorText}`);
  }
  return response;
}

export class GitLabProvider implements GitProvider {
  readonly provider = 'gitlab' as const;
  private accessToken: string;
  private baseUrl: string;

  constructor(accessToken: string, baseUrl: string = 'https://gitlab.com') {
    this.accessToken = accessToken;
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  async listRepositories(): Promise<RepoInfo[]> {
    const repos: RepoInfo[] = [];
    let page = 1;
    const perPage = 100;
    while (true) {
      const res = await gitlabFetch(
        this.baseUrl,
        this.accessToken,
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
    const res = await gitlabFetch(
      this.baseUrl,
      this.accessToken,
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
      const res = await gitlabFetch(
        this.baseUrl,
        this.accessToken,
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
    const res = await gitlabFetch(
      this.baseUrl,
      this.accessToken,
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

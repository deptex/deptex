import type { RepoInfo, TreeEntry, GitProvider } from './git-provider';

const BITBUCKET_API = 'https://api.bitbucket.org/2.0';

async function bbFetch(token: string, path: string): Promise<Response> {
  const url = path.startsWith('http') ? path : `${BITBUCKET_API}${path}`;
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'Deptex-App',
    },
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Bitbucket API error (${path}): ${response.status} ${errorText}`);
  }
  return response;
}

export class BitbucketProvider implements GitProvider {
  readonly provider = 'bitbucket' as const;
  private accessToken: string;
  private workspace: string | undefined;

  constructor(accessToken: string, workspace?: string) {
    this.accessToken = accessToken;
    this.workspace = workspace;
  }

  async listRepositories(): Promise<RepoInfo[]> {
    const repos: RepoInfo[] = [];
    let url: string;

    if (this.workspace) {
      url = `/repositories/${encodeURIComponent(this.workspace)}?pagelen=100&sort=-updated_on`;
    } else {
      url = `/repositories?role=member&pagelen=100&sort=-updated_on`;
    }

    let pageCount = 0;
    while (url && pageCount < 10) {
      const res = await bbFetch(this.accessToken, url);
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
        const numericId = Math.abs(hashString(repo.uuid));
        repos.push({
          id: numericId,
          full_name: repo.full_name,
          default_branch: repo.mainbranch?.name || 'main',
          private: repo.is_private,
        });
      }

      url = data.next || '';
      pageCount++;
    }
    return repos;
  }

  async getFileContent(repo: string, filePath: string, ref: string): Promise<string> {
    const [workspace, repoSlug] = repo.split('/');
    const res = await bbFetch(
      this.accessToken,
      `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/${filePath}`
    );
    return res.text();
  }

  async getTreeRecursive(repo: string, ref: string): Promise<TreeEntry[]> {
    const [workspace, repoSlug] = repo.split('/');
    const entries: TreeEntry[] = [];
    let url = `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/?pagelen=100&max_depth=10`;
    let pageCount = 0;

    while (url && pageCount < 50) {
      const res = await bbFetch(this.accessToken, url);
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

      url = data.next || '';
      pageCount++;
    }
    return entries;
  }

  async getRootContents(repo: string, ref: string): Promise<TreeEntry[]> {
    const [workspace, repoSlug] = repo.split('/');
    const res = await bbFetch(
      this.accessToken,
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

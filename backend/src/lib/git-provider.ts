import {
  createInstallationToken,
  listInstallationRepositories,
  getRepositoryFileContent as ghGetFileContent,
  getRepositoryTreeRecursiveWithFlag as ghGetTreeRecursiveWithFlag,
  getRepositoryDirectoryContents as ghGetDirContents,
} from './github';

export interface RepoInfo {
  id: number;
  full_name: string;
  default_branch: string;
  private: boolean;
}

export interface TreeEntry {
  path: string;
  /** 'tree' (subdirectory), 'blob' (file), or 'submodule' (gitlink). */
  type: string;
}

/** Result of a recursive tree walk. `truncated` means the provider didn't return
 * the full tree — either hit a provider-side entry/size cap (GitHub ~100k entries)
 * or our own pagination/depth cap (Bitbucket max_depth, page cap). Downstream
 * consumers should surface this so users know detection may be incomplete. */
export interface RecursiveTreeResult {
  entries: TreeEntry[];
  truncated: boolean;
}

export interface GitProvider {
  readonly provider: 'github' | 'gitlab' | 'bitbucket';
  listRepositories(): Promise<RepoInfo[]>;
  getFileContent(repo: string, filePath: string, ref: string): Promise<string>;
  getTreeRecursive(repo: string, ref: string): Promise<RecursiveTreeResult>;
  getRootContents(repo: string, ref: string): Promise<TreeEntry[]>;
  /** Single-level directory listing. Empty path lists the repository root. */
  listDirectory(repo: string, ref: string, path: string): Promise<TreeEntry[]>;
  getCloneUrl(repo: string): string;
  getCloneToken(): Promise<string>;
}

export class GitHubProvider implements GitProvider {
  readonly provider = 'github' as const;
  private installationId: string;

  constructor(installationId: string) {
    this.installationId = installationId;
  }

  // Installation tokens are cached + deduplicated at module scope in
  // github.ts (createInstallationToken) so a fresh provider instance per
  // HTTP request doesn't mint a new token every time.
  private getToken(): Promise<string> {
    return createInstallationToken(this.installationId);
  }

  async listRepositories(): Promise<RepoInfo[]> {
    const token = await this.getToken();
    return listInstallationRepositories(token);
  }

  async getFileContent(repo: string, filePath: string, ref: string): Promise<string> {
    const token = await this.getToken();
    return ghGetFileContent(token, repo, filePath, ref);
  }

  async getTreeRecursive(repo: string, ref: string): Promise<RecursiveTreeResult> {
    const token = await this.getToken();
    const result = await ghGetTreeRecursiveWithFlag(token, repo, ref);
    return { entries: result.entries, truncated: result.truncated };
  }

  async getRootContents(repo: string, ref: string): Promise<TreeEntry[]> {
    return this.listDirectory(repo, ref, '');
  }

  async listDirectory(repo: string, ref: string, path: string): Promise<TreeEntry[]> {
    const token = await this.getToken();
    const items = await ghGetDirContents(token, repo, path, ref);
    return items.map((i) => ({ path: i.path, type: i.type === 'dir' ? 'tree' : 'blob' }));
  }

  getCloneUrl(repo: string): string {
    return `https://github.com/${repo}.git`;
  }

  async getCloneToken(): Promise<string> {
    return this.getToken();
  }
}

export { GitLabProvider } from './gitlab-api';
export { BitbucketProvider } from './bitbucket-api';

export interface OrgIntegration {
  id: string;
  provider: 'github' | 'gitlab' | 'bitbucket';
  installation_id?: string | null;
  access_token?: string | null;
  refresh_token?: string | null;
  metadata?: Record<string, any>;
}

export function createProvider(integration: OrgIntegration): GitProvider {
  switch (integration.provider) {
    case 'github': {
      if (!integration.installation_id) {
        throw new Error('GitHub integration missing installation_id');
      }
      return new GitHubProvider(integration.installation_id);
    }
    case 'gitlab': {
      const { GitLabProvider: GL } = require('./gitlab-api');
      if (!integration.access_token) {
        throw new Error('GitLab integration missing access_token');
      }
      const gitlabUrl = integration.metadata?.gitlab_url || process.env.GITLAB_URL || 'https://gitlab.com';
      return new GL(integration.access_token, gitlabUrl, integration.refresh_token ?? null, integration.id);
    }
    case 'bitbucket': {
      const { BitbucketProvider: BB } = require('./bitbucket-api');
      if (!integration.access_token) {
        throw new Error('Bitbucket integration missing access_token');
      }
      const workspace = integration.metadata?.workspace;
      return new BB(integration.access_token, workspace, integration.refresh_token ?? null, integration.id);
    }
    default:
      throw new Error(`Unsupported provider: ${integration.provider}`);
  }
}

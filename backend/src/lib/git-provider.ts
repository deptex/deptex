import {
  createInstallationToken,
  listInstallationRepositories,
  getRepositoryFileContent as ghGetFileContent,
  getRepositoryTreeRecursive as ghGetTreeRecursive,
  getRepositoryRootContents as ghGetRootContents,
} from './github';

export interface RepoInfo {
  id: number;
  full_name: string;
  default_branch: string;
  private: boolean;
}

export interface TreeEntry {
  path: string;
  type: string;
}

export interface GitProvider {
  readonly provider: 'github' | 'gitlab' | 'bitbucket';
  listRepositories(): Promise<RepoInfo[]>;
  getFileContent(repo: string, filePath: string, ref: string): Promise<string>;
  getTreeRecursive(repo: string, ref: string): Promise<TreeEntry[]>;
  getRootContents(repo: string, ref: string): Promise<TreeEntry[]>;
  getCloneUrl(repo: string): string;
  getCloneToken(): Promise<string>;
}

export class GitHubProvider implements GitProvider {
  readonly provider = 'github' as const;
  private installationId: string;
  private tokenCache: { token: string; expiresAt: number } | null = null;

  constructor(installationId: string) {
    this.installationId = installationId;
  }

  private async getToken(): Promise<string> {
    if (this.tokenCache && Date.now() < this.tokenCache.expiresAt) {
      return this.tokenCache.token;
    }
    const token = await createInstallationToken(this.installationId);
    this.tokenCache = { token, expiresAt: Date.now() + 50 * 60 * 1000 };
    return token;
  }

  async listRepositories(): Promise<RepoInfo[]> {
    const token = await this.getToken();
    return listInstallationRepositories(token);
  }

  async getFileContent(repo: string, filePath: string, ref: string): Promise<string> {
    const token = await this.getToken();
    return ghGetFileContent(token, repo, filePath, ref);
  }

  async getTreeRecursive(repo: string, ref: string): Promise<TreeEntry[]> {
    const token = await this.getToken();
    return ghGetTreeRecursive(token, repo, ref);
  }

  async getRootContents(repo: string, ref: string): Promise<TreeEntry[]> {
    const token = await this.getToken();
    const items = await ghGetRootContents(token, repo, ref);
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
      return new GL(integration.access_token, gitlabUrl);
    }
    case 'bitbucket': {
      const { BitbucketProvider: BB } = require('./bitbucket-api');
      if (!integration.access_token) {
        throw new Error('Bitbucket integration missing access_token');
      }
      const workspace = integration.metadata?.workspace;
      return new BB(integration.access_token, workspace);
    }
    default:
      throw new Error(`Unsupported provider: ${integration.provider}`);
  }
}

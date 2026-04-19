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
export declare class GitHubProvider implements GitProvider {
    readonly provider: "github";
    private installationId;
    private tokenCache;
    constructor(installationId: string);
    private getToken;
    listRepositories(): Promise<RepoInfo[]>;
    getFileContent(repo: string, filePath: string, ref: string): Promise<string>;
    getTreeRecursive(repo: string, ref: string): Promise<TreeEntry[]>;
    getRootContents(repo: string, ref: string): Promise<TreeEntry[]>;
    getCloneUrl(repo: string): string;
    getCloneToken(): Promise<string>;
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
export declare function createProvider(integration: OrgIntegration): GitProvider;
//# sourceMappingURL=git-provider.d.ts.map
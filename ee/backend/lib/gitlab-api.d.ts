import type { RepoInfo, TreeEntry, GitProvider } from './git-provider';
export declare class GitLabProvider implements GitProvider {
    readonly provider: "gitlab";
    private accessToken;
    private baseUrl;
    constructor(accessToken: string, baseUrl?: string);
    listRepositories(): Promise<RepoInfo[]>;
    getFileContent(repo: string, filePath: string, ref: string): Promise<string>;
    getTreeRecursive(repo: string, ref: string): Promise<TreeEntry[]>;
    getRootContents(repo: string, ref: string): Promise<TreeEntry[]>;
    getCloneUrl(repo: string): string;
    getCloneToken(): Promise<string>;
}
//# sourceMappingURL=gitlab-api.d.ts.map
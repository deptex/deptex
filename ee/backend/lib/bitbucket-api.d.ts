import type { RepoInfo, TreeEntry, GitProvider } from './git-provider';
export declare class BitbucketProvider implements GitProvider {
    readonly provider: "bitbucket";
    private accessToken;
    private workspace;
    constructor(accessToken: string, workspace?: string);
    listRepositories(): Promise<RepoInfo[]>;
    getFileContent(repo: string, filePath: string, ref: string): Promise<string>;
    getTreeRecursive(repo: string, ref: string): Promise<TreeEntry[]>;
    getRootContents(repo: string, ref: string): Promise<TreeEntry[]>;
    getCloneUrl(repo: string): string;
    getCloneToken(): Promise<string>;
}
//# sourceMappingURL=bitbucket-api.d.ts.map
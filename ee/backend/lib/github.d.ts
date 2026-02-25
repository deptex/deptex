export declare function createGitHubAppJwt(): string;
/** Get installation details including account login and avatar. Uses App JWT. */
export declare function getInstallationAccount(installationId: string): Promise<{
    login: string;
    account_type?: string;
    avatar_url?: string;
} | null>;
export declare function createInstallationToken(installationId: string): Promise<string>;
export declare function listInstallationRepositories(installationToken: string): Promise<{
    id: number;
    full_name: string;
    default_branch: string;
    private: boolean;
}[]>;
export declare function getRepositoryFileContent(installationToken: string, repoFullName: string, path: string, ref?: string): Promise<string>;
/**
 * Get file content and blob sha (for later update). Returns { content, sha }.
 */
export declare function getRepositoryFileWithSha(installationToken: string, repoFullName: string, filePath: string, ref?: string): Promise<{
    content: string;
    sha: string;
}>;
/** Root directory listing: GET /repos/:owner/:repo/contents (no path) */
export declare function getRepositoryRootContents(installationToken: string, repoFullName: string, ref?: string): Promise<Array<{
    name: string;
    path: string;
    type: string;
}>>;
/** Recursive tree (all files/dirs) for monorepo scan. Uses Git Trees API. */
export declare function getRepositoryTreeRecursive(installationToken: string, repoFullName: string, ref: string): Promise<Array<{
    path: string;
    type: string;
}>>;
/**
 * Clone a GitHub repository to a local directory
 * Uses the installation token for authentication
 */
export declare function cloneRepository(installationToken: string, repoFullName: string, branch: string, targetDir: string): Promise<void>;
export declare function getCommitDiff(installationToken: string, repoFullName: string, sha: string): Promise<string>;
/**
 * Fetch commit diff from a public repository
 * Uses GITHUB_PAT env var if available, otherwise makes unauthenticated request (rate limited)
 */
export declare function getCommitDiffPublic(repoFullName: string, sha: string): Promise<string>;
/**
 * Get the list of file paths changed between two refs (e.g. push before/after).
 * Uses Compare API: GET /repos/{owner}/{repo}/compare/{base}...{head}
 */
export declare function getCompareChangedFiles(installationToken: string, repoFullName: string, baseRef: string, headRef: string): Promise<string[]>;
/**
 * Get the commit SHA of a branch (e.g. default branch) for creating a new branch from it.
 */
export declare function getBranchSha(installationToken: string, repoFullName: string, branch: string): Promise<string>;
/**
 * Create a new branch from an existing branch's commit SHA.
 */
export declare function createBranch(installationToken: string, repoFullName: string, newBranchName: string, fromSha: string): Promise<void>;
/**
 * Create or update a file on a branch. Content must be UTF-8; it will be base64-encoded.
 * For update, pass the current file sha (from getRepositoryFileWithSha).
 */
export declare function createOrUpdateFileOnBranch(installationToken: string, repoFullName: string, branch: string, filePath: string, content: string, message: string, currentSha?: string): Promise<void>;
/**
 * Create a pull request. Returns the PR HTML URL.
 */
export declare function createPullRequest(installationToken: string, repoFullName: string, base: string, head: string, title: string, body: string): Promise<{
    html_url: string;
    number: number;
}>;
/**
 * List open pull requests whose head branch matches (e.g. owner:branch for same repo).
 * Returns array of { html_url, number }.
 */
export declare function listPullRequestsByHead(installationToken: string, repoFullName: string, headRef: string): Promise<{
    html_url: string;
    number: number;
}[]>;
/**
 * Get a pull request by number. Returns state (open/closed) and other fields.
 */
export declare function getPullRequest(installationToken: string, repoFullName: string, prNumber: number): Promise<{
    state: string;
}>;
/**
 * Close a pull request by number.
 */
export declare function closePullRequest(installationToken: string, repoFullName: string, prNumber: number): Promise<void>;
/** Check run output for create/update */
export interface CheckRunOutput {
    title: string;
    summary: string;
    text?: string;
}
/**
 * List check runs for a ref, optionally filtered by check name.
 * Returns runs with id, name, status, conclusion.
 */
export declare function listCheckRunsForRef(installationToken: string, repoFullName: string, ref: string, checkName?: string): Promise<{
    id: number;
    name: string;
    status: string;
    conclusion: string | null;
}[]>;
/**
 * Create a check run. Name and head_sha are required.
 * status defaults to 'completed'; pass conclusion for success/failure.
 */
export declare function createCheckRun(installationToken: string, repoFullName: string, headSha: string, name: string, options?: {
    status?: 'queued' | 'in_progress' | 'completed';
    conclusion?: 'success' | 'failure' | 'cancelled' | 'skipped' | 'neutral' | 'timed_out' | 'action_required';
    output?: CheckRunOutput;
}): Promise<{
    id: number;
    html_url: string;
}>;
/**
 * Update an existing check run by id.
 */
export declare function updateCheckRun(installationToken: string, repoFullName: string, checkRunId: number, options: {
    status?: 'queued' | 'in_progress' | 'completed';
    conclusion?: 'success' | 'failure' | 'cancelled' | 'skipped' | 'neutral' | 'timed_out' | 'action_required';
    output?: CheckRunOutput;
}): Promise<void>;
/**
 * Create a comment on an issue or pull request (PRs use the issues API for comments).
 */
export declare function createIssueComment(installationToken: string, repoFullName: string, issueNumber: number, body: string): Promise<{
    id: number;
    html_url: string;
}>;
//# sourceMappingURL=github.d.ts.map
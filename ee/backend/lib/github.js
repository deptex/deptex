"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGitHubAppJwt = createGitHubAppJwt;
exports.getInstallationAccount = getInstallationAccount;
exports.createInstallationToken = createInstallationToken;
exports.listInstallationRepositories = listInstallationRepositories;
exports.getRepositoryFileContent = getRepositoryFileContent;
exports.getRepositoryFileWithSha = getRepositoryFileWithSha;
exports.getRepositoryRootContents = getRepositoryRootContents;
exports.getRepositoryTreeRecursive = getRepositoryTreeRecursive;
exports.cloneRepository = cloneRepository;
exports.getCommitDiff = getCommitDiff;
exports.getCommitDiffPublic = getCommitDiffPublic;
exports.getCompareChangedFiles = getCompareChangedFiles;
exports.getBranchSha = getBranchSha;
exports.createBranch = createBranch;
exports.createOrUpdateFileOnBranch = createOrUpdateFileOnBranch;
exports.createPullRequest = createPullRequest;
exports.listPullRequestsByHead = listPullRequestsByHead;
exports.getPullRequest = getPullRequest;
exports.closePullRequest = closePullRequest;
exports.listCheckRunsForRef = listCheckRunsForRef;
exports.createCheckRun = createCheckRun;
exports.updateCheckRun = updateCheckRun;
exports.createIssueComment = createIssueComment;
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const GITHUB_API_BASE = 'https://api.github.com';
const base64Url = (input) => {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
    return buf
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
};
/**
 * Get the GitHub App private key from env var or file path
 */
function getPrivateKey() {
    // First try direct env var
    if (process.env.GITHUB_APP_PRIVATE_KEY) {
        return process.env.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g, '\n');
    }
    // Then try file path
    const keyPath = process.env.GITHUB_APP_PRIVATE_KEY_PATH;
    if (keyPath) {
        // Resolve relative to backend root (parent of src/lib)
        const resolvedPath = path_1.default.resolve(__dirname, '../../', keyPath);
        if (fs_1.default.existsSync(resolvedPath)) {
            return fs_1.default.readFileSync(resolvedPath, 'utf8');
        }
        throw new Error(`GitHub App private key file not found at: ${resolvedPath}`);
    }
    throw new Error('GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH must be set');
}
function createGitHubAppJwt() {
    const appId = process.env.GITHUB_APP_ID;
    if (!appId) {
        throw new Error('GITHUB_APP_ID is not configured');
    }
    const privateKey = getPrivateKey();
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iat: now - 30,
        exp: now + 9 * 60,
        iss: appId,
    };
    const header = { alg: 'RS256', typ: 'JWT' };
    const unsignedToken = `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(payload))}`;
    const signer = crypto_1.default.createSign('RSA-SHA256');
    signer.update(unsignedToken);
    signer.end();
    const signature = signer.sign(privateKey);
    return `${unsignedToken}.${base64Url(signature)}`;
}
/** Get installation details including account login and avatar. Uses App JWT. */
async function getInstallationAccount(installationId) {
    const jwt = createGitHubAppJwt();
    const response = await fetch(`${GITHUB_API_BASE}/app/installations/${installationId}`, {
        headers: {
            Authorization: `Bearer ${jwt}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok)
        return null;
    const data = (await response.json());
    const login = data.account?.login;
    const accountType = data.account?.type;
    const avatarUrl = data.account?.avatar_url;
    return login ? { login, account_type: accountType, avatar_url: avatarUrl } : null;
}
async function createInstallationToken(installationId) {
    const jwt = createGitHubAppJwt();
    const response = await fetch(`${GITHUB_API_BASE}/app/installations/${installationId}/access_tokens`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${jwt}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to create installation token: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    return data.token;
}
async function listInstallationRepositories(installationToken) {
    const response = await fetch(`${GITHUB_API_BASE}/installation/repositories?per_page=100`, {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to list repositories: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    return data.repositories || [];
}
async function getRepositoryFileContent(installationToken, repoFullName, path, ref) {
    const result = await getRepositoryFileWithSha(installationToken, repoFullName, path, ref);
    return result.content;
}
/**
 * Get file content and blob sha (for later update). Returns { content, sha }.
 */
async function getRepositoryFileWithSha(installationToken, repoFullName, filePath, ref) {
    const url = new URL(`${GITHUB_API_BASE}/repos/${repoFullName}/contents/${filePath}`);
    if (ref) {
        url.searchParams.set('ref', ref);
    }
    const response = await fetch(url.toString(), {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to fetch ${filePath}: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    if (data.encoding !== 'base64') {
        throw new Error(`Unexpected encoding for ${filePath}: ${data.encoding}`);
    }
    return {
        content: Buffer.from(data.content, 'base64').toString('utf-8'),
        sha: data.sha,
    };
}
/** Root directory listing: GET /repos/:owner/:repo/contents (no path) */
async function getRepositoryRootContents(installationToken, repoFullName, ref) {
    const url = new URL(`${GITHUB_API_BASE}/repos/${repoFullName}/contents`);
    if (ref) {
        url.searchParams.set('ref', ref);
    }
    const response = await fetch(url.toString(), {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to list root contents: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    return Array.isArray(data) ? data : [];
}
/** Recursive tree (all files/dirs) for monorepo scan. Uses Git Trees API. */
async function getRepositoryTreeRecursive(installationToken, repoFullName, ref) {
    const commitSha = await getBranchSha(installationToken, repoFullName, ref);
    const commitUrl = `${GITHUB_API_BASE}/repos/${repoFullName}/git/commits/${commitSha}`;
    const commitRes = await fetch(commitUrl, {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!commitRes.ok) {
        const errorText = await commitRes.text();
        throw new Error(`Failed to get commit: ${commitRes.status} ${errorText}`);
    }
    const commitData = (await commitRes.json());
    const treeSha = commitData.tree?.sha;
    if (!treeSha) {
        throw new Error('Commit has no tree');
    }
    const treeUrl = `${GITHUB_API_BASE}/repos/${repoFullName}/git/trees/${treeSha}?recursive=1`;
    const treeRes = await fetch(treeUrl, {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!treeRes.ok) {
        const errorText = await treeRes.text();
        throw new Error(`Failed to get tree: ${treeRes.status} ${errorText}`);
    }
    const treeData = (await treeRes.json());
    const tree = treeData.tree || [];
    return tree.map((node) => ({ path: node.path, type: node.type }));
}
/**
 * Clone a GitHub repository to a local directory
 * Uses the installation token for authentication
 */
async function cloneRepository(installationToken, repoFullName, branch, targetDir) {
    // Dynamic import to avoid requiring simple-git in the main backend
    const simpleGit = await Promise.resolve().then(() => __importStar(require('simple-git')));
    const git = simpleGit.default(targetDir);
    // Construct GitHub clone URL with token
    // Format: https://x-access-token:TOKEN@github.com/owner/repo.git
    const repoUrl = `https://x-access-token:${installationToken}@github.com/${repoFullName}.git`;
    try {
        // Clone the repository
        await git.clone(repoUrl, targetDir, ['--branch', branch, '--depth', '1']);
    }
    catch (error) {
        // If directory already exists or clone fails, try to pull instead
        if (error.message?.includes('already exists')) {
            const existingGit = simpleGit.default(targetDir);
            await existingGit.pull('origin', branch);
        }
        else {
            throw new Error(`Failed to clone repository: ${error.message}`);
        }
    }
}
async function getCommitDiff(installationToken, repoFullName, sha) {
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/commits/${sha}`, {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github.v3.diff',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to fetch commit diff: ${response.status} ${errorText}`);
    }
    return response.text();
}
/**
 * Fetch commit diff from a public repository
 * Uses GITHUB_PAT env var if available, otherwise makes unauthenticated request (rate limited)
 */
async function getCommitDiffPublic(repoFullName, sha) {
    const headers = {
        Accept: 'application/vnd.github.v3.diff',
        'User-Agent': 'Deptex-App',
    };
    // Use PAT if available for higher rate limits
    const pat = process.env.GITHUB_PAT;
    if (pat) {
        headers['Authorization'] = `Bearer ${pat}`;
    }
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/commits/${sha}`, {
        headers,
    });
    if (!response.ok) {
        const errorText = await response.text();
        if (response.status === 403 && errorText.includes('rate limit')) {
            throw new Error('GitHub API rate limit exceeded. Configure GITHUB_PAT environment variable for higher limits.');
        }
        throw new Error(`Failed to fetch commit diff: ${response.status} ${errorText}`);
    }
    return response.text();
}
/**
 * Get the list of file paths changed between two refs (e.g. push before/after).
 * Uses Compare API: GET /repos/{owner}/{repo}/compare/{base}...{head}
 */
async function getCompareChangedFiles(installationToken, repoFullName, baseRef, headRef) {
    const comparePath = `${baseRef}...${headRef}`;
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/compare/${encodeURIComponent(comparePath)}`, {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to compare refs: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    const files = data.files ?? [];
    const paths = new Set();
    for (const f of files) {
        if (f.filename)
            paths.add(f.filename);
        if (f.previous_filename)
            paths.add(f.previous_filename);
    }
    return [...paths];
}
/**
 * Get the commit SHA of a branch (e.g. default branch) for creating a new branch from it.
 */
async function getBranchSha(installationToken, repoFullName, branch) {
    const branchName = branch.startsWith('refs/heads/') ? branch.slice('refs/heads/'.length) : branch;
    // Ref must be a single path segment; encode so "heads/deptex/bump-x" works
    const refEncoded = encodeURIComponent(`heads/${branchName}`);
    const url = `${GITHUB_API_BASE}/repos/${repoFullName}/git/ref/${refEncoded}`;
    const response = await fetch(url, {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to get branch ref: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    return data.object.sha;
}
/**
 * Create a new branch from an existing branch's commit SHA.
 */
async function createBranch(installationToken, repoFullName, newBranchName, fromSha) {
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/git/refs`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            ref: `refs/heads/${newBranchName}`,
            sha: fromSha,
        }),
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to create branch: ${response.status} ${errorText}`);
    }
}
/**
 * Create or update a file on a branch. Content must be UTF-8; it will be base64-encoded.
 * For update, pass the current file sha (from getRepositoryFileWithSha).
 */
async function createOrUpdateFileOnBranch(installationToken, repoFullName, branch, filePath, content, message, currentSha) {
    const body = {
        branch,
        message,
        content: Buffer.from(content, 'utf-8').toString('base64'),
    };
    if (currentSha) {
        body.sha = currentSha;
    }
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/contents/${filePath}`, {
        method: 'PUT',
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to update file ${filePath}: ${response.status} ${errorText}`);
    }
}
/**
 * Create a pull request. Returns the PR HTML URL.
 */
async function createPullRequest(installationToken, repoFullName, base, head, title, body) {
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/pulls`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ base, head, title, body }),
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to create pull request: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    return data;
}
/**
 * List open pull requests whose head branch matches (e.g. owner:branch for same repo).
 * Returns array of { html_url, number }.
 */
async function listPullRequestsByHead(installationToken, repoFullName, headRef) {
    const [owner] = repoFullName.split('/');
    const head = headRef.includes(':') ? headRef : `${owner}:${headRef}`;
    const params = new URLSearchParams({ state: 'open', head });
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/pulls?${params.toString()}`, {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to list pull requests: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    return data;
}
/**
 * Get a pull request by number. Returns state (open/closed) and other fields.
 */
async function getPullRequest(installationToken, repoFullName, prNumber) {
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/pulls/${prNumber}`, {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to get pull request: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    return data;
}
/**
 * Close a pull request by number.
 */
async function closePullRequest(installationToken, repoFullName, prNumber) {
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/pulls/${prNumber}`, {
        method: 'PATCH',
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ state: 'closed' }),
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to close pull request: ${response.status} ${errorText}`);
    }
}
/**
 * List check runs for a ref, optionally filtered by check name.
 * Returns runs with id, name, status, conclusion.
 */
async function listCheckRunsForRef(installationToken, repoFullName, ref, checkName) {
    const params = new URLSearchParams();
    if (checkName)
        params.set('check_name', checkName);
    const query = params.toString() ? `?${params.toString()}` : '';
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/commits/${encodeURIComponent(ref)}/check-runs${query}`, {
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
        },
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to list check runs: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    return data.check_runs ?? [];
}
/**
 * Create a check run. Name and head_sha are required.
 * status defaults to 'completed'; pass conclusion for success/failure.
 */
async function createCheckRun(installationToken, repoFullName, headSha, name, options = {}) {
    const { status = 'completed', conclusion, output } = options;
    const body = {
        name,
        head_sha: headSha,
        status,
    };
    if (conclusion)
        body.conclusion = conclusion;
    if (output)
        body.output = output;
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/check-runs`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to create check run: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    return data;
}
/**
 * Update an existing check run by id.
 */
async function updateCheckRun(installationToken, repoFullName, checkRunId, options) {
    const { status, conclusion, output } = options;
    const body = {};
    if (status !== undefined)
        body.status = status;
    if (conclusion !== undefined)
        body.conclusion = conclusion;
    if (output !== undefined)
        body.output = output;
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/check-runs/${checkRunId}`, {
        method: 'PATCH',
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to update check run: ${response.status} ${errorText}`);
    }
}
/**
 * Create a comment on an issue or pull request (PRs use the issues API for comments).
 */
async function createIssueComment(installationToken, repoFullName, issueNumber, body) {
    const response = await fetch(`${GITHUB_API_BASE}/repos/${repoFullName}/issues/${issueNumber}/comments`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${installationToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Deptex-App',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ body }),
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to create comment: ${response.status} ${errorText}`);
    }
    const data = (await response.json());
    return data;
}
//# sourceMappingURL=github.js.map
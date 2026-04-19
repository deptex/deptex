"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BitbucketProvider = exports.GitLabProvider = exports.GitHubProvider = void 0;
exports.createProvider = createProvider;
const github_1 = require("./github");
class GitHubProvider {
    constructor(installationId) {
        this.provider = 'github';
        this.tokenCache = null;
        this.installationId = installationId;
    }
    async getToken() {
        if (this.tokenCache && Date.now() < this.tokenCache.expiresAt) {
            return this.tokenCache.token;
        }
        const token = await (0, github_1.createInstallationToken)(this.installationId);
        this.tokenCache = { token, expiresAt: Date.now() + 50 * 60 * 1000 };
        return token;
    }
    async listRepositories() {
        const token = await this.getToken();
        return (0, github_1.listInstallationRepositories)(token);
    }
    async getFileContent(repo, filePath, ref) {
        const token = await this.getToken();
        return (0, github_1.getRepositoryFileContent)(token, repo, filePath, ref);
    }
    async getTreeRecursive(repo, ref) {
        const token = await this.getToken();
        return (0, github_1.getRepositoryTreeRecursive)(token, repo, ref);
    }
    async getRootContents(repo, ref) {
        const token = await this.getToken();
        const items = await (0, github_1.getRepositoryRootContents)(token, repo, ref);
        return items.map((i) => ({ path: i.path, type: i.type === 'dir' ? 'tree' : 'blob' }));
    }
    getCloneUrl(repo) {
        return `https://github.com/${repo}.git`;
    }
    async getCloneToken() {
        return this.getToken();
    }
}
exports.GitHubProvider = GitHubProvider;
var gitlab_api_1 = require("./gitlab-api");
Object.defineProperty(exports, "GitLabProvider", { enumerable: true, get: function () { return gitlab_api_1.GitLabProvider; } });
var bitbucket_api_1 = require("./bitbucket-api");
Object.defineProperty(exports, "BitbucketProvider", { enumerable: true, get: function () { return bitbucket_api_1.BitbucketProvider; } });
function createProvider(integration) {
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
//# sourceMappingURL=git-provider.js.map
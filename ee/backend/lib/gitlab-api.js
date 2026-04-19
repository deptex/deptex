"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GitLabProvider = void 0;
const GITLAB_API = '/api/v4';
async function gitlabFetch(baseUrl, token, path) {
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
class GitLabProvider {
    constructor(accessToken, baseUrl = 'https://gitlab.com') {
        this.provider = 'gitlab';
        this.accessToken = accessToken;
        this.baseUrl = baseUrl.replace(/\/+$/, '');
    }
    async listRepositories() {
        const repos = [];
        let page = 1;
        const perPage = 100;
        while (true) {
            const res = await gitlabFetch(this.baseUrl, this.accessToken, `/projects?membership=true&min_access_level=20&per_page=${perPage}&page=${page}&order_by=last_activity_at&sort=desc`);
            const data = (await res.json());
            for (const project of data) {
                repos.push({
                    id: project.id,
                    full_name: project.path_with_namespace,
                    default_branch: project.default_branch || 'main',
                    private: project.visibility !== 'public',
                });
            }
            if (data.length < perPage)
                break;
            page++;
            if (page > 10)
                break;
        }
        return repos;
    }
    async getFileContent(repo, filePath, ref) {
        const projectId = encodeURIComponent(repo);
        const encodedPath = encodeURIComponent(filePath);
        const res = await gitlabFetch(this.baseUrl, this.accessToken, `/projects/${projectId}/repository/files/${encodedPath}/raw?ref=${encodeURIComponent(ref)}`);
        return res.text();
    }
    async getTreeRecursive(repo, ref) {
        const projectId = encodeURIComponent(repo);
        const entries = [];
        let page = 1;
        const perPage = 100;
        while (true) {
            const res = await gitlabFetch(this.baseUrl, this.accessToken, `/projects/${projectId}/repository/tree?ref=${encodeURIComponent(ref)}&recursive=true&per_page=${perPage}&page=${page}`);
            const data = (await res.json());
            for (const entry of data) {
                entries.push({
                    path: entry.path,
                    type: entry.type === 'tree' ? 'tree' : 'blob',
                });
            }
            if (data.length < perPage)
                break;
            page++;
            if (page > 50)
                break;
        }
        return entries;
    }
    async getRootContents(repo, ref) {
        const projectId = encodeURIComponent(repo);
        const res = await gitlabFetch(this.baseUrl, this.accessToken, `/projects/${projectId}/repository/tree?ref=${encodeURIComponent(ref)}&per_page=100`);
        const data = (await res.json());
        return data.map((entry) => ({
            path: entry.path,
            type: entry.type === 'tree' ? 'tree' : 'blob',
        }));
    }
    getCloneUrl(repo) {
        return `${this.baseUrl}/${repo}.git`;
    }
    async getCloneToken() {
        return this.accessToken;
    }
}
exports.GitLabProvider = GitLabProvider;
//# sourceMappingURL=gitlab-api.js.map
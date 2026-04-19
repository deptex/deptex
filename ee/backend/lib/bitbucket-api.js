"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BitbucketProvider = void 0;
const BITBUCKET_API = 'https://api.bitbucket.org/2.0';
async function bbFetch(token, path) {
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
class BitbucketProvider {
    constructor(accessToken, workspace) {
        this.provider = 'bitbucket';
        this.accessToken = accessToken;
        this.workspace = workspace;
    }
    async listRepositories() {
        const repos = [];
        let url;
        if (this.workspace) {
            url = `/repositories/${encodeURIComponent(this.workspace)}?pagelen=100&sort=-updated_on`;
        }
        else {
            url = `/repositories?role=member&pagelen=100&sort=-updated_on`;
        }
        let pageCount = 0;
        while (url && pageCount < 10) {
            const res = await bbFetch(this.accessToken, url);
            const data = (await res.json());
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
    async getFileContent(repo, filePath, ref) {
        const [workspace, repoSlug] = repo.split('/');
        const res = await bbFetch(this.accessToken, `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/${filePath}`);
        return res.text();
    }
    async getTreeRecursive(repo, ref) {
        const [workspace, repoSlug] = repo.split('/');
        const entries = [];
        let url = `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/?pagelen=100&max_depth=10`;
        let pageCount = 0;
        while (url && pageCount < 50) {
            const res = await bbFetch(this.accessToken, url);
            const data = (await res.json());
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
    async getRootContents(repo, ref) {
        const [workspace, repoSlug] = repo.split('/');
        const res = await bbFetch(this.accessToken, `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/src/${encodeURIComponent(ref)}/?pagelen=100`);
        const data = (await res.json());
        return data.values.map((entry) => ({
            path: entry.path,
            type: entry.type === 'commit_directory' ? 'tree' : 'blob',
        }));
    }
    getCloneUrl(repo) {
        return `https://bitbucket.org/${repo}.git`;
    }
    async getCloneToken() {
        return this.accessToken;
    }
}
exports.BitbucketProvider = BitbucketProvider;
function hashString(s) {
    let hash = 0;
    for (let i = 0; i < s.length; i++) {
        const char = s.charCodeAt(i);
        hash = (hash << 5) - hash + char;
        hash |= 0;
    }
    return hash;
}
//# sourceMappingURL=bitbucket-api.js.map
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.CACHE_TTL_SECONDS = void 0;
exports.getLatestSafeVersionCacheKey = getLatestSafeVersionCacheKey;
exports.getWatchtowerSummaryCacheKey = getWatchtowerSummaryCacheKey;
exports.getDependencyVersionsCacheKey = getDependencyVersionsCacheKey;
exports.getDependenciesCacheKey = getDependenciesCacheKey;
exports.getPoliciesCacheKey = getPoliciesCacheKey;
exports.getImportStatusCacheKey = getImportStatusCacheKey;
exports.getDependencyNotesCacheKey = getDependencyNotesCacheKey;
exports.getDependencyNotesIndexKey = getDependencyNotesIndexKey;
exports.registerDependencyNotesCacheKey = registerDependencyNotesCacheKey;
exports.invalidateDependencyNotesCache = invalidateDependencyNotesCache;
exports.invalidateDependenciesCache = invalidateDependenciesCache;
exports.invalidatePoliciesCache = invalidatePoliciesCache;
exports.invalidateImportStatusCache = invalidateImportStatusCache;
exports.invalidateProjectCaches = invalidateProjectCaches;
exports.invalidateAllProjectCachesInOrg = invalidateAllProjectCachesInOrg;
exports.invalidateProjectCachesForTeam = invalidateProjectCachesForTeam;
exports.getCached = getCached;
exports.setCached = setCached;
exports.invalidateCache = invalidateCache;
exports.invalidateLatestSafeVersionCache = invalidateLatestSafeVersionCache;
exports.invalidateWatchtowerSummaryCache = invalidateWatchtowerSummaryCache;
exports.invalidateDependencyVersionsCache = invalidateDependencyVersionsCache;
exports.invalidateDependencyVersionsCacheByDependencyId = invalidateDependencyVersionsCacheByDependencyId;
exports.invalidateLatestSafeVersionCacheByDependencyId = invalidateLatestSafeVersionCacheByDependencyId;
const redis_1 = require("@upstash/redis");
// Redis client for caching expensive computations
// Reuses the same Redis instance configuration as other modules
let redisClient = null;
function getRedisClient() {
    if (!redisClient) {
        const url = process.env.UPSTASH_REDIS_URL;
        const token = process.env.UPSTASH_REDIS_TOKEN;
        if (!url || !token) {
            // Cache is optional - if Redis isn't configured, we'll just skip caching
            return null;
        }
        redisClient = new redis_1.Redis({
            url,
            token,
        });
    }
    return redisClient;
}
/**
 * Cache configuration
 */
const CACHE_TTL = {
    LATEST_SAFE_VERSION: 10 * 60, // 10 minutes - safe versions don't change frequently
    WATCHTOWER_SUMMARY: 5 * 60, // 5 minutes - summary can change more frequently
    VERSIONS: 5 * 60, // 5 minutes - dependency versions list (watchtower sidebar)
    DEPENDENCIES: 12 * 60 * 60, // 12 hours - dependencies tab list
    POLICIES: 12 * 60 * 60, // 12 hours - project effective policies
    IMPORT_STATUS: 12 * 60 * 60, // 12 hours - import/AST completion status
    DEPENDENCY_NOTES: 7 * 24 * 60 * 60, // 1 week - invalidated on note/reaction mutations
};
/**
 * Generate cache key for latest safe version
 */
function getLatestSafeVersionCacheKey(organizationId, projectId, projectDependencyId, severity, excludeBanned) {
    return `latest-safe-version:${organizationId}:${projectId}:${projectDependencyId}:${severity}:${excludeBanned}`;
}
/**
 * Generate cache key for watchtower summary
 */
function getWatchtowerSummaryCacheKey(packageName, projectDependencyId) {
    const depId = projectDependencyId || 'none';
    return `watchtower-summary:${packageName}:${depId}`;
}
/**
 * Cache key for dependency versions (watchtower versions sidebar)
 */
function getDependencyVersionsCacheKey(organizationId, projectId, projectDependencyId) {
    return `dependency-versions:${organizationId}:${projectId}:${projectDependencyId}`;
}
/**
 * Dependencies tab cache keys
 */
function getDependenciesCacheKey(organizationId, projectId) {
    return `deps:v1:${organizationId}:${projectId}`;
}
function getPoliciesCacheKey(organizationId, projectId) {
    return `policies:v1:${organizationId}:${projectId}`;
}
function getImportStatusCacheKey(organizationId, projectId) {
    return `import:v1:${organizationId}:${projectId}`;
}
/**
 * Cache key for dependency notes (per user, per project dependency)
 */
function getDependencyNotesCacheKey(organizationId, projectId, projectDependencyId, userId) {
    return `dependency-notes:${organizationId}:${projectId}:${projectDependencyId}:${userId}`;
}
/**
 * Redis SET key used to track all cache keys for a dependency (for invalidation)
 */
function getDependencyNotesIndexKey(organizationId, projectId, projectDependencyId) {
    return `dependency-notes:index:${organizationId}:${projectId}:${projectDependencyId}`;
}
/**
 * Register a dependency notes cache key in the index so we can invalidate all user entries for this dependency.
 */
async function registerDependencyNotesCacheKey(organizationId, projectId, projectDependencyId, cacheKey) {
    const client = getRedisClient();
    if (!client)
        return;
    try {
        const indexKey = getDependencyNotesIndexKey(organizationId, projectId, projectDependencyId);
        await client.sadd(indexKey, cacheKey);
    }
    catch (error) {
        console.warn(`[Cache] Failed to register dependency notes cache key:`, error.message);
    }
}
/**
 * Invalidate all dependency notes cache entries for a project dependency (all users).
 */
async function invalidateDependencyNotesCache(organizationId, projectId, projectDependencyId) {
    const client = getRedisClient();
    if (!client)
        return;
    try {
        const indexKey = getDependencyNotesIndexKey(organizationId, projectId, projectDependencyId);
        const keys = await client.smembers(indexKey);
        if (keys.length > 0) {
            await Promise.all(keys.map((key) => client.del(key)));
        }
        await client.del(indexKey);
    }
    catch (error) {
        console.warn(`[Cache] Failed to invalidate dependency notes cache:`, error.message);
    }
}
/**
 * Invalidate dependencies tab caches for a single project
 */
async function invalidateDependenciesCache(organizationId, projectId) {
    await invalidateCache(getDependenciesCacheKey(organizationId, projectId));
}
async function invalidatePoliciesCache(organizationId, projectId) {
    await invalidateCache(getPoliciesCacheKey(organizationId, projectId));
}
async function invalidateImportStatusCache(organizationId, projectId) {
    await invalidateCache(getImportStatusCacheKey(organizationId, projectId));
}
/**
 * Invalidate all dependencies tab caches (deps, policies, import) for one project
 */
async function invalidateProjectCaches(organizationId, projectId) {
    const client = getRedisClient();
    if (!client)
        return;
    try {
        await Promise.all([
            client.del(getDependenciesCacheKey(organizationId, projectId)),
            client.del(getPoliciesCacheKey(organizationId, projectId)),
            client.del(getImportStatusCacheKey(organizationId, projectId)),
        ]);
    }
    catch (error) {
        console.warn(`[Cache] Failed to invalidate project caches:`, error.message);
    }
}
/**
 * Invalidate dependencies (and optionally policies) caches for all projects in an org.
 * Used when org-level deprecation or policies change.
 */
async function invalidateAllProjectCachesInOrg(organizationId, options) {
    const { supabase } = await Promise.resolve().then(() => __importStar(require('../../../backend/src/lib/supabase')));
    const client = getRedisClient();
    if (!client)
        return;
    try {
        const { data: projects } = await supabase
            .from('projects')
            .select('id')
            .eq('organization_id', organizationId);
        if (!projects || projects.length === 0)
            return;
        const depsOnly = options?.depsOnly ?? false;
        const policiesOnly = options?.policiesOnly ?? false;
        const keys = [];
        for (const p of projects) {
            const projectId = p.id;
            if (depsOnly) {
                keys.push(getDependenciesCacheKey(organizationId, projectId));
            }
            else if (policiesOnly) {
                keys.push(getPoliciesCacheKey(organizationId, projectId));
            }
            else {
                keys.push(getDependenciesCacheKey(organizationId, projectId));
                keys.push(getPoliciesCacheKey(organizationId, projectId));
                keys.push(getImportStatusCacheKey(organizationId, projectId));
            }
        }
        if (keys.length > 0)
            await Promise.all(keys.map((k) => client.del(k)));
    }
    catch (error) {
        console.warn(`[Cache] Failed to invalidate org project caches:`, error.message);
    }
}
/**
 * Invalidate project caches for all projects in a team.
 * Used when team-level deprecation changes.
 */
async function invalidateProjectCachesForTeam(organizationId, teamId) {
    const { supabase } = await Promise.resolve().then(() => __importStar(require('../../../backend/src/lib/supabase')));
    const client = getRedisClient();
    if (!client)
        return;
    try {
        const { data: projectTeams } = await supabase
            .from('project_teams')
            .select('project_id')
            .eq('team_id', teamId);
        if (!projectTeams || projectTeams.length === 0)
            return;
        const projectIds = [...new Set(projectTeams.map((pt) => pt.project_id))];
        const keys = [];
        for (const projectId of projectIds) {
            keys.push(getDependenciesCacheKey(organizationId, projectId));
        }
        if (keys.length > 0)
            await Promise.all(keys.map((k) => client.del(k)));
    }
    catch (error) {
        console.warn(`[Cache] Failed to invalidate team project caches:`, error.message);
    }
}
/**
 * Get cached value
 */
async function getCached(key) {
    const client = getRedisClient();
    if (!client) {
        return null; // Cache disabled, return null to indicate cache miss
    }
    try {
        const cached = await client.get(key);
        if (cached !== null && cached !== undefined) {
            return (typeof cached === 'string' ? JSON.parse(cached) : cached);
        }
        return null;
    }
    catch (error) {
        console.warn(`[Cache] Failed to get cached value for key ${key}:`, error.message);
        return null; // On error, treat as cache miss
    }
}
/**
 * Set cached value with TTL
 */
async function setCached(key, value, ttlSeconds) {
    const client = getRedisClient();
    if (!client) {
        return false; // Cache disabled
    }
    try {
        await client.setex(key, ttlSeconds, JSON.stringify(value));
        return true;
    }
    catch (error) {
        console.warn(`[Cache] Failed to set cached value for key ${key}:`, error.message);
        return false;
    }
}
/**
 * Invalidate cache by key pattern (supports wildcards)
 * Note: Upstash Redis doesn't support KEYS command, so we need to track keys or use specific deletion
 */
async function invalidateCache(key) {
    const client = getRedisClient();
    if (!client) {
        return false;
    }
    try {
        await client.del(key);
        return true;
    }
    catch (error) {
        console.warn(`[Cache] Failed to invalidate cache for key ${key}:`, error.message);
        return false;
    }
}
/**
 * Invalidate all latest safe version caches for a specific project dependency
 * This is called when vulnerabilities, banned versions, or security checks are updated
 */
async function invalidateLatestSafeVersionCache(organizationId, projectId, projectDependencyId) {
    const client = getRedisClient();
    if (!client) {
        return;
    }
    // Invalidate for all severity levels and excludeBanned combinations
    const severities = ['critical', 'high', 'medium', 'low'];
    const excludeBannedOptions = [true, false];
    const keys = severities.flatMap((severity) => excludeBannedOptions.map((excludeBanned) => getLatestSafeVersionCacheKey(organizationId, projectId, projectDependencyId, severity, excludeBanned)));
    try {
        // Delete all keys in parallel
        await Promise.all(keys.map((key) => client.del(key)));
    }
    catch (error) {
        console.warn(`[Cache] Failed to invalidate latest safe version cache:`, error.message);
    }
}
/**
 * Invalidate watchtower summary cache for a package
 */
async function invalidateWatchtowerSummaryCache(packageName, projectDependencyId) {
    const client = getRedisClient();
    if (!client) {
        return;
    }
    try {
        const key = getWatchtowerSummaryCacheKey(packageName, projectDependencyId);
        await client.del(key);
        // Also invalidate the version without projectDependencyId if it exists
        if (projectDependencyId) {
            const globalKey = getWatchtowerSummaryCacheKey(packageName);
            await client.del(globalKey);
        }
    }
    catch (error) {
        console.warn(`[Cache] Failed to invalidate watchtower summary cache:`, error.message);
    }
}
/**
 * Invalidate dependency versions cache for a specific project dependency
 */
async function invalidateDependencyVersionsCache(organizationId, projectId, projectDependencyId) {
    await invalidateCache(getDependencyVersionsCacheKey(organizationId, projectId, projectDependencyId));
}
/**
 * Invalidate dependency versions cache for all project dependencies using a given dependency_id
 * Used when versions are banned or when poller/worker creates new dependency_versions
 */
async function invalidateDependencyVersionsCacheByDependencyId(dependencyId) {
    const { supabase } = await Promise.resolve().then(() => __importStar(require('../../../backend/src/lib/supabase')));
    const client = getRedisClient();
    if (!client) {
        return;
    }
    try {
        const { data: projectDeps } = await supabase
            .from('project_dependencies')
            .select('id, project_id, projects!inner(organization_id)')
            .eq('dependency_id', dependencyId);
        if (!projectDeps || projectDeps.length === 0) {
            return;
        }
        const keys = [];
        for (const pd of projectDeps) {
            const orgId = pd.projects?.organization_id;
            const projectId = pd.project_id;
            const projectDependencyId = pd.id;
            if (orgId && projectId && projectDependencyId) {
                keys.push(getDependencyVersionsCacheKey(orgId, projectId, projectDependencyId));
            }
        }
        if (keys.length > 0) {
            await Promise.all(keys.map((key) => client.del(key)));
        }
    }
    catch (error) {
        console.warn(`[Cache] Failed to invalidate dependency versions cache by dependency_id:`, error.message);
    }
}
/**
 * Invalidate latest safe version cache for all project dependencies using a given dependency_id
 * This is useful when vulnerabilities or security checks are updated for a dependency
 */
async function invalidateLatestSafeVersionCacheByDependencyId(dependencyId) {
    const { supabase } = await Promise.resolve().then(() => __importStar(require('../../../backend/src/lib/supabase')));
    const client = getRedisClient();
    if (!client) {
        return;
    }
    try {
        // Find all project_dependencies that use this dependency_id
        const { data: projectDeps } = await supabase
            .from('project_dependencies')
            .select('id, project_id, projects!inner(organization_id)')
            .eq('dependency_id', dependencyId);
        if (!projectDeps || projectDeps.length === 0) {
            return;
        }
        // Invalidate cache for each project dependency
        const severities = ['critical', 'high', 'medium', 'low'];
        const excludeBannedOptions = [true, false];
        const keys = [];
        for (const pd of projectDeps) {
            const orgId = pd.projects?.organization_id;
            const projectId = pd.project_id;
            const projectDependencyId = pd.id;
            if (orgId && projectId && projectDependencyId) {
                for (const severity of severities) {
                    for (const excludeBanned of excludeBannedOptions) {
                        keys.push(getLatestSafeVersionCacheKey(orgId, projectId, projectDependencyId, severity, excludeBanned));
                    }
                }
            }
        }
        if (keys.length > 0) {
            await Promise.all(keys.map((key) => client.del(key)));
        }
    }
    catch (error) {
        console.warn(`[Cache] Failed to invalidate latest safe version cache by dependency_id:`, error.message);
    }
}
/**
 * Cache TTL constants
 */
exports.CACHE_TTL_SECONDS = CACHE_TTL;
//# sourceMappingURL=cache.js.map
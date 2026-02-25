/**
 * Generate cache key for latest safe version
 */
export declare function getLatestSafeVersionCacheKey(organizationId: string, projectId: string, projectDependencyId: string, severity: string, excludeBanned: boolean): string;
/**
 * Generate cache key for watchtower summary
 */
export declare function getWatchtowerSummaryCacheKey(packageName: string, projectDependencyId?: string): string;
/**
 * Cache key for dependency versions (watchtower versions sidebar)
 */
export declare function getDependencyVersionsCacheKey(organizationId: string, projectId: string, projectDependencyId: string): string;
/**
 * Dependencies tab cache keys
 */
export declare function getDependenciesCacheKey(organizationId: string, projectId: string): string;
export declare function getPoliciesCacheKey(organizationId: string, projectId: string): string;
export declare function getImportStatusCacheKey(organizationId: string, projectId: string): string;
/**
 * Cache key for dependency notes (per user, per project dependency)
 */
export declare function getDependencyNotesCacheKey(organizationId: string, projectId: string, projectDependencyId: string, userId: string): string;
/**
 * Redis SET key used to track all cache keys for a dependency (for invalidation)
 */
export declare function getDependencyNotesIndexKey(organizationId: string, projectId: string, projectDependencyId: string): string;
/**
 * Register a dependency notes cache key in the index so we can invalidate all user entries for this dependency.
 */
export declare function registerDependencyNotesCacheKey(organizationId: string, projectId: string, projectDependencyId: string, cacheKey: string): Promise<void>;
/**
 * Invalidate all dependency notes cache entries for a project dependency (all users).
 */
export declare function invalidateDependencyNotesCache(organizationId: string, projectId: string, projectDependencyId: string): Promise<void>;
/**
 * Invalidate dependencies tab caches for a single project
 */
export declare function invalidateDependenciesCache(organizationId: string, projectId: string): Promise<void>;
export declare function invalidatePoliciesCache(organizationId: string, projectId: string): Promise<void>;
export declare function invalidateImportStatusCache(organizationId: string, projectId: string): Promise<void>;
/**
 * Invalidate all dependencies tab caches (deps, policies, import) for one project
 */
export declare function invalidateProjectCaches(organizationId: string, projectId: string): Promise<void>;
/**
 * Invalidate dependencies (and optionally policies) caches for all projects in an org.
 * Used when org-level deprecation or policies change.
 */
export declare function invalidateAllProjectCachesInOrg(organizationId: string, options?: {
    depsOnly?: boolean;
    policiesOnly?: boolean;
}): Promise<void>;
/**
 * Invalidate project caches for all projects in a team.
 * Used when team-level deprecation changes.
 */
export declare function invalidateProjectCachesForTeam(organizationId: string, teamId: string): Promise<void>;
/**
 * Get cached value
 */
export declare function getCached<T>(key: string): Promise<T | null>;
/**
 * Set cached value with TTL
 */
export declare function setCached<T>(key: string, value: T, ttlSeconds: number): Promise<boolean>;
/**
 * Invalidate cache by key pattern (supports wildcards)
 * Note: Upstash Redis doesn't support KEYS command, so we need to track keys or use specific deletion
 */
export declare function invalidateCache(key: string): Promise<boolean>;
/**
 * Invalidate all latest safe version caches for a specific project dependency
 * This is called when vulnerabilities, banned versions, or security checks are updated
 */
export declare function invalidateLatestSafeVersionCache(organizationId: string, projectId: string, projectDependencyId: string): Promise<void>;
/**
 * Invalidate watchtower summary cache for a package
 */
export declare function invalidateWatchtowerSummaryCache(packageName: string, projectDependencyId?: string): Promise<void>;
/**
 * Invalidate dependency versions cache for a specific project dependency
 */
export declare function invalidateDependencyVersionsCache(organizationId: string, projectId: string, projectDependencyId: string): Promise<void>;
/**
 * Invalidate dependency versions cache for all project dependencies using a given dependency_id
 * Used when versions are banned or when poller/worker creates new dependency_versions
 */
export declare function invalidateDependencyVersionsCacheByDependencyId(dependencyId: string): Promise<void>;
/**
 * Invalidate latest safe version cache for all project dependencies using a given dependency_id
 * This is useful when vulnerabilities or security checks are updated for a dependency
 */
export declare function invalidateLatestSafeVersionCacheByDependencyId(dependencyId: string): Promise<void>;
/**
 * Cache TTL constants
 */
export declare const CACHE_TTL_SECONDS: {
    LATEST_SAFE_VERSION: number;
    WATCHTOWER_SUMMARY: number;
    VERSIONS: number;
    DEPENDENCIES: number;
    POLICIES: number;
    IMPORT_STATUS: number;
    DEPENDENCY_NOTES: number;
};
//# sourceMappingURL=cache.d.ts.map
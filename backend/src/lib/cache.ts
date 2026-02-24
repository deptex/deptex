import { Redis } from '@upstash/redis';

// Redis client for caching expensive computations
// Reuses the same Redis instance configuration as other modules

let redisClient: Redis | null = null;

function getRedisClient(): Redis | null {
  if (!redisClient) {
    const url = process.env.UPSTASH_REDIS_URL;
    const token = process.env.UPSTASH_REDIS_TOKEN;

    if (!url || !token) {
      // Cache is optional - if Redis isn't configured, we'll just skip caching
      return null;
    }

    redisClient = new Redis({
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
  WATCHTOWER_SUMMARY: 5 * 60,   // 5 minutes - summary can change more frequently
  VERSIONS: 5 * 60,             // 5 minutes - dependency versions list (watchtower sidebar)
  DEPENDENCIES: 12 * 60 * 60,   // 12 hours - dependencies tab list
  POLICIES: 12 * 60 * 60,       // 12 hours - project effective policies
  IMPORT_STATUS: 12 * 60 * 60,  // 12 hours - import/AST completion status
  DEPENDENCY_NOTES: 7 * 24 * 60 * 60, // 1 week - invalidated on note/reaction mutations
};

/**
 * Generate cache key for latest safe version
 */
export function getLatestSafeVersionCacheKey(
  organizationId: string,
  projectId: string,
  projectDependencyId: string,
  severity: string,
  excludeBanned: boolean
): string {
  return `latest-safe-version:${organizationId}:${projectId}:${projectDependencyId}:${severity}:${excludeBanned}`;
}

/**
 * Generate cache key for watchtower summary
 */
export function getWatchtowerSummaryCacheKey(
  packageName: string,
  projectDependencyId?: string
): string {
  const depId = projectDependencyId || 'none';
  return `watchtower-summary:${packageName}:${depId}`;
}

/**
 * Cache key for dependency versions (watchtower versions sidebar)
 */
export function getDependencyVersionsCacheKey(
  organizationId: string,
  projectId: string,
  projectDependencyId: string
): string {
  return `dependency-versions:${organizationId}:${projectId}:${projectDependencyId}`;
}

/**
 * Dependencies tab cache keys
 */
export function getDependenciesCacheKey(organizationId: string, projectId: string): string {
  return `deps:v1:${organizationId}:${projectId}`;
}
export function getPoliciesCacheKey(organizationId: string, projectId: string): string {
  return `policies:v1:${organizationId}:${projectId}`;
}
export function getImportStatusCacheKey(organizationId: string, projectId: string): string {
  return `import:v1:${organizationId}:${projectId}`;
}

/**
 * Cache key for dependency notes (per user, per project dependency)
 */
export function getDependencyNotesCacheKey(
  organizationId: string,
  projectId: string,
  projectDependencyId: string,
  userId: string
): string {
  return `dependency-notes:${organizationId}:${projectId}:${projectDependencyId}:${userId}`;
}

/**
 * Redis SET key used to track all cache keys for a dependency (for invalidation)
 */
export function getDependencyNotesIndexKey(
  organizationId: string,
  projectId: string,
  projectDependencyId: string
): string {
  return `dependency-notes:index:${organizationId}:${projectId}:${projectDependencyId}`;
}

/**
 * Register a dependency notes cache key in the index so we can invalidate all user entries for this dependency.
 */
export async function registerDependencyNotesCacheKey(
  organizationId: string,
  projectId: string,
  projectDependencyId: string,
  cacheKey: string
): Promise<void> {
  const client = getRedisClient();
  if (!client) return;
  try {
    const indexKey = getDependencyNotesIndexKey(organizationId, projectId, projectDependencyId);
    await client.sadd(indexKey, cacheKey);
  } catch (error: any) {
    console.warn(`[Cache] Failed to register dependency notes cache key:`, error.message);
  }
}

/**
 * Invalidate all dependency notes cache entries for a project dependency (all users).
 */
export async function invalidateDependencyNotesCache(
  organizationId: string,
  projectId: string,
  projectDependencyId: string
): Promise<void> {
  const client = getRedisClient();
  if (!client) return;
  try {
    const indexKey = getDependencyNotesIndexKey(organizationId, projectId, projectDependencyId);
    const keys = await client.smembers(indexKey);
    if (keys.length > 0) {
      await Promise.all(keys.map((key) => client.del(key)));
    }
    await client.del(indexKey);
  } catch (error: any) {
    console.warn(`[Cache] Failed to invalidate dependency notes cache:`, error.message);
  }
}

/**
 * Invalidate dependencies tab caches for a single project
 */
export async function invalidateDependenciesCache(organizationId: string, projectId: string): Promise<void> {
  await invalidateCache(getDependenciesCacheKey(organizationId, projectId));
}
export async function invalidatePoliciesCache(organizationId: string, projectId: string): Promise<void> {
  await invalidateCache(getPoliciesCacheKey(organizationId, projectId));
}
export async function invalidateImportStatusCache(organizationId: string, projectId: string): Promise<void> {
  await invalidateCache(getImportStatusCacheKey(organizationId, projectId));
}

/**
 * Invalidate all dependencies tab caches (deps, policies, import) for one project
 */
export async function invalidateProjectCaches(organizationId: string, projectId: string): Promise<void> {
  const client = getRedisClient();
  if (!client) return;
  try {
    await Promise.all([
      client.del(getDependenciesCacheKey(organizationId, projectId)),
      client.del(getPoliciesCacheKey(organizationId, projectId)),
      client.del(getImportStatusCacheKey(organizationId, projectId)),
    ]);
  } catch (error: any) {
    console.warn(`[Cache] Failed to invalidate project caches:`, error.message);
  }
}

/**
 * Invalidate dependencies (and optionally policies) caches for all projects in an org.
 * Used when org-level deprecation or policies change.
 */
export async function invalidateAllProjectCachesInOrg(
  organizationId: string,
  options?: { depsOnly?: boolean; policiesOnly?: boolean }
): Promise<void> {
  const { supabase } = await import('./supabase');
  const client = getRedisClient();
  if (!client) return;
  try {
    const { data: projects } = await supabase
      .from('projects')
      .select('id')
      .eq('organization_id', organizationId);
    if (!projects || projects.length === 0) return;
    const depsOnly = options?.depsOnly ?? false;
    const policiesOnly = options?.policiesOnly ?? false;
    const keys: string[] = [];
    for (const p of projects) {
      const projectId = (p as any).id;
      if (depsOnly) {
        keys.push(getDependenciesCacheKey(organizationId, projectId));
      } else if (policiesOnly) {
        keys.push(getPoliciesCacheKey(organizationId, projectId));
      } else {
        keys.push(getDependenciesCacheKey(organizationId, projectId));
        keys.push(getPoliciesCacheKey(organizationId, projectId));
        keys.push(getImportStatusCacheKey(organizationId, projectId));
      }
    }
    if (keys.length > 0) await Promise.all(keys.map((k) => client.del(k)));
  } catch (error: any) {
    console.warn(`[Cache] Failed to invalidate org project caches:`, error.message);
  }
}

/**
 * Invalidate project caches for all projects in a team.
 * Used when team-level deprecation changes.
 */
export async function invalidateProjectCachesForTeam(organizationId: string, teamId: string): Promise<void> {
  const { supabase } = await import('./supabase');
  const client = getRedisClient();
  if (!client) return;
  try {
    const { data: projectTeams } = await supabase
      .from('project_teams')
      .select('project_id')
      .eq('team_id', teamId);
    if (!projectTeams || projectTeams.length === 0) return;
    const projectIds = [...new Set(projectTeams.map((pt: any) => pt.project_id))];
    const keys: string[] = [];
    for (const projectId of projectIds) {
      keys.push(getDependenciesCacheKey(organizationId, projectId));
    }
    if (keys.length > 0) await Promise.all(keys.map((k) => client.del(k)));
  } catch (error: any) {
    console.warn(`[Cache] Failed to invalidate team project caches:`, error.message);
  }
}

/**
 * Get cached value
 */
export async function getCached<T>(key: string): Promise<T | null> {
  const client = getRedisClient();
  if (!client) {
    return null; // Cache disabled, return null to indicate cache miss
  }

  try {
    const cached = await client.get(key);
    if (cached !== null && cached !== undefined) {
      return (typeof cached === 'string' ? JSON.parse(cached) : cached) as T;
    }
    return null;
  } catch (error: any) {
    console.warn(`[Cache] Failed to get cached value for key ${key}:`, error.message);
    return null; // On error, treat as cache miss
  }
}

/**
 * Set cached value with TTL
 */
export async function setCached<T>(
  key: string,
  value: T,
  ttlSeconds: number
): Promise<boolean> {
  const client = getRedisClient();
  if (!client) {
    return false; // Cache disabled
  }

  try {
    await client.setex(key, ttlSeconds, JSON.stringify(value));
    return true;
  } catch (error: any) {
    console.warn(`[Cache] Failed to set cached value for key ${key}:`, error.message);
    return false;
  }
}

/**
 * Invalidate cache by key pattern (supports wildcards)
 * Note: Upstash Redis doesn't support KEYS command, so we need to track keys or use specific deletion
 */
export async function invalidateCache(key: string): Promise<boolean> {
  const client = getRedisClient();
  if (!client) {
    return false;
  }

  try {
    await client.del(key);
    return true;
  } catch (error: any) {
    console.warn(`[Cache] Failed to invalidate cache for key ${key}:`, error.message);
    return false;
  }
}

/**
 * Invalidate all latest safe version caches for a specific project dependency
 * This is called when vulnerabilities, banned versions, or security checks are updated
 */
export async function invalidateLatestSafeVersionCache(
  organizationId: string,
  projectId: string,
  projectDependencyId: string
): Promise<void> {
  const client = getRedisClient();
  if (!client) {
    return;
  }

  // Invalidate for all severity levels and excludeBanned combinations
  const severities = ['critical', 'high', 'medium', 'low'];
  const excludeBannedOptions = [true, false];

  const keys = severities.flatMap((severity) =>
    excludeBannedOptions.map((excludeBanned) =>
      getLatestSafeVersionCacheKey(organizationId, projectId, projectDependencyId, severity, excludeBanned)
    )
  );

  try {
    // Delete all keys in parallel
    await Promise.all(keys.map((key) => client.del(key)));
  } catch (error: any) {
    console.warn(`[Cache] Failed to invalidate latest safe version cache:`, error.message);
  }
}

/**
 * Invalidate watchtower summary cache for a package
 */
export async function invalidateWatchtowerSummaryCache(
  packageName: string,
  projectDependencyId?: string
): Promise<void> {
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
  } catch (error: any) {
    console.warn(`[Cache] Failed to invalidate watchtower summary cache:`, error.message);
  }
}

/**
 * Invalidate dependency versions cache for a specific project dependency
 */
export async function invalidateDependencyVersionsCache(
  organizationId: string,
  projectId: string,
  projectDependencyId: string
): Promise<void> {
  await invalidateCache(getDependencyVersionsCacheKey(organizationId, projectId, projectDependencyId));
}

/**
 * Invalidate dependency versions cache for all project dependencies using a given dependency_id
 * Used when versions are banned or when poller/worker creates new dependency_versions
 */
export async function invalidateDependencyVersionsCacheByDependencyId(
  dependencyId: string
): Promise<void> {
  const { supabase } = await import('./supabase');
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

    const keys: string[] = [];
    for (const pd of projectDeps) {
      const orgId = (pd.projects as any)?.organization_id;
      const projectId = pd.project_id;
      const projectDependencyId = pd.id;
      if (orgId && projectId && projectDependencyId) {
        keys.push(getDependencyVersionsCacheKey(orgId, projectId, projectDependencyId));
      }
    }

    if (keys.length > 0) {
      await Promise.all(keys.map((key) => client.del(key)));
    }
  } catch (error: any) {
    console.warn(`[Cache] Failed to invalidate dependency versions cache by dependency_id:`, error.message);
  }
}

/**
 * Invalidate latest safe version cache for all project dependencies using a given dependency_id
 * This is useful when vulnerabilities or security checks are updated for a dependency
 */
export async function invalidateLatestSafeVersionCacheByDependencyId(
  dependencyId: string
): Promise<void> {
  const { supabase } = await import('./supabase');
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

    const keys: string[] = [];
    for (const pd of projectDeps) {
      const orgId = (pd.projects as any)?.organization_id;
      const projectId = pd.project_id;
      const projectDependencyId = pd.id;

      if (orgId && projectId && projectDependencyId) {
        for (const severity of severities) {
          for (const excludeBanned of excludeBannedOptions) {
            keys.push(
              getLatestSafeVersionCacheKey(orgId, projectId, projectDependencyId, severity, excludeBanned)
            );
          }
        }
      }
    }

    if (keys.length > 0) {
      await Promise.all(keys.map((key) => client.del(key)));
    }
  } catch (error: any) {
    console.warn(`[Cache] Failed to invalidate latest safe version cache by dependency_id:`, error.message);
  }
}

/**
 * Cache TTL constants
 */
export const CACHE_TTL_SECONDS = CACHE_TTL;

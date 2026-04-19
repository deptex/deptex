/**
 * No-op cache invalidation for the watchtower worker.
 * The worker runs in isolation (e.g. Fly.io) and has no access to the main backend's Redis.
 * Cache invalidation is handled by the backend when it processes watchtower events or job completion.
 */

export async function invalidateLatestSafeVersionCacheByDependencyId(_dependencyId: string): Promise<void> {
  // no-op in worker
}

export async function invalidateWatchtowerSummaryCache(_name: string, _depId?: string): Promise<void> {
  // no-op in worker
}

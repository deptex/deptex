import type { OverviewBundle } from './api';

// In-memory-only cache for the organization overview bundle.
//
// CURRENTLY DISABLED (CACHE_ENABLED = false): the overview fetches the bundle
// fresh and shows its normal loading skeleton on every open. The bundle endpoint
// already collapses the old 4 mount round-trips into 1, so a single quick load is
// fast enough — and a brief skeleton reads as "fresh data just loaded" rather than
// an instant paint that can feel oddly abrupt / possibly-stale.
//
// Flip CACHE_ENABLED to true to re-enable an in-session (in-memory) cache: in-app
// navigation back to the overview repaints instantly from the last bundle, while
// every mount still revalidates in the background. It is in-memory only — nothing
// is ever written to disk, so a reload / new tab always starts cold.

const CACHE_ENABLED: boolean = false;

export interface CachedOverview {
  data: OverviewBundle;
  ts: number;
}

const MEM = new Map<string, CachedOverview>();

// One-time cleanup: an earlier build persisted the overview bundle to localStorage.
// Purge any leftover on-disk entries so nothing lingers between sessions, whether
// or not the in-memory cache is enabled.
try {
  for (let i = localStorage.length - 1; i >= 0; i--) {
    const k = localStorage.key(i);
    if (k && k.startsWith('deptex:overview:v1:')) localStorage.removeItem(k);
  }
} catch {
  /* localStorage unavailable (private mode) — nothing to purge. */
}

export function readOverviewCache(orgId: string): CachedOverview | null {
  if (!CACHE_ENABLED) return null;
  return MEM.get(orgId) ?? null;
}

export function writeOverviewCache(orgId: string, data: OverviewBundle): void {
  if (!CACHE_ENABLED) return;
  MEM.set(orgId, { data, ts: Date.now() });
}

// Clear one org's cache, or (no arg) every one — called on sign-out so a different
// user in the same tab never reuses the previous user's view.
export function clearOverviewCache(orgId?: string): void {
  if (orgId) MEM.delete(orgId);
  else MEM.clear();
}

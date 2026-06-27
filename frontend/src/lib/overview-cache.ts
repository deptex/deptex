import type { OverviewBundle } from './api';

// In-memory-only cache for the organization overview bundle.
//
// The overview is the app's front door, so bouncing around the app and back to it
// should repaint instantly instead of sitting behind a spinner. This cache lives
// for the current page session (the JS module), so in-app navigation reuses it —
// but NOTHING is written to disk, so there's no stored copy lingering between
// sessions. A full reload or a new tab starts cold and fetches fresh.
//
// Every overview mount still revalidates in the background, so the cached paint is
// only ever a head start, never the source of truth.

export interface CachedOverview {
  data: OverviewBundle;
  ts: number;
}

const MEM = new Map<string, CachedOverview>();

// One-time cleanup: an earlier build persisted the overview bundle to localStorage.
// Now that the cache is in-memory only, purge any leftover on-disk entries so
// nothing lingers between sessions.
try {
  for (let i = localStorage.length - 1; i >= 0; i--) {
    const k = localStorage.key(i);
    if (k && k.startsWith('deptex:overview:v1:')) localStorage.removeItem(k);
  }
} catch {
  /* localStorage unavailable (private mode) — nothing to purge. */
}

export function readOverviewCache(orgId: string): CachedOverview | null {
  return MEM.get(orgId) ?? null;
}

export function writeOverviewCache(orgId: string, data: OverviewBundle): void {
  MEM.set(orgId, { data, ts: Date.now() });
}

// Clear one org's cache, or (no arg) every one — call on sign-out so a different
// user in the same tab never reuses the previous user's view.
export function clearOverviewCache(orgId?: string): void {
  if (orgId) MEM.delete(orgId);
  else MEM.clear();
}

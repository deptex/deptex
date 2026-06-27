import type { OverviewBundle } from './api';

// Stale-while-revalidate cache for the organization overview bundle.
//
// The overview is the app's front door; its felt speed sets the baseline for
// everything. On a repeat visit we paint the last-known bundle from this cache
// INSTANTLY (zero network), then revalidate in the background and reconcile.
// First visit of a session (cold cache) still hits the network once.
//
// Keyed by org id. localStorage is inherently per-browser-profile (≈ per-user),
// and every mount revalidates, so a stale paint is corrected within one
// round-trip. Bump the `v1` namespace if the bundle shape changes.

export interface CachedOverview {
  data: OverviewBundle;
  ts: number;
}

const MEM = new Map<string, CachedOverview>();
const STORAGE_PREFIX = 'deptex:overview:v1:';
const storageKey = (orgId: string) => `${STORAGE_PREFIX}${orgId}`;

export function readOverviewCache(orgId: string): CachedOverview | null {
  const mem = MEM.get(orgId);
  if (mem) return mem;
  try {
    const raw = localStorage.getItem(storageKey(orgId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as CachedOverview;
    if (!parsed?.data) return null;
    MEM.set(orgId, parsed);
    return parsed;
  } catch {
    // Corrupt entry or localStorage unavailable (private mode) — treat as miss.
    return null;
  }
}

export function writeOverviewCache(orgId: string, data: OverviewBundle): void {
  const entry: CachedOverview = { data, ts: Date.now() };
  MEM.set(orgId, entry);
  try {
    localStorage.setItem(storageKey(orgId), JSON.stringify(entry));
  } catch {
    // localStorage full / blocked — the in-memory cache still serves this session.
  }
}

// Clear one org's cache, or (no arg) every overview cache — call on sign-out so a
// different user in the same browser never paints the previous user's view.
export function clearOverviewCache(orgId?: string): void {
  if (orgId) {
    MEM.delete(orgId);
    try {
      localStorage.removeItem(storageKey(orgId));
    } catch {
      /* ignore */
    }
    return;
  }
  MEM.clear();
  try {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (k && k.startsWith(STORAGE_PREFIX)) localStorage.removeItem(k);
    }
  } catch {
    /* ignore */
  }
}

import type { CSSProperties } from 'react';
import type { OrganizationStatus } from './api';

/** Minimal project shape for rollup (org overview). */
export interface OverviewRollupProjectLike {
  statusId?: string | null;
  /** Project status name (used when statusId is missing). */
  statusName?: string | null;
  /** Optional project status color (not trusted as source of truth; we prefer org status color). */
  statusColor?: string | null;
}

const UNKNOWN_KEY = '__none__';

export interface OverviewStatusRollup {
  /** Badge text: worst status name or "No status". */
  badgeLabel: string;
  /** Hex color for worst badge, or null for muted styling. */
  badgeColor: string | null;
  /** Single-line tooltip: "3 Compliant, 1 Non-Compliant, 1 No status". */
  tooltipText: string;
}

function buildMetaById(statuses: OrganizationStatus[]): Map<string, { rank: number; name: string; color: string | null }> {
  const m = new Map<string, { rank: number; name: string; color: string | null }>();
  for (const s of statuses) {
    m.set(s.id, { rank: s.rank, name: s.name, color: s.color });
  }
  return m;
}

/**
 * Roll up project statuses: worst badge = max rank among known status_ids (higher rank = worse per DB).
 * Unknown/missing status_id is counted as "No status" in the tooltip only; it does not win the badge
 * unless no project has a known org status.
 */
export function computeOverviewStatusRollup(
  projects: OverviewRollupProjectLike[],
  statuses: OrganizationStatus[]
): OverviewStatusRollup {
  const metaById = buildMetaById(statuses);
  const metaByName = new Map<string, { rank: number; name: string; color: string | null; id: string }>();
  for (const s of statuses) {
    metaByName.set(s.name.trim().toLowerCase(), { rank: s.rank, name: s.name, color: s.color, id: s.id });
  }

  type Agg = { count: number; label: string; color: string | null; rank: number };
  const buckets = new Map<string, Agg>();

  const bump = (key: string, label: string, color: string | null, rank: number) => {
    const cur = buckets.get(key);
    if (cur) {
      cur.count += 1;
    } else {
      buckets.set(key, { count: 1, label, color, rank });
    }
  };

  for (const p of projects) {
    const sid = p.statusId;
    if (sid && metaById.has(sid)) {
      const m = metaById.get(sid)!;
      bump(sid, m.name, m.color, m.rank);
      continue;
    }

    const sname = p.statusName?.trim();
    if (sname) {
      const mByName = metaByName.get(sname.toLowerCase());
      if (mByName) {
        bump(mByName.id, mByName.name, mByName.color, mByName.rank);
        continue;
      }
    } else {
      // fall through to unknown
    }

    bump(UNKNOWN_KEY, 'No status', null, Number.NEGATIVE_INFINITY);
  }

  const bucketEntries = Array.from(buckets.entries()).filter(([key]) => key !== UNKNOWN_KEY);
  let badgeLabel = 'No status';
  let badgeColor: string | null = null;

  if (bucketEntries.length > 0) {
    let worstRank = Number.NEGATIVE_INFINITY;
    for (const [, v] of bucketEntries) worstRank = Math.max(worstRank, v.rank);

    const candidates = bucketEntries.filter(([, v]) => v.rank === worstRank);
    candidates.sort((a, b) => {
      const ac = a[1].count;
      const bc = b[1].count;
      if (bc !== ac) return bc - ac; // more projects wins ties
      return a[1].label.localeCompare(b[1].label); // stable fallback
    });

    badgeLabel = candidates[0][1].label;
    badgeColor = candidates[0][1].color;
  }

  const breakdownRows = Array.from(buckets.values()).sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    if (b.rank !== a.rank) return b.rank - a.rank;
    return a.label.localeCompare(b.label);
  });

  const tooltipText = breakdownRows.map((row) => `${row.count} ${row.label}`).join(', ');

  return {
    badgeLabel,
    badgeColor,
    tooltipText: tooltipText || 'No projects',
  };
}

/** Normalize hex from API (may omit `#`). */
export function normalizeStatusHex(color: string | null | undefined): string | null {
  const raw = color?.trim();
  if (!raw) return null;
  return raw.startsWith('#') ? raw : `#${raw}`;
}

function statusBadgeColorFallback(label: string | null | undefined): string | null {
  if (!label || typeof label !== 'string') return null;
  const lower = label.toLowerCase();
  if (lower.includes('compliant') && !lower.includes('non') && !lower.includes('not')) return '#22c55e';
  if (lower.includes('non-compliant') || lower.includes('not compliant') || lower.includes('non compliant')) return '#ef4444';
  if (lower.includes('under review') || lower.includes('review')) return '#f59e0b';
  if (lower.includes('failed') || lower.includes('error')) return '#ef4444';
  return null;
}

/** Resolved hex for rollup badge (matches VulnProjectNode status styling). */
export function overviewStatusBadgeEffectiveColor(label: string, color: string | null): string | null {
  return normalizeStatusHex(color) ?? statusBadgeColorFallback(label);
}

export function overviewStatusBadgeInlineStyle(label: string, color: string | null): CSSProperties {
  const hex = overviewStatusBadgeEffectiveColor(label, color);
  if (hex) {
    return {
      backgroundColor: `${hex}20`,
      color: hex,
      borderColor: `${hex}40`,
    };
  }
  return {
    backgroundColor: 'transparent',
    color: 'var(--muted-foreground)',
    borderColor: 'rgba(255,255,255,0.2)',
  };
}

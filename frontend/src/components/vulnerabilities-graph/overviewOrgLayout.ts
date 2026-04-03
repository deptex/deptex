/**
 * Layout slot + collision box for the org hub center card (larger than default vuln graph center).
 * Keeps satellite placement from overlapping the beefier org node.
 */
export const ORG_OVERVIEW_CENTER_WIDTH = 328;
/** Approx. rendered height of the org center card (avatar + title block only). */
export const ORG_OVERVIEW_CENTER_HEIGHT = 104;

const ORG_HALF_W = ORG_OVERVIEW_CENTER_WIDTH / 2;
const ORG_HALF_H = ORG_OVERVIEW_CENTER_HEIGHT / 2;

/** Which side of a satellite node receives the edge from the org (for handle centering). */
export type OrgSatelliteTargetEdge = 'top' | 'right' | 'bottom' | 'left';

export interface OverviewLayoutCell {
  globalIndex: number;
  width: number;
  height: number;
}

interface PlacedBox {
  globalIndex: number;
  x: number;
  y: number;
  w: number;
  h: number;
}

function aabbOverlap(a: PlacedBox, b: PlacedBox, margin: number): boolean {
  return !(
    a.x + a.w + margin <= b.x ||
    b.x + b.w + margin <= a.x ||
    a.y + a.h + margin <= b.y ||
    b.y + b.h + margin <= a.y
  );
}

function overlapsOrg(box: PlacedBox, margin: number): boolean {
  const orgBox: PlacedBox = {
    globalIndex: -1,
    x: -ORG_HALF_W,
    y: -ORG_HALF_H,
    w: ORG_OVERVIEW_CENTER_WIDTH,
    h: ORG_OVERVIEW_CENTER_HEIGHT,
  };
  return aabbOverlap(box, orgBox, margin);
}

/**
 * When |horizontal offset| is within this multiple of |vertical offset|, prefer top/bottom (and vice
 * versa for left/right). Stops “mostly below” teams — wide cards / ring layout can leave centers
 * skewed right so atan2 alone picks org-right→team-left and the Bézier wraps awkwardly.
 */
const ORG_LINK_AXIS_BIAS = 2;

/**
 * Map vector from org center (0,0) to satellite center → closest cardinal on org (exit) and on
 * satellite (entry). RF: +x right, +y down.
 */
export function getOrgToSatelliteHandles(dx: number, dy: number): {
  sourceHandle: string;
  targetHandle: string;
  targetEdge: OrgSatelliteTargetEdge;
} {
  if (dx === 0 && dy === 0) {
    return { sourceHandle: 'right', targetHandle: 'left', targetEdge: 'left' };
  }

  const B = ORG_LINK_AXIS_BIAS;
  if (dy > 0 && Math.abs(dx) <= B * dy) {
    return { sourceHandle: 'bottom', targetHandle: 'top', targetEdge: 'top' };
  }
  if (dy < 0 && Math.abs(dx) <= B * Math.abs(dy)) {
    return { sourceHandle: 'top', targetHandle: 'bottom', targetEdge: 'bottom' };
  }
  if (dx > 0 && Math.abs(dy) <= B * dx) {
    return { sourceHandle: 'right', targetHandle: 'left', targetEdge: 'left' };
  }
  if (dx < 0 && Math.abs(dy) <= B * Math.abs(dx)) {
    return { sourceHandle: 'left', targetHandle: 'right', targetEdge: 'right' };
  }

  const a = Math.atan2(dy, dx);
  if (a >= -Math.PI / 4 && a < Math.PI / 4) {
    return { sourceHandle: 'right', targetHandle: 'left', targetEdge: 'left' };
  }
  if (a >= Math.PI / 4 && a < (3 * Math.PI) / 4) {
    return { sourceHandle: 'bottom', targetHandle: 'top', targetEdge: 'top' };
  }
  if (a >= (3 * Math.PI) / 4 || a < (-3 * Math.PI) / 4) {
    return { sourceHandle: 'left', targetHandle: 'right', targetEdge: 'right' };
  }
  return { sourceHandle: 'top', targetHandle: 'bottom', targetEdge: 'bottom' };
}

/**
 * Place team / ungrouped project boxes around the org using directional rings + separation.
 * Larger boxes are placed first. Uses 8–14 angular buckets depending on count.
 */
export function layoutOverviewSatellitesAroundOrg(cells: OverviewLayoutCell[]): Map<number, { x: number; y: number }> {
  const positions = new Map<number, { x: number; y: number }>();
  if (cells.length === 0) return positions;

  const MIN_GAP = 36;
  const sorted = [...cells].sort((a, b) => Math.max(b.width, b.height) - Math.max(a.width, a.height));

  const K = Math.max(8, Math.min(14, Math.ceil(Math.sqrt(cells.length) * 2.8)));
  const placed: PlacedBox[] = [];

  for (const cell of sorted) {
    const { globalIndex, width: w, height: h } = cell;
    let chosen: PlacedBox | null = null;

    outer: for (let ring = 0; ring < 48; ring++) {
      const dist =
        210 +
        ring * 125 +
        Math.max(w, h) * 0.22 +
        ring * Math.max(0, Math.max(w, h) - 260) * 0.05;

      for (let dir = 0; dir < K; dir++) {
        const angle = (2 * Math.PI * dir) / K + Math.PI / (2 * K);
        const cx = Math.cos(angle) * dist;
        const cy = Math.sin(angle) * dist;
        const x = cx - w / 2;
        const y = cy - h / 2;
        const candidate: PlacedBox = { globalIndex, x, y, w, h };

        if (overlapsOrg(candidate, MIN_GAP)) continue;

        let ok = true;
        for (const p of placed) {
          if (aabbOverlap(candidate, p, MIN_GAP)) {
            ok = false;
            break;
          }
        }
        if (ok) {
          chosen = candidate;
          break outer;
        }
      }
    }

    if (!chosen) {
      const idx = placed.length;
      const angle = idx * 2.51327412;
      const dist = 420 + idx * 100 + Math.max(w, h) * 0.3;
      const cx = Math.cos(angle) * dist;
      const cy = Math.sin(angle) * dist;
      chosen = { globalIndex, x: cx - w / 2, y: cy - h / 2, w, h };
    }

    placed.push(chosen);
  }

  for (let iter = 0; iter < 16; iter++) {
    let moved = false;
    for (let i = 0; i < placed.length; i++) {
      for (let j = i + 1; j < placed.length; j++) {
        const a = placed[i];
        const b = placed[j];
        if (!aabbOverlap(a, b, MIN_GAP)) continue;

        const acx = a.x + a.w / 2;
        const acy = a.y + a.h / 2;
        const bcx = b.x + b.w / 2;
        const bcy = b.y + b.h / 2;
        let dx = acx - bcx;
        let dy = acy - bcy;
        const len = Math.hypot(dx, dy) || 1;
        dx /= len;
        dy /= len;
        const push = 10;
        a.x += dx * push;
        a.y += dy * push;
        b.x -= dx * push;
        b.y -= dy * push;
        moved = true;
      }
    }
    if (!moved) break;
  }

  for (const p of placed) {
    positions.set(p.globalIndex, { x: p.x, y: p.y });
  }

  return positions;
}

/** How many attachment points we place along each org card edge (for handle ids; overview uses center slot only). */
export const ORG_OVERVIEW_EDGE_SLOTS = 28;

/** Match Tailwind `border-border` on GroupCenterNode org card (`theme.extend.colors.border` in tailwind.config.js). */
export const ORG_OVERVIEW_EDGE_STROKE = '#262626';

export interface OrgOverviewEdgeRouting {
  sourceHandle: string;
  targetHandle: string;
  /** Passed to Bézier (`default`) edges — slight spread avoids perfectly stacked control handles. */
  pathOptions: { curvature: number };
}

/**
 * Assigns distinct source/target handle ids along the org and satellite faces, plus a Bézier
 * curvature per link. Hub-and-spoke looks cleaner than orthogonal smoothstep for this layout.
 */
export function computeOrgOverviewEdgeRouting(
  items: Array<{ targetId: string; cx: number; cy: number }>
): Map<string, OrgOverviewEdgeRouting> {
  type Side = OrgSatelliteTargetEdge;
  type Ann = { targetId: string; cx: number; cy: number; orgSide: Side; targetSide: Side; sortKey: number };

  const annotated: Ann[] = items.map(({ targetId, cx, cy }) => {
    const { sourceHandle, targetEdge } = getOrgToSatelliteHandles(cx, cy);
    const orgSide = sourceHandle as Side;
    const sortKey = orgSide === 'bottom' || orgSide === 'top' ? cx : cy;
    return { targetId, cx, cy, orgSide, targetSide: targetEdge, sortKey };
  });

  const bySide = new Map<Side, Ann[]>();
  for (const a of annotated) {
    const arr = bySide.get(a.orgSide) ?? [];
    arr.push(a);
    bySide.set(a.orgSide, arr);
  }

  const out = new Map<string, OrgOverviewEdgeRouting>();
  /** Center of each side on org and on team/project (width- or height-mid for that edge). */
  const edgeCenterSlot = Math.floor((ORG_OVERVIEW_EDGE_SLOTS - 1) / 2);

  for (const [, group] of bySide) {
    group.sort((a, b) => a.sortKey - b.sortKey);
    const n = group.length;
    group.forEach((item, idx) => {
      const t = n <= 1 ? 0.5 : idx / (n - 1);
      const curvature = 0.2 + t * 0.12;

      out.set(item.targetId, {
        sourceHandle: `ov-src-${item.orgSide}-${edgeCenterSlot}`,
        targetHandle: `ov-tgt-${item.targetSide}-${edgeCenterSlot}`,
        pathOptions: { curvature },
      });
    });
  }

  return out;
}

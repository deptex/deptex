import {
  getOrgToSatelliteHandles,
  layoutOverviewSatellitesAroundOrg,
  ORG_OVERVIEW_CENTER_WIDTH,
  ORG_OVERVIEW_CENTER_HEIGHT,
  type OverviewLayoutCell,
} from '../components/vulnerabilities-graph/overviewOrgLayout';

const ORG_HALF_W = ORG_OVERVIEW_CENTER_WIDTH / 2;
const ORG_HALF_H = ORG_OVERVIEW_CENTER_HEIGHT / 2;

// ── getOrgToSatelliteHandles ────────────────────────────────────────────────

describe('getOrgToSatelliteHandles', () => {
  it('returns right/left when dx=0 dy=0', () => {
    const r = getOrgToSatelliteHandles(0, 0);
    expect(r.sourceHandle).toBe('right');
    expect(r.targetHandle).toBe('left');
    expect(r.targetEdge).toBe('left');
  });

  it('picks bottom→top for node directly below', () => {
    const r = getOrgToSatelliteHandles(0, 300);
    expect(r.sourceHandle).toBe('bottom');
    expect(r.targetHandle).toBe('top');
    expect(r.targetEdge).toBe('top');
  });

  it('picks top→bottom for node directly above', () => {
    const r = getOrgToSatelliteHandles(0, -300);
    expect(r.sourceHandle).toBe('top');
    expect(r.targetHandle).toBe('bottom');
    expect(r.targetEdge).toBe('bottom');
  });

  it('picks right→left for node directly to the right', () => {
    const r = getOrgToSatelliteHandles(300, 0);
    expect(r.sourceHandle).toBe('right');
    expect(r.targetHandle).toBe('left');
    expect(r.targetEdge).toBe('left');
  });

  it('picks left→right for node directly to the left', () => {
    const r = getOrgToSatelliteHandles(-300, 0);
    expect(r.sourceHandle).toBe('left');
    expect(r.targetHandle).toBe('right');
    expect(r.targetEdge).toBe('right');
  });

  it('axis bias: mostly-below node with small horizontal offset still picks bottom', () => {
    // dy=200, dx=50 → |dx|=50 <= 2*200=400, so should pick bottom
    const r = getOrgToSatelliteHandles(50, 200);
    expect(r.sourceHandle).toBe('bottom');
    expect(r.targetEdge).toBe('top');
  });

  it('axis bias: mostly-right node with small vertical offset still picks right', () => {
    // dx=200, dy=50 → |dy|=50 <= 2*200=400, so should pick right
    const r = getOrgToSatelliteHandles(200, 50);
    expect(r.sourceHandle).toBe('right');
    expect(r.targetEdge).toBe('left');
  });

  it('axis bias: mostly-above node with small horizontal offset still picks top', () => {
    const r = getOrgToSatelliteHandles(-30, -200);
    expect(r.sourceHandle).toBe('top');
    expect(r.targetEdge).toBe('bottom');
  });

  it('diagonal bottom-right beyond bias threshold falls back to atan2 (right)', () => {
    // dx=200, dy=200 — equal, atan2 gives π/4, which is NOT < π/4, so falls to bottom
    // Actually atan2(200, 200) = π/4 which hits the ≥ π/4 && < 3π/4 branch → bottom
    const r = getOrgToSatelliteHandles(200, 200);
    expect(r.sourceHandle).toBe('bottom');
  });
});

// ── layoutOverviewSatellitesAroundOrg ────────────────────────────────────────

describe('layoutOverviewSatellitesAroundOrg', () => {
  const makeCell = (i: number, w = 220, h = 88): OverviewLayoutCell => ({
    globalIndex: i,
    width: w,
    height: h,
  });

  it('returns empty map for empty input', () => {
    const result = layoutOverviewSatellitesAroundOrg([]);
    expect(result.size).toBe(0);
  });

  it('places a single cell away from the org center', () => {
    const result = layoutOverviewSatellitesAroundOrg([makeCell(0)]);
    expect(result.size).toBe(1);
    const pos = result.get(0)!;
    // Cell center must be far enough from (0,0) not to overlap org box
    const cellCX = pos.x + 220 / 2;
    const cellCY = pos.y + 88 / 2;
    // Rough check: center is outside the org envelope with a margin
    const withinOrgX = Math.abs(cellCX) < ORG_HALF_W + 36;
    const withinOrgY = Math.abs(cellCY) < ORG_HALF_H + 36;
    expect(withinOrgX && withinOrgY).toBe(false);
  });

  it('assigns a position to every cell', () => {
    const cells = Array.from({ length: 8 }, (_, i) => makeCell(i));
    const result = layoutOverviewSatellitesAroundOrg(cells);
    expect(result.size).toBe(8);
    for (let i = 0; i < 8; i++) {
      expect(result.has(i)).toBe(true);
    }
  });

  it('produces distinct positions for all cells', () => {
    const cells = Array.from({ length: 6 }, (_, i) => makeCell(i));
    const result = layoutOverviewSatellitesAroundOrg(cells);
    const positions = [...result.values()];
    for (let i = 0; i < positions.length; i++) {
      for (let j = i + 1; j < positions.length; j++) {
        const dx = positions[i].x - positions[j].x;
        const dy = positions[i].y - positions[j].y;
        // Cells shouldn't be placed at exactly the same coordinate
        expect(Math.abs(dx) + Math.abs(dy)).toBeGreaterThan(0);
      }
    }
  });

  it('preserves globalIndex keys correctly', () => {
    const cells: OverviewLayoutCell[] = [
      { globalIndex: 42, width: 220, height: 88 },
      { globalIndex: 7, width: 276, height: 104 },
    ];
    const result = layoutOverviewSatellitesAroundOrg(cells);
    expect(result.has(42)).toBe(true);
    expect(result.has(7)).toBe(true);
    expect(result.has(0)).toBe(false);
  });

  it('handles a large set (20 cells) without throwing', () => {
    const cells = Array.from({ length: 20 }, (_, i) => makeCell(i));
    expect(() => layoutOverviewSatellitesAroundOrg(cells)).not.toThrow();
    const result = layoutOverviewSatellitesAroundOrg(cells);
    expect(result.size).toBe(20);
  });
});

// ── child-carry delta math ────────────────────────────────────────────────────
// The drag handler translates child nodes by the same delta as their parent team.
// These tests document the invariant: child final position = child start + team delta.

describe('child-carry drag delta', () => {
  function applyDelta(
    teamStart: { x: number; y: number },
    teamFinal: { x: number; y: number },
    childStart: { x: number; y: number },
  ) {
    const dx = teamFinal.x - teamStart.x;
    const dy = teamFinal.y - teamStart.y;
    return { x: childStart.x + dx, y: childStart.y + dy };
  }

  it('child moves by the same delta as the team', () => {
    const result = applyDelta(
      { x: 100, y: 200 },
      { x: 160, y: 250 },
      { x: 130, y: 220 },
    );
    expect(result).toEqual({ x: 190, y: 270 });
  });

  it('zero delta leaves child at start position', () => {
    const start = { x: 80, y: -40 };
    const result = applyDelta(start, start, { x: 300, y: 100 });
    expect(result).toEqual({ x: 300, y: 100 });
  });

  it('negative delta translates child in the negative direction', () => {
    const result = applyDelta(
      { x: 200, y: 300 },
      { x: 100, y: 150 },
      { x: 250, y: 350 },
    );
    expect(result).toEqual({ x: 150, y: 200 });
  });
});

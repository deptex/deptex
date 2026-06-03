// The /overview cumulative growth series runs as all-zeros under the route mock
// (paginated fetches return []), so its math is otherwise uncovered (audit P0-9 named
// "cumulative-growth" alongside the billing figures). These pin the pure helper.
//
// Importing the router executes its module body (route registration) — supabase is the
// jest-mapped mock, so this is side-effect-free for the test.
import { cumulativeGrowth } from '../routes/admin';

const NOW = Date.UTC(2026, 5, 2, 12, 0, 0); // 2026-06-02T12:00:00Z
const DAY = 24 * 60 * 60 * 1000;
const dayStr = (ms: number) => new Date(ms).toISOString().slice(0, 10);

describe('cumulativeGrowth', () => {
  it('returns 365 days, oldest first, ending today', () => {
    const series = cumulativeGrowth(NOW, { orgs: [], projects: [], users: [] });
    expect(series).toHaveLength(365);
    expect(series[0].date).toBe(dayStr(NOW - 364 * DAY));
    expect(series[364].date).toBe(dayStr(NOW));
  });

  it('is all-zero for empty input', () => {
    const series = cumulativeGrowth(NOW, { orgs: [], projects: [], users: [] });
    expect(series.every((d) => d.orgs === 0 && d.projects === 0 && d.users === 0)).toBe(true);
  });

  it('counts an item only on and after the day it was created (cumulative, monotonic)', () => {
    // One org created 100 days ago: zero before that day, 1 from then through today.
    const created = NOW - 100 * DAY;
    const series = cumulativeGrowth(NOW, { orgs: [created], projects: [], users: [] });

    const dayBefore = series.find((d) => d.date === dayStr(NOW - 101 * DAY));
    const dayOf = series.find((d) => d.date === dayStr(created));
    expect(dayBefore?.orgs).toBe(0);
    expect(dayOf?.orgs).toBe(1);
    expect(series[364].orgs).toBe(1); // still counted today

    // Monotonically non-decreasing across the whole window.
    for (let i = 1; i < series.length; i++) {
      expect(series[i].orgs).toBeGreaterThanOrEqual(series[i - 1].orgs);
    }
  });

  it('accumulates multiple items across days and tracks each series independently', () => {
    const series = cumulativeGrowth(NOW, {
      orgs: [NOW - 300 * DAY, NOW - 200 * DAY, NOW - 10 * DAY],
      projects: [NOW - 50 * DAY],
      users: [NOW - 5 * DAY, NOW - 5 * DAY],
    });
    const today = series[364];
    expect(today.orgs).toBe(3);
    expect(today.projects).toBe(1);
    expect(today.users).toBe(2);

    // At 100 days ago: 2 of 3 orgs exist (created 300d/200d ago); the project (50d ago)
    // and users (5d ago) don't exist yet.
    const at100 = series.find((d) => d.date === dayStr(NOW - 100 * DAY))!;
    expect(at100.orgs).toBe(2);
    expect(at100.projects).toBe(0);
    expect(at100.users).toBe(0);
  });

  it('ignores items older than the 365-day window (still counted as already-present today)', () => {
    // An org created 400 days ago is before the window start, so every day in the
    // window already includes it — count is 1 from day 0.
    const series = cumulativeGrowth(NOW, { orgs: [NOW - 400 * DAY], projects: [], users: [] });
    expect(series[0].orgs).toBe(1);
    expect(series[364].orgs).toBe(1);
  });
});

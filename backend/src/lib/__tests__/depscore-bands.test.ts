import { depscoreBand, countDepscoreBands } from '../depscore-bands';

describe('depscoreBand', () => {
  it('buckets by the >=90 / >=70 / >=40 / <40 thresholds', () => {
    expect(depscoreBand(100)).toBe('critical');
    expect(depscoreBand(90)).toBe('critical');
    expect(depscoreBand(89.9)).toBe('high');
    expect(depscoreBand(70)).toBe('high');
    expect(depscoreBand(69.9)).toBe('medium');
    expect(depscoreBand(40)).toBe('medium');
    expect(depscoreBand(39.9)).toBe('low');
    expect(depscoreBand(0)).toBe('low');
  });
});

describe('countDepscoreBands', () => {
  it('counts each vuln into its band', () => {
    expect(
      countDepscoreBands([
        { depscore: 95 },
        { depscore: 92 },
        { depscore: 75 },
        { depscore: 50 },
        { depscore: 10 },
      ]),
    ).toEqual({ critical: 2, high: 1, medium: 1, low: 1 });
  });

  it('prefers contextual_depscore over base depscore', () => {
    // base depscore would be critical, but the EPD-applied contextual score drops it to low.
    expect(countDepscoreBands([{ depscore: 95, contextual_depscore: 20 }])).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
    });
  });

  it('treats missing / null scores as 0 (low band)', () => {
    expect(countDepscoreBands([{}, { depscore: null }, { contextual_depscore: null, depscore: null }])).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 3,
    });
  });

  it('returns all-zero for an empty list', () => {
    expect(countDepscoreBands([])).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
  });
});

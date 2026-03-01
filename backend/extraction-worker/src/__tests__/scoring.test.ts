interface ScoreBreakdown {
  score: number;
  openssfPenalty: number;
  popularityPenalty: number;
  maintenancePenalty: number;
  slsaMultiplier: number;
  maliciousMultiplier: number;
}

function calculateDependencyScore(data: {
  openssfScore: number | null;
  weeklyDownloads: number | null;
  releasesLast12Months: number | null;
  slsaLevel: number | null;
  isMalicious: boolean;
}): ScoreBreakdown {
  let openssfPenalty = data.openssfScore !== null ? (10 - data.openssfScore) * 3.3 : 11;
  let popularityPenalty = data.weeklyDownloads !== null ? Math.max(0, Math.min(33, 34 - Math.log10(data.weeklyDownloads + 1) * 7)) : 16;
  let maintenancePenalty = 0;
  if (data.releasesLast12Months !== null) {
    const r = data.releasesLast12Months;
    if (r >= 12) maintenancePenalty = 0;
    else if (r >= 6) maintenancePenalty = 8;
    else if (r >= 3) maintenancePenalty = 16;
    else if (r >= 1) maintenancePenalty = 24;
    else maintenancePenalty = 33;
  } else maintenancePenalty = 16;
  const baseScore = 100 - openssfPenalty - popularityPenalty - maintenancePenalty;
  const slsaMultiplier = data.slsaLevel != null ? (data.slsaLevel >= 3 ? 1.1 : data.slsaLevel >= 1 ? 1.05 : 1.0) : 1.0;
  const maliciousMultiplier = data.isMalicious ? 0.15 : 1.0;
  const score = Math.max(0, Math.min(100, Math.round(baseScore * slsaMultiplier * maliciousMultiplier)));
  return { score, openssfPenalty: Math.round(openssfPenalty * 10) / 10, popularityPenalty: Math.round(popularityPenalty * 10) / 10, maintenancePenalty: Math.round(maintenancePenalty * 10) / 10, slsaMultiplier, maliciousMultiplier };
}

describe('calculateDependencyScore', () => {
  describe('regression - packages without new data (slsaLevel=null, isMalicious=false)', () => {
    it('perfect package: openssf=10, downloads=1M, 12 releases -> ~100', () => {
      const result = calculateDependencyScore({
        openssfScore: 10,
        weeklyDownloads: 1_000_000,
        releasesLast12Months: 12,
        slsaLevel: null,
        isMalicious: false,
      });
      expect(result.score).toBeGreaterThanOrEqual(95);
      expect(result.score).toBeLessThanOrEqual(100);
      expect(result.openssfPenalty).toBe(0);
      expect(result.maintenancePenalty).toBe(0);
    });

    it('unknown package: all null -> moderate score', () => {
      const result = calculateDependencyScore({
        openssfScore: null,
        weeklyDownloads: null,
        releasesLast12Months: null,
        slsaLevel: null,
        isMalicious: false,
      });
      expect(result.score).toBeGreaterThan(40);
      expect(result.score).toBeLessThan(60);
      expect(result.openssfPenalty).toBe(11);
      expect(result.popularityPenalty).toBe(16);
      expect(result.maintenancePenalty).toBe(16);
    });

    it('poor package: openssf=2, downloads=50, 0 releases -> low score', () => {
      const result = calculateDependencyScore({
        openssfScore: 2,
        weeklyDownloads: 50,
        releasesLast12Months: 0,
        slsaLevel: null,
        isMalicious: false,
      });
      expect(result.score).toBeLessThan(30);
      expect(result.openssfPenalty).toBeCloseTo(26.4, 1);
      expect(result.maintenancePenalty).toBe(33);
    });
  });

  describe('SLSA bonus', () => {
    it('level 3 = 10% boost', () => {
      const base = calculateDependencyScore({
        openssfScore: 8,
        weeklyDownloads: 10000,
        releasesLast12Months: 6,
        slsaLevel: null,
        isMalicious: false,
      });
      const slsa3 = calculateDependencyScore({
        openssfScore: 8,
        weeklyDownloads: 10000,
        releasesLast12Months: 6,
        slsaLevel: 3,
        isMalicious: false,
      });
      expect(slsa3.score).toBeCloseTo(base.score * 1.1, -1);
      expect(slsa3.slsaMultiplier).toBe(1.1);
    });

    it('level 1 = 5% boost', () => {
      const result = calculateDependencyScore({
        openssfScore: 8,
        weeklyDownloads: 10000,
        releasesLast12Months: 6,
        slsaLevel: 1,
        isMalicious: false,
      });
      expect(result.slsaMultiplier).toBe(1.05);
    });

    it('no SLSA = unchanged', () => {
      const base = calculateDependencyScore({
        openssfScore: 8,
        weeklyDownloads: 10000,
        releasesLast12Months: 6,
        slsaLevel: null,
        isMalicious: false,
      });
      expect(base.slsaMultiplier).toBe(1.0);
    });
  });

  describe('malicious multiplier', () => {
    it('isMalicious drops score by 85%', () => {
      const base = calculateDependencyScore({
        openssfScore: 10,
        weeklyDownloads: 1_000_000,
        releasesLast12Months: 12,
        slsaLevel: null,
        isMalicious: false,
      });
      const malicious = calculateDependencyScore({
        openssfScore: 10,
        weeklyDownloads: 1_000_000,
        releasesLast12Months: 12,
        slsaLevel: null,
        isMalicious: true,
      });
      expect(malicious.maliciousMultiplier).toBe(0.15);
      expect(malicious.score).toBeCloseTo(base.score * 0.15, -1);
    });
  });

  describe('combined', () => {
    it('malicious + SLSA 3 (malicious dominates)', () => {
      const result = calculateDependencyScore({
        openssfScore: 10,
        weeklyDownloads: 1_000_000,
        releasesLast12Months: 12,
        slsaLevel: 3,
        isMalicious: true,
      });
      expect(result.slsaMultiplier).toBe(1.1);
      expect(result.maliciousMultiplier).toBe(0.15);
      expect(result.score).toBeLessThan(20);
    });
  });

  describe('score bounds', () => {
    it('never below 0', () => {
      const result = calculateDependencyScore({
        openssfScore: 0,
        weeklyDownloads: 0,
        releasesLast12Months: 0,
        slsaLevel: null,
        isMalicious: true,
      });
      expect(result.score).toBeGreaterThanOrEqual(0);
    });

    it('never above 100', () => {
      const result = calculateDependencyScore({
        openssfScore: 10,
        weeklyDownloads: 10_000_000,
        releasesLast12Months: 24,
        slsaLevel: 4,
        isMalicious: false,
      });
      expect(result.score).toBeLessThanOrEqual(100);
    });
  });
});

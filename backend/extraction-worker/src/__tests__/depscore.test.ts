import { calculateDepscore, type DepscoreContext } from '../depscore';

describe('calculateDepscore', () => {
  describe('regression - existing formula without new optional fields', () => {
    it('critical vuln (CVSS 9.0), CISA KEV, reachable, CROWN_JEWELS -> high score', () => {
      const ctx: DepscoreContext = {
        cvss: 9,
        epss: 0.5,
        cisaKev: true,
        isReachable: true,
        assetTier: 'CROWN_JEWELS',
      };
      expect(calculateDepscore(ctx)).toBe(100);
    });

    it('low vuln (CVSS 2.0), no KEV, not reachable, NON_PRODUCTION -> low score', () => {
      const ctx: DepscoreContext = {
        cvss: 2,
        epss: 0,
        cisaKev: false,
        isReachable: false,
        assetTier: 'NON_PRODUCTION',
      };
      expect(calculateDepscore(ctx)).toBe(1);
    });

    it('medium vuln, EXTERNAL tier, reachable -> mid score', () => {
      const ctx: DepscoreContext = {
        cvss: 4,
        epss: 0.5,
        cisaKev: false,
        isReachable: true,
        assetTier: 'EXTERNAL',
      };
      const score = calculateDepscore(ctx);
      expect(score).toBeGreaterThanOrEqual(40);
      expect(score).toBeLessThanOrEqual(50);
    });
  });

  describe('isDirect', () => {
    it('isDirect: false (transitive) reduces score by 25%', () => {
      const base: DepscoreContext = {
        cvss: 8,
        epss: 0.3,
        cisaKev: false,
        isReachable: true,
        assetTier: 'EXTERNAL',
      };
      const direct = calculateDepscore({ ...base, isDirect: true });
      const transitive = calculateDepscore({ ...base, isDirect: false });
      const ratio = transitive / direct;
      expect(ratio).toBeCloseTo(0.75, 1);
    });
  });

  describe('isDevDependency', () => {
    it('isDevDependency: true reduces score by 60%', () => {
      const base: DepscoreContext = {
        cvss: 8,
        epss: 0.3,
        cisaKev: false,
        isReachable: true,
        assetTier: 'EXTERNAL',
      };
      const prod = calculateDepscore({ ...base, isDevDependency: false });
      const dev = calculateDepscore({ ...base, isDevDependency: true });
      const ratio = dev / prod;
      expect(ratio).toBeCloseTo(0.4, 1);
    });
  });

  describe('combined transitive dev dep', () => {
    it('transitive + dev dep yields ~70% reduction from direct prod', () => {
      const base: DepscoreContext = {
        cvss: 8,
        epss: 0.3,
        cisaKev: false,
        isReachable: true,
        assetTier: 'EXTERNAL',
      };
      const directProd = calculateDepscore({ ...base, isDirect: true, isDevDependency: false });
      const transitiveDev = calculateDepscore({ ...base, isDirect: false, isDevDependency: true });
      const ratio = transitiveDev / directProd;
      expect(ratio).toBeCloseTo(0.3, 1);
    });
  });

  describe('isMalicious', () => {
    it('isMalicious boosts score by 30%', () => {
      const base: DepscoreContext = {
        cvss: 6,
        epss: 0.2,
        cisaKev: false,
        isReachable: true,
        assetTier: 'INTERNAL',
      };
      const normal = calculateDepscore({ ...base, isMalicious: false });
      const malicious = calculateDepscore({ ...base, isMalicious: true });
      const ratio = malicious / normal;
      expect(ratio).toBeCloseTo(1.3, 1);
    });
  });

  describe('packageScore', () => {
    it('low reputation (<30) boosts by 15%', () => {
      const base: DepscoreContext = {
        cvss: 5,
        epss: 0.2,
        cisaKev: false,
        isReachable: true,
        assetTier: 'EXTERNAL',
      };
      const neutral = calculateDepscore({ ...base, packageScore: 50 });
      const lowRep = calculateDepscore({ ...base, packageScore: 20 });
      const ratio = lowRep / neutral;
      expect(ratio).toBeCloseTo(1.15, 1);
    });

    it('high reputation (>70) reduces by 5%', () => {
      const base: DepscoreContext = {
        cvss: 5,
        epss: 0.2,
        cisaKev: false,
        isReachable: true,
        assetTier: 'EXTERNAL',
      };
      const neutral = calculateDepscore({ ...base, packageScore: 50 });
      const highRep = calculateDepscore({ ...base, packageScore: 85 });
      const ratio = highRep / neutral;
      expect(ratio).toBeCloseTo(0.95, 1);
    });
  });

  describe('edge cases', () => {
    it('null packageScore uses neutral weight', () => {
      const base: DepscoreContext = {
        cvss: 5,
        epss: 0.2,
        cisaKev: false,
        isReachable: true,
        assetTier: 'EXTERNAL',
      };
      const withNull = calculateDepscore({ ...base, packageScore: null });
      const withUndefined = calculateDepscore({ ...base });
      expect(withNull).toBe(withUndefined);
    });

    it('undefined isDirect treated as direct (weight 1.0)', () => {
      const base: DepscoreContext = {
        cvss: 6,
        epss: 0.2,
        cisaKev: false,
        isReachable: true,
        assetTier: 'EXTERNAL',
      };
      const explicitDirect = calculateDepscore({ ...base, isDirect: true });
      const undefinedDirect = calculateDepscore({ ...base });
      expect(undefinedDirect).toBe(explicitDirect);
    });

    it('all multipliers combined', () => {
      const ctx: DepscoreContext = {
        cvss: 7,
        epss: 0.4,
        cisaKev: true,
        isReachable: true,
        assetTier: 'CROWN_JEWELS',
        isDirect: false,
        isDevDependency: true,
        isMalicious: true,
        packageScore: 15,
      };
      const score = calculateDepscore(ctx);
      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(100);
    });
  });

  describe('tierMultiplier (custom tiers)', () => {
    it('tierMultiplier overrides legacy assetTier weight', () => {
      const base: DepscoreContext = {
        cvss: 7,
        epss: 0.3,
        cisaKev: false,
        isReachable: true,
        assetTier: 'INTERNAL',
      };
      const legacyInternal = calculateDepscore(base);
      const customHigh = calculateDepscore({ ...base, tierMultiplier: 1.5 });
      const customLow = calculateDepscore({ ...base, tierMultiplier: 0.3 });

      expect(customHigh).toBeGreaterThan(legacyInternal);
      expect(customLow).toBeLessThan(legacyInternal);
    });

    it('tierMultiplier affects unreachable dampening', () => {
      const base: DepscoreContext = {
        cvss: 7,
        epss: 0.3,
        cisaKev: false,
        isReachable: false,
        assetTier: 'INTERNAL',
      };
      const highMultiplier = calculateDepscore({ ...base, tierMultiplier: 1.5 });
      const lowMultiplier = calculateDepscore({ ...base, tierMultiplier: 0.3 });

      expect(highMultiplier).toBeGreaterThan(lowMultiplier);
    });

    it('tierMultiplier: 1.0 (Internal-equivalent) matches legacy INTERNAL for reachable', () => {
      const base: DepscoreContext = {
        cvss: 6,
        epss: 0.2,
        cisaKev: false,
        isReachable: true,
        assetTier: 'INTERNAL',
      };
      const legacy = calculateDepscore(base);
      const custom = calculateDepscore({ ...base, tierMultiplier: 0.9 });
      expect(custom).toBe(legacy);
    });
  });

  describe('score capping', () => {
    it('result never exceeds 100', () => {
      const ctx: DepscoreContext = {
        cvss: 10,
        epss: 1,
        cisaKev: true,
        isReachable: true,
        assetTier: 'CROWN_JEWELS',
        isDirect: true,
        isDevDependency: false,
        isMalicious: true,
        packageScore: 10,
      };
      expect(calculateDepscore(ctx)).toBe(100);
    });
  });
});

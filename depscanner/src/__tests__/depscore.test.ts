import {
  calculateDepscore,
  calculateBaseDepscoreNoReachability,
  calculateSecretDepscore,
  calculateSemgrepDepscore,
  calculateLicenseDepscore,
  calculateDastDepscore,
  type DepscoreContext,
} from '../depscore';
import { scoreVulnRow } from '../pipeline-steps/dep-scan';

describe('calculateDepscore', () => {
  describe('regression - existing formula without new optional fields', () => {
    it('critical vuln (CVSS 9.0), CISA KEV, reachable, importance=1.5 -> high score', () => {
      const ctx: DepscoreContext = {
        cvss: 9,
        epss: 0.5,
        cisaKev: true,
        isReachable: true,
        importance: 1.5,
      };
      expect(calculateDepscore(ctx)).toBe(100);
    });

    it('low vuln (CVSS 2.0), no KEV, not reachable, importance=0.6 -> low score', () => {
      const ctx: DepscoreContext = {
        cvss: 2,
        epss: 0,
        cisaKev: false,
        isReachable: false,
        importance: 0.6,
      };
      // base 20 * 0.6 * 0.6 * 0.2 ≈ 1.44 → 1
      expect(calculateDepscore(ctx)).toBe(1);
    });

    it('medium vuln, importance=1.0, reachable -> mid score', () => {
      const ctx: DepscoreContext = {
        cvss: 4,
        epss: 0.5,
        cisaKev: false,
        isReachable: true,
        importance: 1.0,
      };
      const score = calculateDepscore(ctx);
      expect(score).toBeGreaterThanOrEqual(35);
      expect(score).toBeLessThanOrEqual(50);
    });
  });

  describe('importance multiplier', () => {
    const base: Omit<DepscoreContext, 'importance'> = {
      cvss: 7.0,
      epss: 0.3,
      cisaKev: false,
      isReachable: true,
    };

    it('higher importance produces higher score', () => {
      const low = calculateDepscore({ ...base, importance: 0.5 });
      const mid = calculateDepscore({ ...base, importance: 1.0 });
      const high = calculateDepscore({ ...base, importance: 2.0 });
      expect(low).toBeLessThan(mid);
      expect(mid).toBeLessThan(high);
    });

    it('importance scales linearly when nothing saturates at 100', () => {
      const at_05 = calculateDepscore({ ...base, importance: 0.5, cvss: 3.0, cisaKev: false });
      const at_10 = calculateDepscore({ ...base, importance: 1.0, cvss: 3.0, cisaKev: false });
      // doubling importance roughly doubles the un-saturated score
      expect(at_10).toBeGreaterThanOrEqual(at_05 * 1.9);
      expect(at_10).toBeLessThanOrEqual(at_05 * 2.1);
    });

    it('clamps importance > 2.0 to 2.0', () => {
      const at_20 = calculateDepscore({ ...base, importance: 2.0 });
      const at_99 = calculateDepscore({ ...base, importance: 99 });
      expect(at_99).toBe(at_20);
    });

    it('clamps importance < 0.5 to 0.5', () => {
      const at_05 = calculateDepscore({ ...base, importance: 0.5 });
      const at_neg = calculateDepscore({ ...base, importance: -1 });
      expect(at_neg).toBe(at_05);
    });

    it('falls back to 1.0 on NaN', () => {
      const at_10 = calculateDepscore({ ...base, importance: 1.0 });
      const at_nan = calculateDepscore({ ...base, importance: Number.NaN });
      expect(at_nan).toBe(at_10);
    });
  });

  // SC1: the dependency-context multiplier (directness / dev-scope / malicious /
  // reputation) was dead on the vuln path because the worker call site never
  // passed these fields. These pin that the multiplier actually moves the score.
  describe('dependency context multiplier', () => {
    // cvss=4 / epss=0.1 keeps every variant well below the 100 cap so the
    // multiplier is visible (not saturated).
    const base: DepscoreContext = {
      cvss: 4, epss: 0.1, cisaKev: false, isReachable: true, importance: 1.0,
    };

    it('transitive (isDirect=false) tapers to 0.75× of direct', () => {
      const direct = calculateDepscore({ ...base, isDirect: true });
      const transitive = calculateDepscore({ ...base, isDirect: false });
      expect(transitive).toBeLessThan(direct);
      expect(transitive).toBeCloseTo(direct * 0.75, 0);
    });

    it('omitting isDirect behaves the same as direct (no accidental taper)', () => {
      const direct = calculateDepscore({ ...base, isDirect: true });
      const unset = calculateDepscore({ ...base });
      expect(unset).toBe(direct);
    });

    it('dev-scope (isDevDependency=true) tapers hard to 0.4×', () => {
      const prod = calculateDepscore({ ...base, isDevDependency: false });
      const dev = calculateDepscore({ ...base, isDevDependency: true });
      expect(dev).toBeLessThan(prod);
      expect(dev).toBeCloseTo(prod * 0.4, 0);
    });

    it('malicious dep boosts 1.3×', () => {
      const benign = calculateDepscore({ ...base, isMalicious: false });
      const malicious = calculateDepscore({ ...base, isMalicious: true });
      expect(malicious).toBeGreaterThan(benign);
      // ratio (rather than absolute) avoids integer-rounding flake at low scores.
      expect(malicious / benign).toBeCloseTo(1.3, 1);
    });

    it('package reputation: low score (<30) raises 1.15×, high (>70) lowers 0.95×', () => {
      const neutral = calculateDepscore({ ...base, packageScore: 50 });
      const sketchy = calculateDepscore({ ...base, packageScore: 10 });
      const trusted = calculateDepscore({ ...base, packageScore: 90 });
      expect(sketchy).toBeGreaterThan(neutral);
      expect(trusted).toBeLessThan(neutral);
    });

    it('the base (no-reachability) score honors the same multiplier', () => {
      const direct = calculateBaseDepscoreNoReachability({
        cvss: 4, epss: 0.1, cisaKev: false, importance: 1.0, isDirect: true, isDevDependency: false,
      });
      const devTransitive = calculateBaseDepscoreNoReachability({
        cvss: 4, epss: 0.1, cisaKev: false, importance: 1.0, isDirect: false, isDevDependency: true,
      });
      expect(devTransitive).toBeLessThan(direct);
      expect(devTransitive / direct).toBeCloseTo(0.75 * 0.4, 1);
    });
  });

  describe('reachability levels', () => {
    const base: Omit<DepscoreContext, 'reachabilityLevel'> = {
      cvss: 7.0,
      epss: 0.3,
      cisaKev: false,
      isReachable: true,
      importance: 1.0,
    };

    it('confirmed > data_flow > function > module', () => {
      const confirmed = calculateDepscore({ ...base, reachabilityLevel: 'confirmed' });
      const data_flow = calculateDepscore({ ...base, reachabilityLevel: 'data_flow' });
      const fn = calculateDepscore({ ...base, reachabilityLevel: 'function' });
      const mod = calculateDepscore({ ...base, reachabilityLevel: 'module' });
      expect(confirmed).toBeGreaterThanOrEqual(data_flow);
      expect(data_flow).toBeGreaterThan(fn);
      expect(fn).toBeGreaterThan(mod);
    });

    it('unreachable -> 0 score', () => {
      expect(calculateDepscore({ ...base, reachabilityLevel: 'unreachable' })).toBe(0);
    });

    it('legacy isReachable=false dampens to 20% of reachable', () => {
      const reachable = calculateDepscore({ ...base, isReachable: true });
      const unreached = calculateDepscore({ ...base, isReachable: false });
      expect(unreached).toBeGreaterThan(0);
      expect(unreached).toBeLessThan(reachable);
    });
  });
});

describe('calculateBaseDepscoreNoReachability', () => {
  it('higher importance produces higher base score', () => {
    const low = calculateBaseDepscoreNoReachability({
      cvss: 7.0, epss: 0.3, cisaKev: false, importance: 0.5,
    });
    const high = calculateBaseDepscoreNoReachability({
      cvss: 7.0, epss: 0.3, cisaKev: false, importance: 2.0,
    });
    expect(high).toBeGreaterThan(low);
  });
});

describe('calculateSecretDepscore', () => {
  it('importance scales the score', () => {
    const low = calculateSecretDepscore({
      detectorType: 'AWS', isVerified: true, isCurrent: true, importance: 0.5,
    });
    const high = calculateSecretDepscore({
      detectorType: 'AWS', isVerified: true, isCurrent: true, importance: 2.0,
    });
    expect(high).toBeGreaterThan(low);
  });

  it('unknown detector falls to 0.6 weight', () => {
    const known = calculateSecretDepscore({
      detectorType: 'AWS', isVerified: true, isCurrent: true, importance: 1.0,
    });
    const unknown = calculateSecretDepscore({
      detectorType: 'mystery', isVerified: true, isCurrent: true, importance: 1.0,
    });
    expect(unknown).toBeLessThan(known);
  });
});

describe('calculateSemgrepDepscore', () => {
  it('high-impact CWE boosts the score', () => {
    const lowCwe = calculateSemgrepDepscore({
      severity: 'ERROR', cweIds: ['CWE-200'], category: 'best-practice', importance: 1.0,
    });
    const highCwe = calculateSemgrepDepscore({
      severity: 'ERROR', cweIds: ['CWE-89'], category: 'security', importance: 1.0,
    });
    expect(highCwe).toBeGreaterThan(lowCwe);
  });

  it('importance scales the score', () => {
    const low = calculateSemgrepDepscore({
      severity: 'ERROR', cweIds: ['CWE-89'], category: 'security', importance: 0.5,
    });
    const high = calculateSemgrepDepscore({
      severity: 'ERROR', cweIds: ['CWE-89'], category: 'security', importance: 2.0,
    });
    expect(high).toBeGreaterThan(low);
  });
});

describe('calculateLicenseDepscore', () => {
  it('AGPL > GPL > unknown', () => {
    const agpl = calculateLicenseDepscore({
      reasons: ['agpl'], isDirect: true, isDevDependency: false, importance: 1.0,
    });
    const gpl = calculateLicenseDepscore({
      reasons: ['gpl'], isDirect: true, isDevDependency: false, importance: 1.0,
    });
    const unknown = calculateLicenseDepscore({
      reasons: ['unknown license'], isDirect: true, isDevDependency: false, importance: 1.0,
    });
    expect(agpl).toBeGreaterThan(gpl);
    expect(gpl).toBeGreaterThan(unknown);
  });

  it('dev-dependency dampens the score', () => {
    const prod = calculateLicenseDepscore({
      reasons: ['agpl'], isDirect: true, isDevDependency: false, importance: 1.0,
    });
    const dev = calculateLicenseDepscore({
      reasons: ['agpl'], isDirect: true, isDevDependency: true, importance: 1.0,
    });
    expect(dev).toBeLessThan(prod);
  });
});

// N2: DAST findings need a depscore so ZAP/Nuclei rows rank in the unified
// findings order. Score = severity-band base × importance, at the implicit
// confirmed reachability tier (a DAST hit is runtime proof).
describe('calculateDastDepscore', () => {
  it('every severity band yields a non-null, in-range score', () => {
    for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
      const s = calculateDastDepscore({ severity, importance: 1.0 });
      expect(typeof s).toBe('number');
      expect(s).toBeGreaterThan(0);
      expect(s).toBeLessThanOrEqual(100);
    }
  });

  it('orders strictly by severity at fixed importance', () => {
    const critical = calculateDastDepscore({ severity: 'critical', importance: 1.0 });
    const high = calculateDastDepscore({ severity: 'high', importance: 1.0 });
    const medium = calculateDastDepscore({ severity: 'medium', importance: 1.0 });
    const low = calculateDastDepscore({ severity: 'low', importance: 1.0 });
    const info = calculateDastDepscore({ severity: 'info', importance: 1.0 });
    expect(critical).toBeGreaterThan(high);
    expect(high).toBeGreaterThan(medium);
    expect(medium).toBeGreaterThan(low);
    expect(low).toBeGreaterThan(info);
    // Mirrors the container/IaC severityToDepscore bands.
    expect(critical).toBe(90);
    expect(high).toBe(70);
    expect(medium).toBe(50);
    expect(low).toBe(30);
    expect(info).toBe(10);
  });

  it('folds in project importance (tierWeight), clamped to [0.5, 2.0]', () => {
    const base = calculateDastDepscore({ severity: 'medium', importance: 1.0 });
    const heavy = calculateDastDepscore({ severity: 'medium', importance: 2.0 });
    const light = calculateDastDepscore({ severity: 'medium', importance: 0.5 });
    expect(heavy).toBeGreaterThan(base);
    expect(light).toBeLessThan(base);
    // 50 × 2.0 = 100; 50 × 0.5 = 25; out-of-range importance clamps.
    expect(heavy).toBe(100);
    expect(light).toBe(25);
    expect(calculateDastDepscore({ severity: 'medium', importance: 9 })).toBe(100);
  });

  it('caps at 100 and falls back to the LOW band for an unknown severity', () => {
    expect(calculateDastDepscore({ severity: 'critical', importance: 2.0 })).toBe(100);
    const unknown = calculateDastDepscore({ severity: 'bogus', importance: 1.0 });
    expect(unknown).toBe(30);
  });
});

// SC1 wiring: proves the worker's per-PDV scoring helper actually threads
// directness + scope from the matched project_dependencies row into the
// depscore math — the bug was that the call site passed neither.
describe('scoreVulnRow (dep-scan worker wiring)', () => {
  const row = {
    cvss_score: 9 as number | null,
    epss_score: 0.5 as number | null,
    cisa_kev: false,
    severity: 'critical' as string | null,
    is_reachable: true,
  };

  it('a prod + direct dep scores far higher than the same vuln on a dev + transitive dep', () => {
    const prodDirect = scoreVulnRow(row, { is_direct: true, environment: 'prod' }, 1.0);
    const devTransitive = scoreVulnRow(row, { is_direct: false, environment: 'dev' }, 1.0);
    expect(devTransitive.depscore).toBeLessThan(prodDirect.depscore);
    // 0.75 (transitive) × 0.4 (dev) = 0.30× — a real, visible taper.
    expect(devTransitive.depscore).toBeCloseTo(prodDirect.depscore * 0.3, 0);
    expect(devTransitive.base_depscore_no_reachability)
      .toBeLessThan(prodDirect.base_depscore_no_reachability);
  });

  it('a missing pd context defaults to direct + prod (no accidental taper)', () => {
    const explicit = scoreVulnRow(row, { is_direct: true, environment: 'prod' }, 1.0);
    const missing = scoreVulnRow(row, undefined, 1.0);
    expect(missing.depscore).toBe(explicit.depscore);
  });

  it('derives cvss from the severity word when cvss_score is null', () => {
    const withCvss = scoreVulnRow(row, { is_direct: true, environment: 'prod' }, 1.0);
    const fromSeverity = scoreVulnRow(
      { ...row, cvss_score: null }, { is_direct: true, environment: 'prod' }, 1.0,
    );
    // severity 'critical' → SEVERITY_TO_CVSS 9.0, same as the explicit cvss 9.
    expect(fromSeverity.depscore).toBe(withCvss.depscore);
  });
});

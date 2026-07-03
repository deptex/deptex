/**
 * SC1 — the authoritative post-classifier rescore (`rescoreVulnRow`) must
 * thread directness + dev-scope into the depscore, mirroring dep-scan.ts's
 * `scoreVulnRow`. Before SC1 this site passed neither, so the dep-context
 * taper (0.75× transitive, 0.4× dev) dep-scan.ts applied was overwritten back
 * to flat in the full pipeline. These tests pin that the taper survives AND
 * that the reachability-tier weight is applied on top.
 */

import { rescoreVulnRow } from '../pipeline-steps/reachability';

const baseRow = {
  cvss_score: 8.0,
  epss_score: 0,
  cisa_kev: false,
  severity: 'high',
  is_reachable: true,
  reachability_level: 'module' as string | null,
};

describe('rescoreVulnRow — SC1 directness/scope taper', () => {
  it('tapers base_depscore_no_reachability 0.75× for a transitive dep', () => {
    const direct = rescoreVulnRow(baseRow, { is_direct: true, environment: 'prod' }, 1.0);
    const transitive = rescoreVulnRow(baseRow, { is_direct: false, environment: 'prod' }, 1.0);
    // baseImpact 80 × threat 0.6 × importance 1 = 48 direct; ×0.75 = 36 transitive.
    expect(direct.base_depscore_no_reachability).toBe(48);
    expect(transitive.base_depscore_no_reachability).toBe(36);
  });

  it('tapers 0.4× for a dev-scope dep', () => {
    const dev = rescoreVulnRow(baseRow, { is_direct: true, environment: 'dev' }, 1.0);
    // 48 × 0.4 = 19.2 → 19.
    expect(dev.base_depscore_no_reachability).toBe(19);
  });

  it('applies the reachability tier weight on top of the dep-context taper (depscore)', () => {
    // direct prod, module tier (0.5): depscore = 48 × 0.5 = 24.
    const direct = rescoreVulnRow(baseRow, { is_direct: true, environment: 'prod' }, 1.0);
    expect(direct.depscore).toBe(24);
    // transitive prod, module tier: 48 × 0.75 × 0.5 = 18.
    const transitive = rescoreVulnRow(baseRow, { is_direct: false, environment: 'prod' }, 1.0);
    expect(transitive.depscore).toBe(18);
  });

  it('treats `unreachable` as weight 0 regardless of directness', () => {
    const r = rescoreVulnRow({ ...baseRow, reachability_level: 'unreachable', is_reachable: false }, { is_direct: true, environment: 'prod' }, 1.0);
    expect(r.depscore).toBe(0);
    // base is reachability-independent — still non-zero.
    expect(r.base_depscore_no_reachability).toBe(48);
  });

  it('defaults to direct + prod when no project_dependency context is available', () => {
    const undef = rescoreVulnRow(baseRow, undefined, 1.0);
    const direct = rescoreVulnRow(baseRow, { is_direct: true, environment: 'prod' }, 1.0);
    expect(undef.base_depscore_no_reachability).toBe(direct.base_depscore_no_reachability);
    expect(undef.depscore).toBe(direct.depscore);
  });

  it('uses the CVSS 4.0 fallback when both cvss_score and severity lookup are absent', () => {
    const r = rescoreVulnRow(
      { cvss_score: null, epss_score: 0, cisa_kev: false, severity: null, is_reachable: true, reachability_level: 'confirmed' },
      { is_direct: true, environment: 'prod' },
      1.0,
    );
    // cvss 4.0 → baseImpact 40 × 0.6 × confirmed 1.0 = 24.
    expect(r.depscore).toBe(24);
  });
});

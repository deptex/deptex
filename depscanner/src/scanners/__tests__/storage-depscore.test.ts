/**
 * containerDepscore — reachability-weighted depscore for container findings.
 *
 * Pins the close-out behavior: `unreachable` findings are downweighted by
 * CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER (×0.4); `module` and `null`
 * findings keep their severity-based score; `null` severity stays null. This
 * is the load-bearing change for Phase 2 close-out Success Criterion 1.
 */

import {
  containerDepscore,
  CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER,
} from '../storage';
import type { ContainerFinding } from '../types';

function finding(overrides: Partial<ContainerFinding>): ContainerFinding {
  return {
    scanner_version: 'trivy@0.69.3',
    image_reference: 'debian:bookworm-slim',
    image_digest: 'sha256:' + 'a'.repeat(64),
    os_package_name: 'libc6',
    os_package_version: '2.36-9',
    os_package_ecosystem: 'debian',
    osv_id: null,
    cve_id: 'CVE-2026-9999',
    severity: 'HIGH',
    cvss_score: null,
    epss_score: null,
    is_kev: false,
    fix_versions: [],
    layer_digest: null,
    description: null,
    rule_doc_url: null,
    container_fingerprint: 'libc6@CVE-2026-9999',
    reachability_level: null,
    reachability_details: null,
    ...overrides,
  };
}

describe('containerDepscore', () => {
  it('keeps the severity score when reachability is module', () => {
    expect(containerDepscore(finding({ severity: 'CRITICAL', reachability_level: 'module' }))).toBe(90);
    expect(containerDepscore(finding({ severity: 'HIGH', reachability_level: 'module' }))).toBe(70);
    expect(containerDepscore(finding({ severity: 'MEDIUM', reachability_level: 'module' }))).toBe(50);
  });

  it('keeps the severity score when reachability is null (unclassified)', () => {
    expect(containerDepscore(finding({ severity: 'HIGH', reachability_level: null }))).toBe(70);
    expect(containerDepscore(finding({ severity: 'CRITICAL', reachability_level: null }))).toBe(90);
  });

  it('downweights unreachable findings by ×0.4', () => {
    expect(containerDepscore(finding({ severity: 'CRITICAL', reachability_level: 'unreachable' }))).toBe(36);
    expect(containerDepscore(finding({ severity: 'HIGH', reachability_level: 'unreachable' }))).toBe(28);
    expect(containerDepscore(finding({ severity: 'MEDIUM', reachability_level: 'unreachable' }))).toBe(20);
    expect(containerDepscore(finding({ severity: 'LOW', reachability_level: 'unreachable' }))).toBe(12);
    expect(containerDepscore(finding({ severity: 'INFO', reachability_level: 'unreachable' }))).toBe(4);
  });

  it('returns null for null severity regardless of reachability', () => {
    expect(containerDepscore(finding({ severity: null, reachability_level: 'unreachable' }))).toBeNull();
    expect(containerDepscore(finding({ severity: null, reachability_level: 'module' }))).toBeNull();
    expect(containerDepscore(finding({ severity: null, reachability_level: null }))).toBeNull();
  });

  it('downweighted HIGH (28) sorts below module HIGH (70) and below LOW (30) — the close-out ranking goal', () => {
    const unreachableHigh = containerDepscore(finding({ severity: 'HIGH', reachability_level: 'unreachable' }));
    const moduleHigh = containerDepscore(finding({ severity: 'HIGH', reachability_level: 'module' }));
    const moduleLow = containerDepscore(finding({ severity: 'LOW', reachability_level: 'module' }));
    expect(unreachableHigh!).toBeLessThan(moduleHigh!);
    expect(unreachableHigh!).toBeLessThan(moduleLow!);
  });

  it('exports the multiplier constant for the migration backfill to reference', () => {
    expect(CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER).toBe(0.4);
  });
});

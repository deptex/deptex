import { describe, it, expect } from 'vitest';
import { teamBundleToRows } from './team-findings';
import type { TeamFindingsBundle } from './api';

function bundle(partial: Partial<TeamFindingsBundle>): TeamFindingsBundle {
  return {
    vulnerabilities: [], secrets: [], semgrep: [], iac: [], container: [],
    malicious: [], codeFlows: [], dast: [], baseImageRecs: [],
    trackerLinks: [], groupSuppressions: [], acknowledgements: [],
    projectIds: [], degradedSlices: [],
    ...partial,
  } as TeamFindingsBundle;
}

describe('teamBundleToRows', () => {
  it('keeps the SAME CVE in two different projects as TWO rows (cross-project dedup key)', () => {
    // dependency_id is the GLOBAL dependencies.id, shared across projects for the same
    // package@version. Keying dedup on dependency_id:osv_id alone would collapse these.
    const { rows } = teamBundleToRows(bundle({
      vulnerabilities: [
        { project_id: 'p1', dependency_id: 'dep-1', osv_id: 'CVE-1', depscore: 50 },
        { project_id: 'p2', dependency_id: 'dep-1', osv_id: 'CVE-1', depscore: 50 },
      ] as any,
    }));
    const vulns = rows.filter((r) => r.type === 'vulnerability');
    expect(vulns).toHaveLength(2);
    expect(vulns.map((r) => (r.data as any).project_id).sort()).toEqual(['p1', 'p2']);
  });

  it('dedups within ONE project by dependency+CVE, keeping the highest depscore', () => {
    const { rows } = teamBundleToRows(bundle({
      vulnerabilities: [
        { project_id: 'p1', dependency_id: 'dep-1', osv_id: 'CVE-1', depscore: 30 },
        { project_id: 'p1', dependency_id: 'dep-1', osv_id: 'CVE-1', contextual_depscore: 90 },
      ] as any,
    }));
    const vulns = rows.filter((r) => r.type === 'vulnerability');
    expect(vulns).toHaveLength(1);
    expect((vulns[0].data as any).contextual_depscore).toBe(90);
  });

  it('maps every finding type to a row and splits baseImageRecs out', () => {
    const { rows, baseImageRecs } = teamBundleToRows(bundle({
      vulnerabilities: [{ project_id: 'p1', dependency_id: 'd', osv_id: 'CVE-1' }] as any,
      secrets: [{ id: 's1', project_id: 'p1' }] as any,
      semgrep: [{ id: 'sg1', project_id: 'p1' }] as any,
      iac: [{ id: 'i1', project_id: 'p1' }] as any,
      container: [{ id: 'c1', project_id: 'p1' }] as any,
      malicious: [{ id: 'm1', project_id: 'p1' }] as any,
      dast: [{ id: 'd1', project_name: 'P1' }] as any,
      codeFlows: [{ id: 'f1', project_id: 'p1' }] as any,
      baseImageRecs: [{ id: 'r1' }] as any,
    }));
    const types = rows.map((r) => r.type).sort();
    expect(types).toEqual(['container', 'dast', 'iac', 'malicious', 'secret', 'semgrep', 'taint_flow', 'vulnerability']);
    expect(baseImageRecs).toHaveLength(1);
  });

  it('returns empty for an empty bundle', () => {
    const { rows, baseImageRecs } = teamBundleToRows(bundle({}));
    expect(rows).toEqual([]);
    expect(baseImageRecs).toEqual([]);
  });

  it('passes server-stamped project_framework through to row data (org bundle)', () => {
    const { rows } = teamBundleToRows(bundle({
      vulnerabilities: [{ project_id: 'p1', dependency_id: 'd', osv_id: 'CVE-1', project_framework: 'node' }] as any,
      secrets: [{ id: 's1', project_id: 'p1', project_framework: 'go' }] as any,
    }));
    const vuln = rows.find((r) => r.type === 'vulnerability');
    const secret = rows.find((r) => r.type === 'secret');
    expect((vuln!.data as any).project_framework).toBe('node');
    expect((secret!.data as any).project_framework).toBe('go');
  });

  it('does not regress when project_framework is absent (team bundle)', () => {
    const { rows } = teamBundleToRows(bundle({
      vulnerabilities: [{ project_id: 'p1', dependency_id: 'd', osv_id: 'CVE-1' }] as any,
    }));
    const vuln = rows.find((r) => r.type === 'vulnerability');
    expect(vuln).toBeDefined();
    expect((vuln!.data as any).project_framework).toBeUndefined();
  });
});

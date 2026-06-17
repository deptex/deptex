import { describe, it, expect } from 'vitest';
import { autoTriageRow, type SecurityTableRow } from '../VulnerabilityExpandableTable';

/** Build a minimal `vulnerability` row from the fields autoTriageRow reads. */
function vuln(partial: Record<string, unknown>): SecurityTableRow {
  return { type: 'vulnerability', data: { osv_id: 'CVE-x', ...partial } } as unknown as SecurityTableRow;
}

describe('autoTriageRow — Refined/All reachability rules', () => {
  it('keeps confirmed-reachable findings regardless of score', () => {
    expect(autoTriageRow(vuln({ reachability_level: 'confirmed', depscore: 5 }))).toBeNull();
  });

  it('keeps data_flow-reachable findings regardless of score', () => {
    // A real data_flow finding is a strong signal — never set aside, even low-score.
    expect(autoTriageRow(vuln({ reachability_level: 'data_flow', depscore: 20 }))).toBeNull();
    expect(autoTriageRow(vuln({ reachability_level: 'data_flow', depscore: 90 }))).toBeNull();
  });

  it('keeps runtime-confirmed (DAST) findings even when the static verdict is unreachable', () => {
    expect(autoTriageRow(vuln({ runtime_confirmed_at: '2026-06-05', reachability_level: 'unreachable' }))).toBeNull();
  });

  it('sets aside unreachable findings as not_reachable (score is irrelevant)', () => {
    expect(autoTriageRow(vuln({ reachability_level: 'unreachable', depscore: 90 }))?.reason).toBe('not_reachable');
    expect(autoTriageRow(vuln({ is_reachable: false, depscore: 90 }))?.reason).toBe('not_reachable');
  });

  it('sets aside module-only findings as unconfirmed_reachable (the post-engine-fix CVE-2020-28500 case)', () => {
    expect(autoTriageRow(vuln({ reachability_level: 'module', depscore: 20 }))?.reason).toBe('unconfirmed_reachable');
  });

  it('keeps function-level findings — the vulnerable function is called', () => {
    expect(autoTriageRow(vuln({ reachability_level: 'function', depscore: 18 }))).toBeNull();
  });

  it('keeps findings with no reachability verdict — we can’t confidently call them safe', () => {
    expect(autoTriageRow(vuln({ depscore: 5 }))).toBeNull();
    expect(autoTriageRow(vuln({ reachability_level: null, depscore: 90 }))).toBeNull();
  });

  it('sets aside container (base-image) findings as base_image, even critical', () => {
    const container = { type: 'container', data: { id: 'c1', severity: 'CRITICAL' } } as unknown as SecurityTableRow;
    expect(autoTriageRow(container)?.reason).toBe('base_image');
  });

  it('never triages secret or semgrep finding types', () => {
    const secret = { type: 'secret', data: { id: 's1' } } as unknown as SecurityTableRow;
    const semgrep = { type: 'semgrep', data: { id: 'g1' } } as unknown as SecurityTableRow;
    expect(autoTriageRow(secret)).toBeNull();
    expect(autoTriageRow(semgrep)).toBeNull();
  });
});

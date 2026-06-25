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

  it('keeps KEV base-image findings (never set aside)', () => {
    const kev = { type: 'container', data: { id: 'c2', is_kev: true, severity: 'MEDIUM' } } as unknown as SecurityTableRow;
    expect(autoTriageRow(kev)).toBeNull();
  });
});

// Golden-master freeze for the findings-status foundation: these cases pin the
// REAL autoTriageRow's IaC/DAST per-row verdicts — including the cases where the
// phase54 count SQL DISAGREES with the table — before autoTriageRow is replaced
// by the stored `auto_ignored` column. The byte-identical backend contract lives
// in backend/src/lib/findings/triage-golden-master.ts; keep the two in sync.
function iac(data: Record<string, unknown>): SecurityTableRow {
  return { type: 'iac', data: { id: 'i1', ...data } } as unknown as SecurityTableRow;
}
function dast(data: Record<string, unknown>): SecurityTableRow {
  return { type: 'dast', data: { id: 'd1', ...data } } as unknown as SecurityTableRow;
}

describe('autoTriageRow — IaC critical vs hardening (frozen)', () => {
  it('keeps per-rule critical misconfigs open even at LOW severity', () => {
    expect(autoTriageRow(iac({ rule_id: 'CKV_K8S_16', severity: 'LOW' }))).toBeNull();
    expect(autoTriageRow(iac({ rule_id: 'KSV-0023', severity: 'MEDIUM' }))).toBeNull();
  });

  it('sets aside per-rule hardening checks as iac_hardening', () => {
    expect(autoTriageRow(iac({ rule_id: 'CKV_K8S_13', severity: 'MEDIUM' }))?.reason).toBe('iac_hardening');
  });

  it('keeps known hardening rules set aside even at HIGH severity (per-rule wins over severity)', () => {
    expect(autoTriageRow(iac({ rule_id: 'CKV_K8S_22', severity: 'HIGH' }))?.reason).toBe('iac_hardening');
  });

  it('DIVERGENCE: unmapped HIGH/CRITICAL rules stay open via the severity fallback (phase54 hides them)', () => {
    expect(autoTriageRow(iac({ rule_id: 'CKV_AWS_23', severity: 'HIGH' }))).toBeNull();
    expect(autoTriageRow(iac({ rule_id: 'CKV_AWS_999', severity: 'CRITICAL' }))).toBeNull();
  });

  it('sets aside unmapped MEDIUM rules as iac_hardening', () => {
    expect(autoTriageRow(iac({ rule_id: 'CKV_AWS_50', severity: 'MEDIUM' }))?.reason).toBe('iac_hardening');
  });
});

describe('autoTriageRow — DAST passive vs active (frozen)', () => {
  it('sets aside passive checks (no payload, low/info severity) as passive_hygiene', () => {
    expect(autoTriageRow(dast({ severity: 'low', payload_redacted: null }))?.reason).toBe('passive_hygiene');
    expect(autoTriageRow(dast({ severity: 'info', payload_redacted: '' }))?.reason).toBe('passive_hygiene');
  });

  it('keeps exploited findings (a payload was injected) open even at low severity', () => {
    expect(autoTriageRow(dast({ severity: 'low', payload_redacted: "' OR 1=1--" }))).toBeNull();
  });

  it('keeps high/critical-severity findings open', () => {
    expect(autoTriageRow(dast({ severity: 'high', payload_redacted: null }))).toBeNull();
    expect(autoTriageRow(dast({ severity: 'critical', payload_redacted: '   ' }))).toBeNull();
  });
});

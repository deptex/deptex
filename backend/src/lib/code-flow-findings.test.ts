import {
  flowVulnClassLabel,
  flowSeverity,
  firstPartyFlowDepscore,
  toDataFlowFinding,
} from './code-flow-findings';

describe('code-flow-findings scoring', () => {
  it('bands injection / deserialization classes critical (>= 90)', () => {
    for (const vc of ['sql_injection', 'command_injection', 'code_injection', 'deserialization']) {
      expect(flowSeverity(vc)).toBe('critical');
      expect(firstPartyFlowDepscore(vc)).toBeGreaterThanOrEqual(90);
    }
  });

  it('bands xss / ssrf / traversal / upload / proto / auth high (70–89)', () => {
    for (const vc of ['xss', 'ssrf', 'path_traversal', 'file_upload', 'prototype_pollution', 'auth_bypass']) {
      expect(flowSeverity(vc)).toBe('high');
      const s = firstPartyFlowDepscore(vc);
      expect(s).toBeGreaterThanOrEqual(70);
      expect(s).toBeLessThan(90);
    }
  });

  it('bands the softer classes medium (40–69)', () => {
    for (const vc of ['open_redirect', 'redos', 'log_injection', 'weak_crypto']) {
      expect(flowSeverity(vc)).toBe('medium');
      const s = firstPartyFlowDepscore(vc);
      expect(s).toBeGreaterThanOrEqual(40);
      expect(s).toBeLessThan(70);
    }
  });

  it('falls back to a medium "Tainted data flow" for null/unknown vuln_class', () => {
    expect(flowVulnClassLabel(null)).toBe('Tainted data flow');
    expect(flowVulnClassLabel(undefined)).toBe('Tainted data flow');
    expect(flowSeverity('not-a-real-class')).toBe('medium');
    expect(firstPartyFlowDepscore(undefined)).toBe(55);
  });

  it('labels classes for humans', () => {
    expect(flowVulnClassLabel('xss')).toMatch(/Cross-site scripting/);
    expect(flowVulnClassLabel('sql_injection')).toBe('SQL injection');
    expect(flowVulnClassLabel('ssrf')).toMatch(/Server-side request forgery/);
  });

  it('maps a raw flow row to the finding DTO with derived title/severity/depscore', () => {
    const dto = toDataFlowFinding({
      id: 'flow-1',
      project_id: 'proj-1',
      extraction_run_id: 'run-1',
      vuln_class: 'xss',
      entry_point_file: 'app/page.tsx',
      entry_point_line: 10,
      entry_point_method: 'Page',
      entry_point_tag: 'framework-input:PUBLIC_UNAUTH',
      sink_file: 'app/page.tsx',
      sink_line: 16,
      sink_method: 'dangerouslySetInnerHTML',
      flow_length: 10,
      flow_nodes: [{ kind: 'source', label: 'searchParams.msg' }],
      flow_signature_hash: 'abc',
      created_at: '2026-06-17T00:00:00Z',
    });
    expect(dto.title).toMatch(/Cross-site scripting/);
    expect(dto.severity).toBe('high');
    // xss base 78, minus a depth nudge of 2 for a deep (10-hop) flow → 76.
    expect(dto.depscore).toBe(76);
    expect(dto.vuln_class).toBe('xss');
    expect(dto.sink_method).toBe('dangerouslySetInnerHTML');
    expect(Array.isArray(dto.flow_nodes)).toBe(true);
  });

  it('defaults missing flow_nodes to an empty array (never undefined)', () => {
    const dto = toDataFlowFinding({ id: 'x', project_id: 'p', extraction_run_id: 'r' });
    expect(dto.flow_nodes).toEqual([]);
    expect(dto.vuln_class).toBeNull();
    expect(dto.title).toBe('Tainted data flow');
  });

  // Drift guard: phase54_security_summary_code_flows.sql hard-codes these exact
  // *bare-class* scores in its vuln_class CASE. The depth nudge below is a
  // TS-only, within-band spread the SQL doesn't mirror — so the bare-class
  // values must stay put. If these change, update that migration too.
  it('keeps the bare-class band scores the count-pills SQL mirrors', () => {
    expect(firstPartyFlowDepscore('sql_injection')).toBe(92);
    expect(firstPartyFlowDepscore('xss')).toBe(78);
    expect(firstPartyFlowDepscore('open_redirect')).toBe(55);
  });

  it('spreads same-class flows by path depth but never leaves the band', () => {
    const shallow = firstPartyFlowDepscore('sql_injection', 2);  // direct path
    const mid = firstPartyFlowDepscore('sql_injection', 5);
    const deep = firstPartyFlowDepscore('sql_injection', 14);    // long winding path
    expect(shallow).toBeGreaterThan(mid);
    expect(mid).toBeGreaterThanOrEqual(deep);
    expect(shallow).toBe(95);
    expect(deep).toBeGreaterThanOrEqual(90); // clamped to the critical ramp floor
    // a deep XSS dips but stays in the high band (never reads as critical/medium)
    const deepXss = firstPartyFlowDepscore('xss', 14);
    expect(deepXss).toBeGreaterThanOrEqual(70);
    expect(deepXss).toBeLessThan(90);
  });
});

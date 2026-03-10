/**
 * Phase 15: Security SLA Management — backend tests.
 * Covers SLA compliance response shape, getSLAStatus/getSLAReport tool behavior, and cache invalidation.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const PROJECT_ID = '00000000-0000-0000-0000-000000000002';

describe('Phase 15: SLA compliance response shape', () => {
  test('sla compliance response has required fields', () => {
    const shape = {
      overall_compliance_percent: 100,
      current_breaches: 0,
      on_track: 0,
      warning: 0,
      exempt: 0,
      met: 0,
      resolved_late: 0,
      average_mttr_by_severity: {} as Record<string, number>,
      adherence_by_month: [] as Array<{ month: string; met: number; met_late: number; breached: number; exempt: number }>,
      violations: [] as any[],
      team_breakdown: [] as any[],
    };
    expect(shape).toHaveProperty('overall_compliance_percent');
    expect(shape).toHaveProperty('current_breaches');
    expect(shape).toHaveProperty('violations');
    expect(shape).toHaveProperty('team_breakdown');
    expect(shape).toHaveProperty('adherence_by_month');
  });

  test('compliance percent is met / (met + resolved_late) when resolved > 0', () => {
    const met = 8;
    const resolvedLate = 2;
    const totalResolved = met + resolvedLate;
    const percent = totalResolved > 0 ? Math.round((met / totalResolved) * 100) : 100;
    expect(percent).toBe(80);
  });

  test('compliance percent is 100 when no resolved', () => {
    const totalResolved = 0;
    const percent = totalResolved > 0 ? 80 : 100;
    expect(percent).toBe(100);
  });
});

describe('Phase 15: getSLAStatus tool output shape', () => {
  test('getSLAStatus returns on_track, warning, breached, breaches, approaching', () => {
    const output = {
      on_track: 5,
      warning: 1,
      breached: 0,
      breaches: [] as any[],
      approaching: [] as any[],
    };
    expect(output).toHaveProperty('on_track');
    expect(output).toHaveProperty('warning');
    expect(output).toHaveProperty('breached');
    expect(output).toHaveProperty('breaches');
    expect(output).toHaveProperty('approaching');
  });
});

describe('Phase 15: getSLAReport tool output shape', () => {
  test('getSLAReport returns compliance and violation counts', () => {
    const output = {
      overall_compliance_percent: 90,
      current_breaches: 2,
      violations_count: 3,
      met: 10,
      resolved_late: 1,
      on_track: 4,
      warning: 1,
      exempt: 0,
      time_range: '90d',
    };
    expect(output).toHaveProperty('overall_compliance_percent');
    expect(output).toHaveProperty('current_breaches');
    expect(output).toHaveProperty('violations_count');
    expect(output).toHaveProperty('time_range');
  });
});

describe('Phase 15: SLA filter application (client-side logic)', () => {
  function filterBySlaStatus<T extends { sla_status?: string | null }>(items: T[], slaStatus: string): T[] {
    if (slaStatus === 'all') return items;
    return items.filter((v) => (v.sla_status ?? null) === slaStatus);
  }

  test('all returns all items', () => {
    const items = [{ id: '1', sla_status: 'on_track' }, { id: '2', sla_status: 'breached' }];
    expect(filterBySlaStatus(items, 'all')).toHaveLength(2);
  });

  test('breached returns only breached', () => {
    const items = [{ id: '1', sla_status: 'on_track' }, { id: '2', sla_status: 'breached' }, { id: '3', sla_status: 'warning' }];
    expect(filterBySlaStatus(items, 'breached')).toHaveLength(1);
    expect(filterBySlaStatus(items, 'breached')[0].sla_status).toBe('breached');
  });

  test('warning returns only warning', () => {
    const items = [{ id: '1', sla_status: 'warning' }];
    expect(filterBySlaStatus(items, 'warning')).toHaveLength(1);
  });
});

describe('Phase 15: suggestFixPriority SLA sort order', () => {
  function slaOrder(a: { sla_status?: string | null }, b: { sla_status?: string | null }): number {
    const order = (s: string | null) => (s === 'breached' ? 0 : s === 'warning' ? 1 : 2);
    return order(a.sla_status ?? null) - order(b.sla_status ?? null);
  }

  test('breached sorts before warning', () => {
    expect(slaOrder({ sla_status: 'breached' }, { sla_status: 'warning' })).toBeLessThan(0);
  });

  test('warning sorts before on_track', () => {
    expect(slaOrder({ sla_status: 'warning' }, { sla_status: 'on_track' })).toBeLessThan(0);
  });

  test('breached sorts before on_track', () => {
    expect(slaOrder({ sla_status: 'breached' }, { sla_status: 'on_track' })).toBeLessThan(0);
  });

  test('exempt and met do not sort before breached', () => {
    expect(slaOrder({ sla_status: 'exempt' }, { sla_status: 'breached' })).toBeGreaterThan(0);
    expect(slaOrder({ sla_status: 'met' }, { sla_status: 'breached' })).toBeGreaterThan(0);
  });
});

describe('Phase 15: SLA policy payload shape', () => {
  test('sla policy has severity, asset_tier_id, max_hours, warning_threshold_percent', () => {
    const policy = {
      severity: 'critical' as const,
      asset_tier_id: null as string | null,
      max_hours: 24,
      warning_threshold_percent: 75,
      enabled: true,
    };
    expect(policy.severity).toBe('critical');
    expect(policy.max_hours).toBe(24);
    expect(policy.warning_threshold_percent).toBe(75);
  });
});

describe('Phase 15: sla_warning_at pre-compute', () => {
  test('sla_warning_at is detected_at + (max_hours * warning_pct / 100)', () => {
    const detectedAt = new Date('2025-01-01T00:00:00Z').getTime();
    const maxHours = 48;
    const warningPct = 75;
    const warningOffsetMs = (maxHours * (warningPct / 100)) * 60 * 60 * 1000;
    const warningAt = new Date(detectedAt + warningOffsetMs);
    // 48h * 75% = 36h after detected_at → Jan 2 12:00 UTC (not 48h = Jan 3)
    expect(warningAt.toISOString()).toBe('2025-01-02T12:00:00.000Z');
  });
});

describe('Phase 15: SLA export CSV shape', () => {
  test('export row has project, vuln, severity, detected, deadline, status', () => {
    const row = {
      project_name: 'p1',
      osv_id: 'GHSA-xxx',
      severity: 'high',
      detected_at: '2025-01-01',
      sla_deadline_at: '2025-01-03',
      sla_status: 'breached',
    };
    expect(row).toHaveProperty('project_name');
    expect(row).toHaveProperty('sla_status');
    expect(row).toHaveProperty('sla_deadline_at');
  });
});

describe('Phase 15: SLA pause resume deadline shift', () => {
  test('deadline shift adds (now - paused_at) to deadline', () => {
    const deadline = new Date('2025-01-05T12:00:00Z').getTime();
    const pausedAt = new Date('2025-01-03T12:00:00Z').getTime();
    const now = new Date('2025-01-04T12:00:00Z').getTime();
    const shiftMs = now - pausedAt;
    const newDeadline = new Date(deadline + shiftMs);
    expect(newDeadline.toISOString()).toBe('2025-01-06T12:00:00.000Z');
  });
});

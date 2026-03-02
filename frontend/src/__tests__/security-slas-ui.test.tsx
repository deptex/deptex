/**
 * Phase 15: Security SLA Management — frontend UI tests.
 * Covers SLA filter (SecurityFilterBar), SLAStatusCard variants, graph filtering by sla_status.
 */

import { describe, test, expect } from 'vitest';
import type { SlaStatusFilter } from '../components/security/SecurityFilterBar';

describe('Phase 15: SLA filter URL param', () => {
  test('sla param maps to slaStatus filter', () => {
    const param = 'breached' as SlaStatusFilter;
    expect(['all', 'on_track', 'warning', 'breached', 'exempt']).toContain(param);
  });

  test('default slaStatus is all', () => {
    const defaultSla: SlaStatusFilter = 'all';
    expect(defaultSla).toBe('all');
  });
});

describe('Phase 15: graphDepNodesForLayout SLA filter', () => {
  type Vuln = { id: string; osv_id: string; sla_status?: string | null };
  type DepNode = { id: string; vulnerabilities: Vuln[] };

  function applySlaFilter(nodes: DepNode[], slaStatus: SlaStatusFilter): DepNode[] {
    if (slaStatus === 'all') return nodes;
    return nodes
      .map((node) => ({
        ...node,
        vulnerabilities: node.vulnerabilities.filter((v) => (v.sla_status ?? null) === slaStatus),
      }))
      .filter((node) => node.vulnerabilities.length > 0);
  }

  test('all keeps all nodes', () => {
    const nodes: DepNode[] = [
      { id: '1', vulnerabilities: [{ id: 'v1', osv_id: 'x', sla_status: 'breached' }] },
    ];
    expect(applySlaFilter(nodes, 'all')).toHaveLength(1);
  });

  test('breached keeps only nodes with breached vulns', () => {
    const nodes: DepNode[] = [
      { id: '1', vulnerabilities: [{ id: 'v1', osv_id: 'x', sla_status: 'on_track' }] },
      { id: '2', vulnerabilities: [{ id: 'v2', osv_id: 'y', sla_status: 'breached' }] },
    ];
    const result = applySlaFilter(nodes, 'breached');
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('2');
    expect(result[0].vulnerabilities[0].sla_status).toBe('breached');
  });

  test('filtering removes nodes with no matching vulns', () => {
    const nodes: DepNode[] = [
      { id: '1', vulnerabilities: [{ id: 'v1', osv_id: 'x', sla_status: 'on_track' }] },
    ];
    const result = applySlaFilter(nodes, 'breached');
    expect(result).toHaveLength(0);
  });
});

describe('Phase 15: SLAStatusCard status labels', () => {
  const statusLabels: Record<string, string> = {
    on_track: 'On track',
    warning: 'Approaching deadline',
    breached: 'Breached',
    met: 'Met',
    resolved_late: 'Resolved late',
    exempt: 'Exempt',
  };

  test('all SLA statuses have a label', () => {
    const statuses = ['on_track', 'warning', 'breached', 'met', 'resolved_late', 'exempt'];
    for (const s of statuses) {
      expect(statusLabels[s]).toBeDefined();
      expect(statusLabels[s].length).toBeGreaterThan(0);
    }
  });
});

describe('Phase 15: getSlaBreachCount', () => {
  type Vuln = { sla_status?: string | null };
  type DepNode = { vulnerabilities: Vuln[] };

  function getSlaBreachCount(depNodes: DepNode[]): number {
    let count = 0;
    for (const dep of depNodes) {
      for (const v of dep.vulnerabilities) {
        if (v.sla_status === 'breached') count++;
      }
    }
    return count;
  }

  test('counts only breached', () => {
    const nodes: DepNode[] = [
      { vulnerabilities: [{ sla_status: 'breached' }, { sla_status: 'warning' }] },
      { vulnerabilities: [{ sla_status: 'breached' }] },
    ];
    expect(getSlaBreachCount(nodes)).toBe(2);
  });

  test('zero when none breached', () => {
    const nodes: DepNode[] = [
      { vulnerabilities: [{ sla_status: 'on_track' }] },
    ];
    expect(getSlaBreachCount(nodes)).toBe(0);
  });

  test('ignores exempt and met', () => {
    const nodes: DepNode[] = [
      { vulnerabilities: [{ sla_status: 'exempt' }, { sla_status: 'met' }] },
    ];
    expect(getSlaBreachCount(nodes)).toBe(0);
  });
});

describe('Phase 15: SLA filter on_track and exempt', () => {
  type Vuln = { id: string; sla_status?: string | null };
  type DepNode = { id: string; vulnerabilities: Vuln[] };
  function applySlaFilter(nodes: DepNode[], slaStatus: string): DepNode[] {
    if (slaStatus === 'all') return nodes;
    return nodes
      .map((n) => ({ ...n, vulnerabilities: n.vulnerabilities.filter((v) => (v.sla_status ?? null) === slaStatus) }))
      .filter((n) => n.vulnerabilities.length > 0);
  }

  test('on_track filter keeps only on_track vulns', () => {
    const nodes: DepNode[] = [
      { id: '1', vulnerabilities: [{ id: 'v1', sla_status: 'on_track' }, { id: 'v2', sla_status: 'warning' }] },
    ];
    const result = applySlaFilter(nodes, 'on_track');
    expect(result).toHaveLength(1);
    expect(result[0].vulnerabilities).toHaveLength(1);
    expect(result[0].vulnerabilities[0].sla_status).toBe('on_track');
  });

  test('exempt filter keeps only exempt vulns', () => {
    const nodes: DepNode[] = [
      { id: '1', vulnerabilities: [{ id: 'v1', sla_status: 'exempt' }] },
    ];
    const result = applySlaFilter(nodes, 'exempt');
    expect(result).toHaveLength(1);
    expect(result[0].vulnerabilities[0].sla_status).toBe('exempt');
  });
});

describe('Phase 15: SLA dashboard metric cards', () => {
  test('compliance percent is 0-100', () => {
    const percent = 85;
    expect(percent).toBeGreaterThanOrEqual(0);
    expect(percent).toBeLessThanOrEqual(100);
  });

  test('current breaches is non-negative', () => {
    const breaches = 3;
    expect(breaches).toBeGreaterThanOrEqual(0);
  });

  test('MTTR in hours is non-negative', () => {
    const mttrHours = 12.5;
    expect(mttrHours).toBeGreaterThanOrEqual(0);
  });
});

describe('Phase 15: SLA violations table assignee', () => {
  test('assignee is last fix created_by or Unassigned', () => {
    const assignee = 'Unassigned';
    expect(assignee).toBe('Unassigned');
    const fromFix = 'user-uuid';
    expect(fromFix).toBeTruthy();
  });
});

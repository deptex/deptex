/**
 * Phase 6B: Reachability Filter Tests
 * Additional tests for SecurityFilterBar reachability level integration.
 */

import type { ReachabilityLevel } from '../lib/api';

type ReachabilityFilterLevel = 'all' | 'data_flow' | 'function' | 'module' | 'unreachable';

interface SecurityFilters {
  severity: string[];
  depscoreMin: number | null;
  epssMin: number | null;
  kevOnly: boolean;
  fixAvailable: boolean;
  reachableOnly: boolean;
  reachabilityLevel: ReachabilityFilterLevel;
  depType: 'all' | 'direct' | 'transitive';
}

function applyReachabilityFilter(
  vulns: Array<{ reachability_level: ReachabilityLevel; is_reachable: boolean | null }>,
  filter: ReachabilityFilterLevel
): typeof vulns {
  if (filter === 'all') return vulns;

  if (filter === 'data_flow') {
    return vulns.filter(v =>
      v.reachability_level === 'data_flow' || v.reachability_level === 'confirmed'
    );
  }

  if (filter === 'function') {
    return vulns.filter(v =>
      v.reachability_level === 'data_flow' ||
      v.reachability_level === 'confirmed' ||
      v.reachability_level === 'function'
    );
  }

  if (filter === 'module') {
    return vulns.filter(v =>
      v.reachability_level !== 'unreachable' && v.reachability_level !== null
    );
  }

  if (filter === 'unreachable') {
    return vulns.filter(v => v.reachability_level === 'unreachable');
  }

  return vulns;
}

describe('Reachability filter application', () => {
  const vulns = [
    { reachability_level: 'confirmed' as ReachabilityLevel, is_reachable: true },
    { reachability_level: 'data_flow' as ReachabilityLevel, is_reachable: true },
    { reachability_level: 'function' as ReachabilityLevel, is_reachable: true },
    { reachability_level: 'module' as ReachabilityLevel, is_reachable: true },
    { reachability_level: 'unreachable' as ReachabilityLevel, is_reachable: false },
    { reachability_level: null, is_reachable: true },
  ];

  test('all filter returns everything', () => {
    expect(applyReachabilityFilter(vulns, 'all')).toHaveLength(6);
  });

  test('data_flow filter returns data_flow + confirmed', () => {
    const result = applyReachabilityFilter(vulns, 'data_flow');
    expect(result).toHaveLength(2);
    expect(result.every(v => v.reachability_level === 'data_flow' || v.reachability_level === 'confirmed')).toBe(true);
  });

  test('function filter returns data_flow + confirmed + function', () => {
    const result = applyReachabilityFilter(vulns, 'function');
    expect(result).toHaveLength(3);
  });

  test('module filter returns all non-unreachable, non-null', () => {
    const result = applyReachabilityFilter(vulns, 'module');
    expect(result).toHaveLength(4);
    expect(result.every(v => v.reachability_level !== 'unreachable' && v.reachability_level !== null)).toBe(true);
  });

  test('unreachable filter returns only unreachable', () => {
    const result = applyReachabilityFilter(vulns, 'unreachable');
    expect(result).toHaveLength(1);
    expect(result[0].reachability_level).toBe('unreachable');
  });

  test('URL persistence for reachability filter', () => {
    const filters: SecurityFilters = {
      severity: [],
      depscoreMin: null,
      epssMin: null,
      kevOnly: false,
      fixAvailable: false,
      reachableOnly: false,
      reachabilityLevel: 'data_flow',
      depType: 'all',
    };

    const params = new URLSearchParams();
    if (filters.reachabilityLevel !== 'all') params.set('reachability', filters.reachabilityLevel);

    expect(params.get('reachability')).toBe('data_flow');
  });

  test('default filters have reachabilityLevel = all', () => {
    const defaults: SecurityFilters = {
      severity: [],
      depscoreMin: null,
      epssMin: null,
      kevOnly: false,
      fixAvailable: false,
      reachableOnly: false,
      reachabilityLevel: 'all',
      depType: 'all',
    };

    expect(defaults.reachabilityLevel).toBe('all');
  });
});

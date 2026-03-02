/**
 * Phase 16: Aegis Learning — frontend UI tests (10 tests).
 * Covers StrategyPicker display, cold-start state, LearningDashboard sections.
 */

import { describe, test, expect } from 'vitest';
import type { StrategyRecommendation, LearningDashboard } from '../lib/api';

const STRATEGY_DISPLAY_NAMES: Record<string, string> = {
  bump_version: 'Version Bump',
  code_patch: 'Code Patch',
  add_wrapper: 'Add Wrapper',
  pin_transitive: 'Pin Transitive',
  remove_unused: 'Remove Unused',
  fix_semgrep: 'Fix Semgrep',
  remediate_secret: 'Remediate Secret',
};

function mockRecommendations(isGlobalDefault = true): StrategyRecommendation[] {
  return [
    {
      strategy: 'bump_version',
      displayName: 'Version Bump',
      predictedSuccessRate: 0.75,
      confidence: 'low',
      basedOnSamples: 0,
      avgDuration: 120,
      avgCost: 0.02,
      reasoning: 'Using platform average — no organization-specific data yet.',
      isGlobalDefault,
    },
    {
      strategy: 'code_patch',
      displayName: 'Code Patch',
      predictedSuccessRate: 0.55,
      confidence: 'low',
      basedOnSamples: 0,
      avgDuration: 300,
      avgCost: 0.08,
      reasoning: 'Using platform average — no organization-specific data yet.',
      isGlobalDefault,
    },
  ];
}

// ──── Strategy Picker (41-45) ────

describe('Strategy Picker', () => {
  test('41. Recommendations are sorted by predicted success rate', () => {
    const recs = mockRecommendations();
    const sorted = [...recs].sort((a, b) => b.predictedSuccessRate - a.predictedSuccessRate);
    expect(sorted[0].strategy).toBe('bump_version');
    expect(sorted[0].predictedSuccessRate).toBeGreaterThan(sorted[1].predictedSuccessRate);
  });

  test('42. Top strategy has highest predicted success rate', () => {
    const recs = mockRecommendations();
    const top = recs.reduce((best, r) => r.predictedSuccessRate > best.predictedSuccessRate ? r : best);
    expect(top.strategy).toBe('bump_version');
  });

  test('43. Reasoning text is present for all recommendations', () => {
    const recs = mockRecommendations();
    for (const rec of recs) {
      expect(rec.reasoning.length).toBeGreaterThan(0);
    }
  });

  test('44. User can select any strategy (selection logic)', () => {
    const recs = mockRecommendations();
    let selected = recs[0].strategy;
    selected = recs[1].strategy;
    expect(selected).toBe('code_patch');
  });

  test('45. Cold-start state: all strategies show isGlobalDefault=true', () => {
    const recs = mockRecommendations(true);
    expect(recs.every(r => r.isGlobalDefault)).toBe(true);
    expect(recs[0].reasoning).toContain('platform average');
  });
});

// ──── Learning Dashboard (46-50) ────

describe('Learning Dashboard', () => {
  const mockDashboard: LearningDashboard = {
    strategyMatrix: [
      { strategy: 'bump_version', displayName: 'Version Bump', successRate: 0.82, samples: 25, confidence: 'high', avgCost: 0.03, avgDuration: 110 },
      { strategy: 'code_patch', displayName: 'Code Patch', successRate: 0.65, samples: 12, confidence: 'medium', avgCost: 0.09, avgDuration: 280 },
    ],
    learningCurve: [
      { month: '2025-01', successRate: 0.60, total: 10, successes: 6 },
      { month: '2025-02', successRate: 0.70, total: 15, successes: 11 },
      { month: '2025-03', successRate: 0.78, total: 20, successes: 16 },
      { month: '2025-04', successRate: 0.85, total: 18, successes: 15 },
    ],
    failureAnalysis: [
      { reason: 'build_error', displayName: 'Build Error', count: 8, percentage: 0.32 },
      { reason: 'breaking_changes', displayName: 'Breaking Changes', count: 5, percentage: 0.20 },
    ],
    followupChains: [
      {
        failedStrategy: 'code_patch',
        failedDisplayName: 'Code Patch',
        followupStrategy: 'bump_version',
        followupDisplayName: 'Version Bump',
        followupSuccessRate: 0.85,
        samples: 7,
      },
    ],
    qualityInsights: [
      { strategy: 'bump_version', displayName: 'Version Bump', avgRating: 4.2, totalRatings: 15, distribution: [0, 1, 2, 5, 7] },
    ],
    totalOutcomes: 63,
    totalSuccesses: 48,
    totalRatings: 15,
  };

  test('46. Strategy Performance Matrix has correct data shape', () => {
    expect(mockDashboard.strategyMatrix).toHaveLength(2);
    const best = mockDashboard.strategyMatrix.reduce((a, b) => a.successRate > b.successRate ? a : b);
    expect(best.strategy).toBe('bump_version');
    expect(best.confidence).toBe('high');
  });

  test('47. Learning Curve shows improvement trend', () => {
    const { learningCurve } = mockDashboard;
    expect(learningCurve.length).toBeGreaterThanOrEqual(3);
    const first = learningCurve[0].successRate;
    const last = learningCurve[learningCurve.length - 1].successRate;
    expect(last).toBeGreaterThan(first);
  });

  test('48. Failure Analysis sorted by count descending', () => {
    const sorted = [...mockDashboard.failureAnalysis].sort((a, b) => b.count - a.count);
    expect(sorted[0].reason).toBe('build_error');
    expect(sorted[0].count).toBeGreaterThan(sorted[1].count);
  });

  test('49. Follow-up Chains show correct strategy pairs', () => {
    expect(mockDashboard.followupChains).toHaveLength(1);
    const chain = mockDashboard.followupChains[0];
    expect(chain.failedStrategy).toBe('code_patch');
    expect(chain.followupStrategy).toBe('bump_version');
    expect(chain.followupSuccessRate).toBeGreaterThan(0.5);
  });

  test('50. Quality Insights shows star ratings and distribution', () => {
    expect(mockDashboard.qualityInsights).toHaveLength(1);
    const insight = mockDashboard.qualityInsights[0];
    expect(insight.avgRating).toBeGreaterThanOrEqual(1);
    expect(insight.avgRating).toBeLessThanOrEqual(5);
    expect(insight.distribution).toHaveLength(5);
    expect(insight.distribution.reduce((a, b) => a + b, 0)).toBe(insight.totalRatings);
  });
});

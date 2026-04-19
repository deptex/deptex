import { supabase } from '../../../../backend/src/lib/supabase';
import { getCached, setCached } from '../cache';
import { CANONICAL_STRATEGIES, STRATEGY_DISPLAY_NAMES } from './strategy-constants';

export interface StrategyRecommendation {
  strategy: string;
  displayName: string;
  predictedSuccessRate: number;
  confidence: 'low' | 'medium' | 'high';
  basedOnSamples: number;
  avgDuration: number;
  avgCost: number;
  reasoning: string;
  warnings?: string[];
  isGlobalDefault: boolean;
}

const GLOBAL_DEFAULTS: Record<string, number> = {
  bump_version: 0.75,
  pin_transitive: 0.70,
  remove_unused: 0.90,
  code_patch: 0.55,
  add_wrapper: 0.50,
  fix_semgrep: 0.65,
  remediate_secret: 0.85,
};

const CONFIDENCE_MULTIPLIER: Record<string, number> = {
  high: 1.0,
  medium: 0.8,
  low: 0.5,
};

const DEFAULT_DURATIONS: Record<string, number> = {
  bump_version: 120,
  code_patch: 300,
  add_wrapper: 240,
  pin_transitive: 90,
  remove_unused: 60,
  fix_semgrep: 180,
  remediate_secret: 150,
};

const DEFAULT_COSTS: Record<string, number> = {
  bump_version: 0.02,
  code_patch: 0.08,
  add_wrapper: 0.06,
  pin_transitive: 0.01,
  remove_unused: 0.01,
  fix_semgrep: 0.05,
  remediate_secret: 0.04,
};

export async function recommendStrategies(
  orgId: string,
  ecosystem: string,
  vulnType: string | null,
  isDirect: boolean,
  fixType: 'vulnerability' | 'semgrep' | 'secret',
): Promise<StrategyRecommendation[]> {
  const cacheKey = `strategy-recs:${orgId}:${ecosystem}:${vulnType || 'any'}:${isDirect}:${fixType}`;
  const cached = await getCached<StrategyRecommendation[]>(cacheKey);
  if (cached) return cached;

  const available = fixType === 'semgrep' ? ['fix_semgrep'] :
                    fixType === 'secret' ? ['remediate_secret'] :
                    ['bump_version', 'code_patch', 'add_wrapper', 'pin_transitive', 'remove_unused'];

  const recommendations: StrategyRecommendation[] = [];

  for (const strategy of available) {
    const pattern = await findBestPattern(orgId, ecosystem, vulnType, isDirect, strategy);

    if (pattern) {
      const revertPenalty = (pattern.revert_rate || 0) * 0.5;
      const effectiveRate = Math.max(0, (pattern.success_rate || 0) - revertPenalty);
      const warnings: string[] = [];

      if ((pattern.revert_rate || 0) > 0.10) {
        warnings.push(`High revert rate (${Math.round((pattern.revert_rate || 0) * 100)}%) after merge`);
      }
      if (pattern.common_failure_reasons) {
        const topFailure = Object.entries(pattern.common_failure_reasons)
          .sort(([, a], [, b]) => (b as number) - (a as number))[0];
        if (topFailure && (topFailure[1] as number) >= 3) {
          warnings.push(`Common failure: ${topFailure[0].replace(/_/g, ' ')} (${topFailure[1]}x)`);
        }
      }

      const confidence = pattern.confidence as 'low' | 'medium' | 'high';
      recommendations.push({
        strategy,
        displayName: STRATEGY_DISPLAY_NAMES[strategy] || strategy,
        predictedSuccessRate: effectiveRate,
        confidence,
        basedOnSamples: pattern.sample_count || 0,
        avgDuration: pattern.avg_duration_seconds || DEFAULT_DURATIONS[strategy] || 180,
        avgCost: pattern.avg_cost != null ? Number(pattern.avg_cost) : (DEFAULT_COSTS[strategy] || 0.05),
        reasoning: buildReasoning(strategy, pattern, effectiveRate),
        warnings: warnings.length > 0 ? warnings : undefined,
        isGlobalDefault: false,
      });
    } else {
      recommendations.push({
        strategy,
        displayName: STRATEGY_DISPLAY_NAMES[strategy] || strategy,
        predictedSuccessRate: GLOBAL_DEFAULTS[strategy] || 0.50,
        confidence: 'low',
        basedOnSamples: 0,
        avgDuration: DEFAULT_DURATIONS[strategy] || 180,
        avgCost: DEFAULT_COSTS[strategy] || 0.05,
        reasoning: 'Using platform average — no organization-specific data yet.',
        isGlobalDefault: true,
      });
    }
  }

  recommendations.sort((a, b) => {
    const scoreA = a.predictedSuccessRate * CONFIDENCE_MULTIPLIER[a.confidence];
    const scoreB = b.predictedSuccessRate * CONFIDENCE_MULTIPLIER[b.confidence];

    if (Math.abs(scoreA - scoreB) < 0.05) {
      return a.avgCost - b.avgCost;
    }
    return scoreB - scoreA;
  });

  await setCached(cacheKey, recommendations, 300);
  return recommendations;
}

async function findBestPattern(
  orgId: string,
  ecosystem: string,
  vulnType: string | null,
  isDirect: boolean,
  strategy: string,
): Promise<any | null> {
  // Level 1: most specific
  if (vulnType) {
    const { data } = await supabase
      .from('strategy_patterns')
      .select('*')
      .eq('organization_id', orgId)
      .eq('ecosystem', ecosystem)
      .eq('vulnerability_type', vulnType)
      .eq('strategy', strategy)
      .eq('is_direct_dep', isDirect)
      .maybeSingle();
    if (data) return data;
  }

  // Level 1b: ecosystem + vulnType + strategy (no isDirect)
  if (vulnType) {
    const { data } = await supabase
      .from('strategy_patterns')
      .select('*')
      .eq('organization_id', orgId)
      .eq('ecosystem', ecosystem)
      .eq('vulnerability_type', vulnType)
      .eq('strategy', strategy)
      .is('is_direct_dep', null)
      .maybeSingle();
    if (data) return data;
  }

  // Level 2: ecosystem + strategy
  const { data: l2 } = await supabase
    .from('strategy_patterns')
    .select('*')
    .eq('organization_id', orgId)
    .eq('ecosystem', ecosystem)
    .is('vulnerability_type', null)
    .eq('strategy', strategy)
    .is('is_direct_dep', null)
    .maybeSingle();
  if (l2) return l2;

  // Level 3: strategy only (org-wide)
  const { data: l3 } = await supabase
    .from('strategy_patterns')
    .select('*')
    .eq('organization_id', orgId)
    .is('ecosystem', null)
    .is('vulnerability_type', null)
    .eq('strategy', strategy)
    .is('is_direct_dep', null)
    .maybeSingle();
  return l3 || null;
}

function buildReasoning(strategy: string, pattern: any, effectiveRate: number): string {
  const pct = Math.round(effectiveRate * 100);
  const name = STRATEGY_DISPLAY_NAMES[strategy] || strategy;
  const conf = pattern.confidence;
  const samples = pattern.sample_count || 0;

  let reasoning = `${name} has a ${pct}% success rate based on ${samples} attempts (${conf} confidence).`;

  if (pattern.avg_quality_rating) {
    reasoning += ` Average quality rating: ${Number(pattern.avg_quality_rating).toFixed(1)}/5.`;
  }

  if (pattern.best_followup_strategy && pattern.followup_success_rate) {
    const followupPct = Math.round(Number(pattern.followup_success_rate) * 100);
    const followupName = STRATEGY_DISPLAY_NAMES[pattern.best_followup_strategy] || pattern.best_followup_strategy;
    reasoning += ` If this fails, ${followupName} succeeds ${followupPct}% of the time as a follow-up.`;
  }

  return reasoning;
}

export async function getDashboardData(orgId: string, timeRange?: string) {
  const timeFilter = timeRange === '30d' ? 30 :
                     timeRange === '90d' ? 90 : null;
  const sinceDate = timeFilter
    ? new Date(Date.now() - timeFilter * 24 * 60 * 60 * 1000).toISOString()
    : null;

  let outcomesQuery = supabase
    .from('fix_outcomes')
    .select('*')
    .eq('organization_id', orgId)
    .order('created_at', { ascending: true });

  if (sinceDate) {
    outcomesQuery = outcomesQuery.gte('created_at', sinceDate);
  }

  const [{ data: outcomes }, { data: patterns }] = await Promise.all([
    outcomesQuery,
    supabase.from('strategy_patterns').select('*').eq('organization_id', orgId),
  ]);

  const allOutcomes = outcomes || [];
  const allPatterns = patterns || [];

  // Strategy Performance Matrix
  const strategyMatrix = allPatterns
    .filter(p => p.ecosystem === null && p.vulnerability_type === null)
    .map(p => ({
      strategy: p.strategy,
      displayName: STRATEGY_DISPLAY_NAMES[p.strategy] || p.strategy,
      successRate: Number(p.success_rate),
      samples: p.sample_count,
      confidence: p.confidence,
      avgCost: p.avg_cost != null ? Number(p.avg_cost) : null,
      avgDuration: p.avg_duration_seconds,
    }));

  // Learning Curve (monthly success rates)
  const monthlyBuckets: Record<string, { total: number; success: number }> = {};
  for (const o of allOutcomes) {
    const month = o.created_at.slice(0, 7); // YYYY-MM
    if (!monthlyBuckets[month]) monthlyBuckets[month] = { total: 0, success: 0 };
    monthlyBuckets[month].total++;
    if (o.success) monthlyBuckets[month].success++;
  }
  const learningCurve = Object.entries(monthlyBuckets)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([month, data]) => ({
      month,
      successRate: data.total > 0 ? data.success / data.total : 0,
      total: data.total,
      successes: data.success,
    }));

  // Failure Analysis
  const failureReasons: Record<string, number> = {};
  for (const o of allOutcomes) {
    if (!o.success && o.failure_reason) {
      failureReasons[o.failure_reason] = (failureReasons[o.failure_reason] || 0) + 1;
    }
  }
  const failureAnalysis = Object.entries(failureReasons)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8)
    .map(([reason, count]) => ({
      reason,
      displayName: reason.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      count,
      percentage: allOutcomes.filter(o => !o.success).length > 0
        ? count / allOutcomes.filter(o => !o.success).length
        : 0,
    }));

  // Follow-up Chains
  const followupChains = allPatterns
    .filter(p => p.best_followup_strategy)
    .map(p => ({
      failedStrategy: p.strategy,
      failedDisplayName: STRATEGY_DISPLAY_NAMES[p.strategy] || p.strategy,
      followupStrategy: p.best_followup_strategy!,
      followupDisplayName: STRATEGY_DISPLAY_NAMES[p.best_followup_strategy!] || p.best_followup_strategy!,
      followupSuccessRate: p.followup_success_rate != null ? Number(p.followup_success_rate) : 0,
      samples: p.sample_count,
    }));

  // Quality Insights
  const ratedOutcomes = allOutcomes.filter(o => o.human_quality_rating != null);
  const qualityByStrategy: Record<string, { ratings: number[]; total: number }> = {};
  for (const o of ratedOutcomes) {
    if (!qualityByStrategy[o.strategy]) qualityByStrategy[o.strategy] = { ratings: [], total: 0 };
    qualityByStrategy[o.strategy].ratings.push(o.human_quality_rating);
    qualityByStrategy[o.strategy].total++;
  }
  const qualityInsights = Object.entries(qualityByStrategy).map(([strategy, data]) => {
    const avg = data.ratings.reduce((a, b) => a + b, 0) / data.ratings.length;
    const dist = [1, 2, 3, 4, 5].map(r => data.ratings.filter(v => v === r).length);
    return {
      strategy,
      displayName: STRATEGY_DISPLAY_NAMES[strategy] || strategy,
      avgRating: avg,
      totalRatings: data.total,
      distribution: dist,
    };
  });

  return {
    strategyMatrix,
    learningCurve,
    failureAnalysis,
    followupChains,
    qualityInsights,
    totalOutcomes: allOutcomes.length,
    totalSuccesses: allOutcomes.filter(o => o.success).length,
    totalRatings: ratedOutcomes.length,
  };
}

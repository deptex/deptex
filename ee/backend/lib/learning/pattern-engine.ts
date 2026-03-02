import { supabase } from '../../../../backend/src/lib/supabase';
import { invalidateCache } from '../cache';

export async function recomputePatterns(orgId: string): Promise<void> {
  const { error } = await supabase.rpc('compute_strategy_patterns', { p_org_id: orgId });
  if (error) {
    console.error(`[learning] Pattern recomputation failed for org ${orgId}:`, error.message);
    throw error;
  }

  try {
    const redis = (await import('../cache')).getRedisClient?.();
    if (redis) {
      const keys = await redis.keys(`strategy-recs:${orgId}:*`);
      if (keys.length > 0) {
        await Promise.all(keys.map((k: string) => invalidateCache(k)));
      }
    } else {
      await invalidateCache(`strategy-recs:${orgId}:*`);
    }
  } catch {
    // Cache invalidation failure is non-fatal
  }
}

export async function recomputeAllStaleOrgs(): Promise<number> {
  const { data: orgs } = await supabase
    .from('fix_outcomes')
    .select('organization_id')
    .gt('created_at', new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString())
    .limit(500);

  if (!orgs || orgs.length === 0) return 0;

  const uniqueOrgs = [...new Set(orgs.map(o => o.organization_id))];
  let count = 0;

  for (const orgId of uniqueOrgs) {
    try {
      await recomputePatterns(orgId);
      count++;
    } catch (e) {
      console.warn(`[learning] Failed to recompute patterns for org ${orgId}:`, (e as Error).message);
    }
  }

  return count;
}

export interface PatternQueryResult {
  strategy: string;
  success_rate: number;
  total_attempts: number;
  successes: number;
  confidence: string;
  avg_duration_seconds: number | null;
  avg_cost: number | null;
  avg_quality_rating: number | null;
  pr_merge_rate: number | null;
  revert_rate: number | null;
  common_failure_reasons: Record<string, number> | null;
  best_followup_strategy: string | null;
  followup_success_rate: number | null;
  sample_count: number;
}

export async function queryPatterns(
  orgId: string,
  ecosystem?: string | null,
  vulnType?: string | null,
  isDirect?: boolean | null,
): Promise<PatternQueryResult[]> {
  let query = supabase
    .from('strategy_patterns')
    .select('*')
    .eq('organization_id', orgId)
    .order('success_rate', { ascending: false });

  if (ecosystem) {
    query = query.eq('ecosystem', ecosystem);
  }
  if (vulnType) {
    query = query.eq('vulnerability_type', vulnType);
  }
  if (isDirect !== null && isDirect !== undefined) {
    query = query.eq('is_direct_dep', isDirect);
  }

  const { data } = await query;
  return (data || []) as PatternQueryResult[];
}

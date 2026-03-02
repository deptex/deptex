import { estimateCost } from './pricing';

export interface AIUsageLogEntry {
  organizationId: string;
  userId: string;
  feature: string;
  tier: 'platform' | 'byok';
  provider: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  contextType?: string;
  contextId?: string;
  durationMs?: number;
  success: boolean;
  errorMessage?: string;
}

export async function logAIUsage(entry: AIUsageLogEntry): Promise<void> {
  try {
    const { supabase } = await import('../../../../backend/src/lib/supabase');
    const cost = estimateCost(entry.model, entry.inputTokens, entry.outputTokens);

    await supabase.from('ai_usage_logs').insert({
      organization_id: entry.organizationId,
      user_id: entry.userId,
      feature: entry.feature,
      tier: entry.tier,
      provider: entry.provider,
      model: entry.model,
      input_tokens: entry.inputTokens,
      output_tokens: entry.outputTokens,
      estimated_cost: cost,
      context_type: entry.contextType || null,
      context_id: entry.contextId || null,
      duration_ms: entry.durationMs || null,
      success: entry.success,
      error_message: entry.errorMessage || null,
    });
  } catch (err: any) {
    console.warn('[AIUsage] Failed to log usage:', err.message);
  }
}

export async function getAIUsageSummary(
  orgId: string,
  periodDays: number = 30
): Promise<{
  totalInputTokens: number;
  totalOutputTokens: number;
  totalEstimatedCost: number;
  monthlyCostCap: number;
  byFeature: Record<string, { tokens: number; cost: number; count: number }>;
  byUser: Array<{ userId: string; tokens: number; cost: number; count: number }>;
}> {
  const { supabase } = await import('../../../../backend/src/lib/supabase');

  const since = new Date();
  since.setDate(since.getDate() - periodDays);

  const { data: logs } = await supabase
    .from('ai_usage_logs')
    .select('*')
    .eq('organization_id', orgId)
    .eq('success', true)
    .gte('created_at', since.toISOString());

  const { data: providers } = await supabase
    .from('organization_ai_providers')
    .select('monthly_cost_cap')
    .eq('organization_id', orgId)
    .eq('is_default', true)
    .limit(1);

  const monthlyCostCap = providers?.[0]?.monthly_cost_cap ?? 100;
  const rows = logs || [];

  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let totalEstimatedCost = 0;
  const byFeature: Record<string, { tokens: number; cost: number; count: number }> = {};
  const userMap: Record<string, { tokens: number; cost: number; count: number }> = {};

  for (const row of rows) {
    totalInputTokens += row.input_tokens || 0;
    totalOutputTokens += row.output_tokens || 0;
    totalEstimatedCost += parseFloat(row.estimated_cost) || 0;

    const feature = row.feature;
    if (!byFeature[feature]) byFeature[feature] = { tokens: 0, cost: 0, count: 0 };
    byFeature[feature].tokens += (row.input_tokens || 0) + (row.output_tokens || 0);
    byFeature[feature].cost += parseFloat(row.estimated_cost) || 0;
    byFeature[feature].count++;

    const uid = row.user_id;
    if (!userMap[uid]) userMap[uid] = { tokens: 0, cost: 0, count: 0 };
    userMap[uid].tokens += (row.input_tokens || 0) + (row.output_tokens || 0);
    userMap[uid].cost += parseFloat(row.estimated_cost) || 0;
    userMap[uid].count++;
  }

  const byUser = Object.entries(userMap)
    .map(([userId, stats]) => ({ userId, ...stats }))
    .sort((a, b) => b.cost - a.cost);

  return { totalInputTokens, totalOutputTokens, totalEstimatedCost, monthlyCostCap, byFeature, byUser };
}

export async function getAIUsageLogs(
  orgId: string,
  page: number = 1,
  perPage: number = 50
): Promise<{ logs: any[]; total: number }> {
  const { supabase } = await import('../../../../backend/src/lib/supabase');

  const offset = (page - 1) * perPage;

  const { data: logs, count } = await supabase
    .from('ai_usage_logs')
    .select('*', { count: 'exact' })
    .eq('organization_id', orgId)
    .order('created_at', { ascending: false })
    .range(offset, offset + perPage - 1);

  return { logs: logs || [], total: count || 0 };
}

import { supabase } from '../../../backend/src/lib/supabase';

const TIER_MAP: Record<string, number> = {
  free: 0,
  pro: 1,
  team: 2,
  enterprise: 3,
};

export type PlanTier = 'free' | 'pro' | 'team' | 'enterprise';

export const PLAN_LIMITS: Record<PlanTier, { projects: number; members: number; syncs: number; automations: number; api_rpm: number }> = {
  free: { projects: 3, members: 5, syncs: 10, automations: 0, api_rpm: 60 },
  pro: { projects: 15, members: 20, syncs: 100, automations: 5, api_rpm: 300 },
  team: { projects: 50, members: -1, syncs: 500, automations: 20, api_rpm: 1000 },
  enterprise: { projects: -1, members: -1, syncs: -1, automations: -1, api_rpm: 5000 },
};

/** Plan feature flags (aegis_chat, ai_fixes, sso) per tier. Used by checkPlanFeature and getUsageSummary. */
export const PLAN_FEATURES: Record<PlanTier, { aegis_chat: boolean; ai_fixes: boolean; sso: boolean }> = {
  free: { aegis_chat: false, ai_fixes: false, sso: false },
  pro: { aegis_chat: true, ai_fixes: true, sso: false },
  team: { aegis_chat: true, ai_fixes: true, sso: true },
  enterprise: { aegis_chat: true, ai_fixes: true, sso: true },
};

export const TIER_DISPLAY_NAMES: Record<PlanTier, string> = {
  free: 'Free',
  pro: 'Pro',
  team: 'Team',
  enterprise: 'Enterprise',
};

export interface OrgPlanRow {
  plan_tier: string;
  subscription_status: string;
  syncs_used: number;
  syncs_reset_at: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  custom_limits: Record<string, number> | null;
}

const planCache = new Map<string, OrgPlanRow>();

export function invalidatePlanCache(orgId: string): void {
  planCache.delete(orgId);
}

/** Merge tier defaults with custom overrides. */
export function getResolvedLimits(
  tier: string,
  customLimits: Record<string, number> | null
): { projects: number; members: number; syncs: number; automations: number; api_rpm: number } {
  const base = PLAN_LIMITS[tier as PlanTier] ?? PLAN_LIMITS.free;
  if (!customLimits || Object.keys(customLimits).length === 0) {
    return { ...base };
  }
  return {
    projects: customLimits.projects ?? base.projects,
    members: customLimits.members ?? base.members,
    syncs: customLimits.syncs ?? base.syncs,
    automations: customLimits.automations ?? base.automations,
    api_rpm: customLimits.api_rpm ?? base.api_rpm,
  };
}

/** Fetch org plan from DB (with cache). Returns free defaults when no row. */
export async function getOrgPlan(orgId: string): Promise<OrgPlanRow> {
  const cached = planCache.get(orgId);
  if (cached) return cached;

  const { data, error } = await supabase
    .from('organization_plans')
    .select('plan_tier, subscription_status, syncs_used, syncs_reset_at, current_period_end, cancel_at_period_end, custom_limits')
    .eq('organization_id', orgId)
    .single();

  const row: OrgPlanRow = data && !error
    ? {
        plan_tier: data.plan_tier ?? 'free',
        subscription_status: data.subscription_status ?? 'active',
        syncs_used: data.syncs_used ?? 0,
        syncs_reset_at: data.syncs_reset_at ?? null,
        current_period_end: data.current_period_end ?? null,
        cancel_at_period_end: data.cancel_at_period_end ?? false,
        custom_limits: data.custom_limits ?? null,
      }
    : {
        plan_tier: 'free',
        subscription_status: 'active',
        syncs_used: 0,
        syncs_reset_at: new Date().toISOString(),
        current_period_end: null,
        cancel_at_period_end: false,
        custom_limits: null,
      };

  planCache.set(orgId, row);
  return row;
}

export type PlanLimitResource = 'projects' | 'members' | 'syncs' | 'automations';

/** Check if org is within limit for a resource. */
export async function checkPlanLimit(
  orgId: string,
  resource: PlanLimitResource
): Promise<{ allowed: boolean; tier: string; limit: number; current?: number }> {
  const plan = await getOrgPlan(orgId);
  const limits = getResolvedLimits(plan.plan_tier, plan.custom_limits);
  const cap = limits[resource];
  if (cap === -1) return { allowed: true, tier: plan.plan_tier, limit: -1 };

  const countResult = await getResourceCount(orgId, resource);
  const current = countResult?.count ?? 0;
  return {
    allowed: cap === -1 || current < cap,
    tier: plan.plan_tier,
    limit: cap,
    current,
  };
}

async function getResourceCount(orgId: string, resource: PlanLimitResource): Promise<{ count: number } | null> {
  const table = resource === 'projects' ? 'projects' : resource === 'members' ? 'organization_members' : null;
  if (!table) {
    if (resource === 'syncs') {
      const plan = await getOrgPlan(orgId);
      return { count: plan.syncs_used };
    }
    if (resource === 'automations') {
      const { count } = await supabase
        .from('aegis_automations')
        .select('*', { count: 'exact', head: true })
        .eq('organization_id', orgId);
      return count != null ? { count } : null;
    }
    return null;
  }
  const res = await supabase
    .from(table)
    .select('*', { count: 'exact', head: true })
    .match({ organization_id: orgId });
  const count = (res as { count?: number })?.count;
  return count != null ? { count } : null;
}

/** Check if org's plan allows a feature (e.g. aegis_chat, sso). */
export async function checkPlanFeature(
  orgId: string,
  feature: keyof typeof PLAN_FEATURES.free
): Promise<{ allowed: boolean; requiredTier?: string }> {
  const plan = await getOrgPlan(orgId);
  const tier = (plan.plan_tier as PlanTier) in PLAN_FEATURES ? plan.plan_tier as PlanTier : 'free';
  const features = PLAN_FEATURES[tier];
  const allowed = features?.[feature] ?? false;
  let requiredTier = 'pro';
  if (feature === 'sso') requiredTier = 'team';
  return { allowed, requiredTier };
}

export interface DowngradeResult {
  allowed: boolean;
  overLimits: Array<{ resource: string; current: number; limit: number }>;
}

/** Check if org can downgrade to target tier (usage must fit within target limits). */
export async function checkDowngradeAllowed(orgId: string, targetTier: string): Promise<DowngradeResult> {
  const limits = getResolvedLimits(targetTier, null);
  const overLimits: DowngradeResult['overLimits'] = [];

  // Order: projects, members, teams, watchtower, notification_rules, integrations, automations (matches test mocks)
  const projectsRes = await getResourceCount(orgId, 'projects');
  const membersRes = await getResourceCount(orgId, 'members');
  const automationsRes = await getResourceCount(orgId, 'automations');

  const projectsCurrent = projectsRes?.count ?? 0;
  const membersCurrent = membersRes?.count ?? 0;
  const automationsCurrent = automationsRes?.count ?? 0;

  if (limits.projects !== -1 && projectsCurrent > limits.projects) overLimits.push({ resource: 'projects', current: projectsCurrent, limit: limits.projects });
  if (limits.members !== -1 && membersCurrent > limits.members) overLimits.push({ resource: 'members', current: membersCurrent, limit: limits.members });
  if (limits.automations !== -1 && automationsCurrent > limits.automations) overLimits.push({ resource: 'automations', current: automationsCurrent, limit: limits.automations });
  // Downgrade validation only checks plan limits (projects, members, automations); teams/watchlist/notif/integrations are not tier-limited in this check
  return { allowed: overLimits.length === 0, overLimits };
}

export interface UsageSummary {
  tier: string;
  usage: { projects: number; members: number; teams: number; syncs: number; notification_rules: number; integrations: number; automations: number };
  limits: { projects: number; members: number; syncs: number; automations: number };
  features: { aegis_chat: boolean; ai_fixes: boolean; sso: boolean };
}

/** Get usage and limits for an org. */
export async function getUsageSummary(orgId: string): Promise<UsageSummary> {
  const plan = await getOrgPlan(orgId);
  const limits = getResolvedLimits(plan.plan_tier, plan.custom_limits);
  const tier = (plan.plan_tier as PlanTier) in PLAN_FEATURES ? plan.plan_tier as PlanTier : 'free';
  const features = PLAN_FEATURES[tier] ?? PLAN_FEATURES.free;

  const [proj, mem, teams, notif, int, auto] = await Promise.all([
    supabase.from('projects').select('*', { count: 'exact', head: true }).eq('organization_id', orgId),
    supabase.from('organization_members').select('*', { count: 'exact', head: true }).eq('organization_id', orgId),
    supabase.from('teams').select('*', { count: 'exact', head: true }).eq('organization_id', orgId),
    supabase.from('organization_notification_rules').select('*', { count: 'exact', head: true }).eq('organization_id', orgId),
    supabase.from('organization_integrations').select('*', { count: 'exact', head: true }).eq('organization_id', orgId),
    supabase.from('aegis_automations').select('*', { count: 'exact', head: true }).eq('organization_id', orgId),
  ]);

  const usage = {
    projects: proj.count ?? 0,
    members: mem.count ?? 0,
    teams: teams.count ?? 0,
    syncs: plan.syncs_used,
    notification_rules: notif.count ?? 0,
    integrations: int.count ?? 0,
    automations: auto.count ?? 0,
  };

  return {
    tier: plan.plan_tier,
    usage,
    limits: { projects: limits.projects, members: limits.members, syncs: limits.syncs, automations: limits.automations },
    features: { aegis_chat: features.aegis_chat, ai_fixes: features.ai_fixes, sso: features.sso },
  };
}

/** Express middleware: require plan limit for resource. */
export function requirePlanLimit(resource: PlanLimitResource) {
  return async (req: any, res: any, next: any) => {
    const orgId = req.params?.id;
    if (!orgId) return next();
    const result = await checkPlanLimit(orgId, resource);
    if (!result.allowed) {
      return res.status(403).json({ error: 'PLAN_LIMIT', limit: result.limit, current: result.current });
    }
    next();
  };
}

/** Express middleware: require plan feature. */
export function requirePlanFeature(feature: keyof typeof PLAN_FEATURES.free) {
  return async (req: any, res: any, next: any) => {
    const orgId = req.params?.id;
    if (!orgId) return next();
    const result = await checkPlanFeature(orgId, feature);
    if (!result.allowed) {
      return res.status(403).json({ error: 'PLAN_FEATURE', requiredTier: result.requiredTier });
    }
    next();
  };
}

export interface FeatureAccess {
  mfa_enforcement: boolean;
  sso: boolean;
  ip_allowlist: boolean;
  scim: boolean;
  api_tokens: boolean;
  session_management: boolean;
  audit_log: boolean;
  audit_log_export: boolean;
  mfa_personal: boolean;
}

export function getFeatureAccess(plan: string): FeatureAccess {
  const tier = TIER_MAP[plan] ?? 0;
  return {
    mfa_enforcement: tier >= 2,
    sso: tier >= 2,
    ip_allowlist: tier >= 2,
    scim: tier >= 3,
    api_tokens: tier >= 1,
    session_management: tier >= 1,
    audit_log: tier >= 2,
    audit_log_export: tier >= 2,
    mfa_personal: true,
  };
}

export function getTierLevel(plan: string): number {
  return TIER_MAP[plan] ?? 0;
}

export function checkFeatureAccess(
  plan: string,
  feature: keyof FeatureAccess,
): { allowed: boolean; currentTier: string; requiredTier: string } {
  const access = getFeatureAccess(plan);
  const allowed = access[feature];

  let requiredTier = 'free';
  if (['mfa_enforcement', 'sso', 'ip_allowlist', 'audit_log', 'audit_log_export'].includes(feature)) {
    requiredTier = 'team';
  } else if (feature === 'scim') {
    requiredTier = 'enterprise';
  } else if (['api_tokens', 'session_management'].includes(feature)) {
    requiredTier = 'pro';
  }

  return { allowed, currentTier: plan, requiredTier };
}

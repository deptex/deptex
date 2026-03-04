import { supabase } from './supabase';

const TIER_MAP: Record<string, number> = {
  free: 0,
  pro: 1,
  team: 2,
  enterprise: 3,
};

export const TIER_DISPLAY_NAMES: Record<string, string> = {
  free: 'Free',
  pro: 'Pro',
  team: 'Team',
  enterprise: 'Enterprise',
};

export type PlanTier = keyof typeof TIER_MAP;

// Full tier limits (Phase 13 billing)
export const PLAN_LIMITS: Record<string, Record<string, number>> = {
  free: { projects: 3, members: 5, syncs: 10, watchtower: 1, teams: 1, notification_rules: 3, integrations: 5, automations: 0, api_rpm: 60 },
  pro: { projects: 15, members: 20, syncs: 100, watchtower: 5, teams: 5, notification_rules: 10, integrations: 10, automations: 5, api_rpm: 300 },
  team: { projects: 50, members: -1, syncs: 1000, watchtower: 20, teams: 20, notification_rules: 25, integrations: 15, automations: 20, api_rpm: 1000 },
  enterprise: { projects: -1, members: -1, syncs: -1, watchtower: -1, teams: -1, notification_rules: -1, integrations: -1, automations: -1, api_rpm: 5000 },
};

// Feature gates by tier (Phase 13)
export const PLAN_FEATURES: Record<string, Record<string, boolean>> = {
  free: {
    aegis_chat: false,
    ai_fixes: false,
    background_monitoring: false,
    watchtower_forensics: false,
    sync_frequency: false,
    sso: false,
    mfa_enforcement: false,
    ip_allowlist: false,
    legal_docs: false,
    aegis_management: false,
    audit_logs: false,
    custom_sla: false,
    security_slas: false,
  },
  pro: {
    aegis_chat: true,
    ai_fixes: true,
    background_monitoring: true,
    watchtower_forensics: true,
    sync_frequency: true,
    sso: false,
    mfa_enforcement: false,
    ip_allowlist: false,
    legal_docs: false,
    aegis_management: true,
    audit_logs: false,
    custom_sla: false,
    security_slas: false,
  },
  team: {
    aegis_chat: true,
    ai_fixes: true,
    background_monitoring: true,
    watchtower_forensics: true,
    sync_frequency: true,
    sso: true,
    mfa_enforcement: true,
    ip_allowlist: true,
    legal_docs: true,
    aegis_management: true,
    audit_logs: true,
    custom_sla: false,
    security_slas: true,
  },
  enterprise: {
    aegis_chat: true,
    ai_fixes: true,
    background_monitoring: true,
    watchtower_forensics: true,
    sync_frequency: true,
    sso: true,
    mfa_enforcement: true,
    ip_allowlist: true,
    legal_docs: true,
    aegis_management: true,
    audit_logs: true,
    custom_sla: true,
    security_slas: true,
  },
};

// In-memory cache for getOrgPlan (keyed by org id)
const planCache = new Map<string, { plan: OrgPlanRow; at: number }>();
const CACHE_TTL_MS = 60_000; // 1 minute

export interface FeatureAccess {
  mfa_enforcement: boolean;
  sso: boolean;
  ip_allowlist: boolean;
  scim: boolean;
  api_tokens: boolean;
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
  } else if (feature === 'api_tokens') {
    requiredTier = 'pro';
  }

  return { allowed, currentTier: plan, requiredTier };
}

// ─── Org plan row (from organization_plans) ───

interface OrgPlanRow {
  plan_tier: string;
  subscription_status: string;
  syncs_used: number;
  syncs_reset_at: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  custom_limits: Record<string, number> | null;
}

const FREE_DEFAULTS: OrgPlanRow = {
  plan_tier: 'free',
  subscription_status: 'active',
  syncs_used: 0,
  syncs_reset_at: new Date().toISOString(),
  current_period_end: null,
  cancel_at_period_end: false,
  custom_limits: null,
};

export async function invalidatePlanCache(organizationId: string): Promise<void> {
  planCache.delete(organizationId);
}

export async function getOrgPlan(organizationId: string): Promise<OrgPlanRow> {
  const cached = planCache.get(organizationId);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) {
    return cached.plan;
  }

  const { data, error } = await supabase
    .from('organization_plans')
    .select('plan_tier, subscription_status, syncs_used, syncs_reset_at, current_period_end, cancel_at_period_end, custom_limits')
    .eq('organization_id', organizationId)
    .maybeSingle();

  if (error || !data) {
    return { ...FREE_DEFAULTS };
  }

  const plan: OrgPlanRow = {
    plan_tier: data.plan_tier ?? 'free',
    subscription_status: data.subscription_status ?? 'active',
    syncs_used: data.syncs_used ?? 0,
    syncs_reset_at: data.syncs_reset_at ?? null,
    current_period_end: data.current_period_end ?? null,
    cancel_at_period_end: data.cancel_at_period_end ?? false,
    custom_limits: data.custom_limits ?? null,
  };
  planCache.set(organizationId, { plan, at: Date.now() });
  return plan;
}

export function getResolvedLimits(tier: string, customLimits: Record<string, number> | null): Record<string, number> {
  const base = PLAN_LIMITS[tier] ?? PLAN_LIMITS.free;
  const out = { ...base };
  if (customLimits && typeof customLimits === 'object') {
    for (const [k, v] of Object.entries(customLimits)) {
      if (typeof v === 'number' && out[k] !== undefined) out[k] = v;
    }
  }
  return out;
}

// Resource count order expected by tests: projects, members, teams, watchtower, notification_rules, integrations, automations
async function getResourceCounts(organizationId: string): Promise<number[]> {
  const count = async (table: string, column: string): Promise<number> => {
    try {
      const { count: c, error } = await supabase
        .from(table)
        .select('*', { count: 'exact', head: true })
        .eq(column, organizationId);
      if (error) return 0;
      return c ?? 0;
    } catch {
      return 0;
    }
  };

  const [projects, members, teams, watchtower, notification_rules, integrations, automations] = await Promise.all([
    count('projects', 'organization_id'),
    count('organization_members', 'organization_id'),
    count('teams', 'organization_id'),
    count('organization_watchlist', 'organization_id'),
    count('organization_notification_rules', 'organization_id'),
    count('organization_integrations', 'organization_id'),
    count('aegis_automations', 'organization_id'),
  ]);

  return [projects, members, teams, watchtower, notification_rules, integrations, automations];
}

export interface UsageSummary {
  tier: string;
  status: string;
  limits: Record<string, number>;
  usage: Record<string, number>;
  features: Record<string, boolean>;
  syncs_reset_at: string;
  current_period_end: string | null;
}

export async function getUsageSummary(organizationId: string): Promise<UsageSummary> {
  const plan = await getOrgPlan(organizationId);
  const limits = getResolvedLimits(plan.plan_tier, plan.custom_limits);
  const [projects, members, teams, watchtower, notification_rules, integrations, automations] = await getResourceCounts(organizationId);

  const usage: Record<string, number> = {
    projects,
    members,
    syncs: plan.syncs_used,
    watchtower,
    teams,
    notification_rules,
    integrations,
    automations,
  };

  const features = PLAN_FEATURES[plan.plan_tier] ?? PLAN_FEATURES.free;

  return {
    tier: plan.plan_tier,
    status: plan.subscription_status,
    limits: { ...limits },
    usage,
    features: { ...features },
    syncs_reset_at: plan.syncs_reset_at ?? new Date().toISOString(),
    current_period_end: plan.current_period_end,
  };
}

export async function checkPlanLimit(
  organizationId: string,
  resource: string,
): Promise<{ allowed: boolean; tier: string; current?: number; limit?: number }> {
  const plan = await getOrgPlan(organizationId);
  const limits = getResolvedLimits(plan.plan_tier, plan.custom_limits);
  const limit = limits[resource] ?? -1;
  if (limit === -1) return { allowed: true, tier: plan.plan_tier };

  const counts = await getResourceCounts(organizationId);
  const resourceOrder = ['projects', 'members', 'teams', 'watchtower', 'notification_rules', 'integrations', 'automations'];
  const idx = resourceOrder.indexOf(resource);
  let current = idx >= 0 ? counts[idx] : 0;
  if (resource === 'syncs') current = plan.syncs_used;

  return {
    allowed: current < limit,
    tier: plan.plan_tier,
    current,
    limit,
  };
}

export async function checkPlanFeature(
  organizationId: string,
  feature: string,
): Promise<{ allowed: boolean; requiredTier: string; currentTier: string }> {
  const plan = await getOrgPlan(organizationId);
  const features = PLAN_FEATURES[plan.plan_tier] ?? PLAN_FEATURES.free;
  const allowed = features[feature] === true;
  const requiredTier = (() => {
    if (['aegis_chat', 'ai_fixes', 'background_monitoring', 'watchtower_forensics', 'sync_frequency', 'aegis_management'].includes(feature)) return 'pro';
    if (['sso', 'mfa_enforcement', 'legal_docs', 'audit_logs', 'security_slas'].includes(feature)) return 'team';
    if (feature === 'custom_sla') return 'enterprise';
    return 'free';
  })();
  return { allowed, requiredTier, currentTier: plan.plan_tier };
}

export async function checkDowngradeAllowed(
  organizationId: string,
  targetTier: string,
): Promise<{ allowed: boolean; overLimits: Array<{ resource: string; current: number; limit: number }> }> {
  const plan = await getOrgPlan(organizationId);
  const targetLimits = getResolvedLimits(targetTier, null);
  const [projects, members, teams, watchtower, notification_rules, integrations, automations] = await getResourceCounts(organizationId);
  const usage = {
    projects,
    members,
    syncs: plan.syncs_used,
    watchtower,
    teams,
    notification_rules,
    integrations,
    automations,
  };

  const overLimits: Array<{ resource: string; current: number; limit: number }> = [];
  for (const [resource, limit] of Object.entries(targetLimits)) {
    if (limit === -1) continue;
    const current = (usage as Record<string, number>)[resource] ?? 0;
    if (current > limit) {
      overLimits.push({ resource, current, limit });
    }
  }
  return { allowed: overLimits.length === 0, overLimits };
}

type RequestWithParams = { params: Record<string, string>; user?: { id: string } };

export function requirePlanLimit(resource: string) {
  return async (req: RequestWithParams, res: { status: (n: number) => { json: (o: object) => void } }, next: () => void) => {
    const orgId = req.params?.id;
    if (!orgId) return next();
    try {
      const result = await checkPlanLimit(orgId, resource);
      if (result.allowed) return next();
      res.status(403).json({ error: 'PLAN_LIMIT', resource, tier: result.tier, current: result.current, limit: result.limit });
    } catch {
      res.status(403).json({ error: 'PLAN_LIMIT', resource });
    }
  };
}

export function requirePlanFeature(feature: string) {
  return async (req: RequestWithParams, res: { status: (n: number) => { json: (o: object) => void } }, next: () => void) => {
    const orgId = req.params?.id;
    if (!orgId) return next();
    try {
      const result = await checkPlanFeature(orgId, feature);
      if (result.allowed) return next();
      res.status(403).json({ error: 'PLAN_FEATURE', feature, requiredTier: result.requiredTier, currentTier: result.currentTier });
    } catch {
      res.status(403).json({ error: 'PLAN_FEATURE', feature });
    }
  };
}

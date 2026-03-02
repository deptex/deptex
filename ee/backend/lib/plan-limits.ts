const TIER_MAP: Record<string, number> = {
  free: 0,
  pro: 1,
  team: 2,
  enterprise: 3,
};

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

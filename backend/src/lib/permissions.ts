import { Response, NextFunction } from 'express';
import { supabase } from '../lib/supabase';
import { AuthRequest } from '../middleware/auth';

export async function userHasOrgPermission(
  userId: string,
  organizationId: string,
  permission: string,
): Promise<boolean> {
  const { data: membership } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();

  if (!membership) return false;

  const { data: role } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', organizationId)
    .eq('name', membership.role)
    .single();

  return role?.permissions?.[permission] === true;
}

export async function userIsOrgMember(
  userId: string,
  organizationId: string,
): Promise<boolean> {
  const { data } = await supabase
    .from('organization_members')
    .select('user_id')
    .eq('organization_id', organizationId)
    .eq('user_id', userId)
    .single();
  return !!data;
}

export function requireOrgPermission(permission: string, orgIdSource: 'body' | 'query' | 'param' = 'body', orgIdKey = 'organizationId') {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: 'Unauthenticated' });

    const orgId =
      orgIdSource === 'body'
        ? req.body?.[orgIdKey]
        : orgIdSource === 'query'
        ? (req.query?.[orgIdKey] as string | undefined)
        : req.params?.[orgIdKey];

    if (!orgId) return res.status(400).json({ error: `Missing ${orgIdKey}` });

    const ok = await userHasOrgPermission(userId, orgId, permission);
    if (!ok) return res.status(403).json({ error: `Permission denied: ${permission}` });

    next();
  };
}

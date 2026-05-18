import { supabase } from '../lib/supabase';

/**
 * checkOrgManageIntegrations — mirrors hasManageIntegrations() in
 * routes/organizations.ts, exposed here so registry-credentials and any
 * other secret-storing routers share a single source. Reads
 * organization_members.role then organization_roles.permissions to confirm
 * `manage_integrations: true`.
 *
 * The blast radius for registry creds (decrypted AWS / GCP / Azure secrets
 * in worker memory) is high, so they reuse the same `manage_integrations`
 * gate that the rest of org integrations use.
 */
export async function checkOrgManageIntegrations(
  userId: string,
  orgId: string,
): Promise<boolean> {
  const { data: membership, error: memberErr } = await supabase
    .from('organization_members')
    .select('role')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .single();
  if (memberErr || !membership) return false;

  const { data: role, error: roleErr } = await supabase
    .from('organization_roles')
    .select('permissions')
    .eq('organization_id', orgId)
    .eq('name', membership.role)
    .single();
  if (roleErr || !role) return false;

  return role.permissions?.manage_integrations === true;
}

/**
 * checkOrgAccess — true when the caller is any member of the org. Used for
 * read-only routes that don't gate on a specific permission.
 */
export async function checkOrgAccess(userId: string, orgId: string): Promise<boolean> {
  const { data, error } = await supabase
    .from('organization_members')
    .select('user_id')
    .eq('organization_id', orgId)
    .eq('user_id', userId)
    .maybeSingle();
  return !error && !!data;
}

import React from 'react';
import {
  Settings,
  UserCircle,
  Users,
  Atom,
  Network,
  Plug,
  Clock,
  FileText,
  LogIn,
  Smartphone,
  Globe,
  BarChart,
  CreditCard,
  ShieldCheck,
} from 'lucide-react';
import { RolePermissions } from './api';

const ALL_SETTINGS_SECTIONS = [
  'general',
  'members',
  'roles',
  'ai',
  'reachability',
  'integrations',
  'security_slas',
  'malicious_allowlist',
  'audit_logs',
  'sso',
  'mfa',
  'ip_allowlist',
  'usage',
  'billing',
];

// MVP scope cut (2026-06): these settings sections are parked — hidden from the nav AND
// excluded from VALID_SETTINGS_SECTIONS so deep-links fall back to General. The components
// and routes are left intact; remove an id from this set to bring a section back.
export const MVP_PARKED_SECTIONS = new Set<string>([
  'reachability',
  'security_slas',
  'malicious_allowlist',
  'audit_logs',
  'sso',
  'mfa',
  'ip_allowlist',
]);

export const VALID_SETTINGS_SECTIONS = new Set(
  ALL_SETTINGS_SECTIONS.filter((s) => !MVP_PARKED_SECTIONS.has(s)),
);

export type OrgSettingsCategoryEntry = {
  id: string;
  label: string;
  isCategory: true;
};

export type OrgSettingsSectionEntry = {
  id: string;
  label: string;
  icon: React.ReactNode;
  isCategory?: false;
};

export type OrgSettingsEntry = OrgSettingsCategoryEntry | OrgSettingsSectionEntry;

/**
 * Owners always have the full permission set; non-owners get their base permissions
 * with `interact_with_aegis` defaulted to false. Mirrors the inline derivation that
 * has lived in OrganizationSettingsPage since the role overrides were introduced.
 */
export function computeEffectiveOrgPermissions(
  role: string | null | undefined,
  base: RolePermissions | null | undefined,
): RolePermissions | null {
  const isOrgOwner = role === 'owner';
  if (isOrgOwner) {
    return {
      ...(base ?? {}),
      view_settings: true,
      manage_billing: true,
      manage_security: true,
      view_activity: true,
      manage_compliance: true,
      interact_with_aegis: true,
      manage_aegis: true,
      view_ai_spending: true,
      manage_organization_settings: true,
      view_members: true,
      add_members: true,
      edit_roles: true,
      edit_permissions: true,
      kick_members: true,
      manage_teams_and_projects: true,
      manage_integrations: true,
      manage_notifications: true,
    } as RolePermissions;
  }
  if (!base) return null;
  return { ...base, interact_with_aegis: base.interact_with_aegis ?? false };
}

export function canManageOrgCompliance(perms: RolePermissions | null | undefined): boolean {
  if (!perms) return false;
  if (perms.manage_compliance) return true;
  const legacy = perms as unknown as { view_compliance?: boolean; edit_policies?: boolean };
  return Boolean(legacy.view_compliance || legacy.edit_policies);
}

const iconClass = 'h-4 w-4 tab-icon-shake';

/**
 * Returns the ordered list of category headers + section entries the org settings
 * sub-nav should render. Permission gating mirrors the long-standing inline list
 * in OrganizationSettingsPage; this is the single source of truth used by both
 * the page itself and the sidebar drilldown.
 */
export function buildOrgSettingsSections(
  perms: RolePermissions | null | undefined,
): OrgSettingsEntry[] {
  if (!perms) return [];

  const canCompliance = canManageOrgCompliance(perms);
  const entries: OrgSettingsEntry[] = [];

  // Workspace — org identity, people, permissions.
  entries.push({ id: 'category_workspace', label: 'Workspace', isCategory: true });
  entries.push({ id: 'general', label: 'General', icon: <Settings className={iconClass} /> });
  if (perms.view_members) {
    entries.push({ id: 'members', label: 'Members', icon: <UserCircle className={iconClass} /> });
  }
  if (perms.edit_roles) {
    entries.push({ id: 'roles', label: 'Roles', icon: <Users className={iconClass} /> });
  }

  // Configuration — how the platform behaves and what it connects to.
  entries.push({ id: 'category_configuration', label: 'Configuration', isCategory: true });
  entries.push({ id: 'ai', label: 'AI', icon: <Atom className={iconClass} /> });
  if (perms.manage_organization_settings) {
    entries.push({ id: 'reachability', label: 'Reachability', icon: <Network className={iconClass} /> });
  }
  if (canCompliance) {
    entries.push({ id: 'security_slas', label: 'Security SLAs', icon: <Clock className={iconClass} /> });
  }
  if (perms.manage_organization_settings) {
    entries.push({ id: 'malicious_allowlist', label: 'Malicious Allowlist', icon: <ShieldCheck className={iconClass} /> });
  }
  if (perms.manage_integrations) {
    entries.push({ id: 'integrations', label: 'Integrations', icon: <Plug className={iconClass} /> });
  }

  // Org Security — auth surface + audit trail, distinct from "Configuration"-style policy rules.
  const showOrgSecurityCategory = perms.view_activity || perms.manage_security;
  if (showOrgSecurityCategory) {
    entries.push({ id: 'category_security', label: 'Org Security', isCategory: true });
  }
  if (perms.view_activity) {
    entries.push({ id: 'audit_logs', label: 'Audit Logs', icon: <FileText className={iconClass} /> });
  }
  if (perms.manage_security) {
    entries.push({ id: 'sso', label: 'SSO', icon: <LogIn className={iconClass} /> });
    entries.push({ id: 'mfa', label: 'Multi-Factor Authentication', icon: <Smartphone className={iconClass} /> });
    entries.push({ id: 'ip_allowlist', label: 'IP Allowlist', icon: <Globe className={iconClass} /> });
  }

  // Plan — usage + billing.
  if (perms.manage_billing) {
    entries.push({ id: 'category_plan', label: 'Plan', isCategory: true });
    entries.push({ id: 'usage', label: 'Usage', icon: <BarChart className={iconClass} /> });
    entries.push({ id: 'billing', label: 'Billing', icon: <CreditCard className={iconClass} /> });
  }

  // MVP scope cut: drop parked sections, then drop any category header left with no sections.
  const withoutParked = entries.filter((e) => e.isCategory || !MVP_PARKED_SECTIONS.has(e.id));
  return withoutParked.filter((e, i) => {
    if (!e.isCategory) return true;
    const next = withoutParked[i + 1];
    return next != null && !next.isCategory; // keep a category only if a real section follows it
  });
}

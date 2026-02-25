import { useState, useEffect, useRef, useMemo } from 'react';
import { useParams, useOutletContext, useNavigate, useSearchParams, Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../hooks/use-toast';
import { api, Organization, OrganizationMember, OrganizationRole, RolePermissions, CiCdConnection, type CiCdProvider } from '../../lib/api';
import { supabase } from '../../lib/supabase';
import { Button } from '../../components/ui/button';
import { Toaster } from '../../components/ui/toaster';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import { Settings, CreditCard, Users, Save, Trash2, UserPlus, X, Plus, ChevronDown, Check, Edit2, GripVertical, Lock, Shield, BarChart, Tag, Palette, Search, Plug, Bell, Loader2, Upload, Copy, Webhook, Pencil, BookOpen, Mail } from 'lucide-react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from '../../components/ui/dialog';
import { Label } from '../../components/ui/label';
import { Input } from '../../components/ui/input';
import { PermissionEditor } from '../../components/PermissionEditor';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';
import { cn } from '../../lib/utils';
import { RoleDropdown } from '../../components/RoleDropdown';
import { RoleBadge } from '../../components/RoleBadge';
import { UserCircle, FileText } from 'lucide-react';
import MembersPage from './MembersPage';
import AuditLogsSection from './AuditLogsSection';
import PoliciesPage from './PoliciesPage';
import NotificationRulesSection from './NotificationRulesSection';

interface OrganizationContextType {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

interface PlanFeature {
  name: string;
  description?: string;
}

interface PlanTier {
  id: string;
  name: string;
  description: string;
  price: {
    monthly: string;
    annual: string;
    perUnit?: string;
  };
  features: PlanFeature[];
  popular?: boolean;
}

const planTiers: PlanTier[] = [
  {
    id: 'free',
    name: 'Free',
    description: 'Perfect for students, indie devs, and small projects',
    price: {
      monthly: 'Free',
      annual: 'Free',
    },
    features: [
      { name: 'Up to 3 projects' },
      { name: 'Dependency tracking' },
      { name: 'AI agent (20 actions/month)' },
      { name: 'Basic policy enforcement' },
      { name: 'Basic anomaly detection' },
      { name: 'Basic vulnerability watchlists' },
      { name: '2 team members' },
      { name: 'Community support' },
    ],
  },
  {
    id: 'pro',
    name: 'Pro',
    description: 'For power users and small teams maintaining multiple projects',
    price: {
      monthly: '$12',
      annual: '$8',
      perUnit: 'per user',
    },
    popular: true,
    features: [
      { name: 'Unlimited projects' },
      { name: 'Unlimited team members' },
      { name: 'Full AI agent access' },
      { name: 'Fix vulnerabilities' },
      { name: 'Summarize repo health' },
      { name: 'Generate PRs for dependency issues' },
      { name: 'Expanded anomaly detection' },
      { name: 'Automated PR generation' },
      { name: 'Dependency graph visualization' },
      { name: 'Custom policies' },
      { name: 'Advanced reporting' },
      { name: 'Priority support' },
    ],
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    description: 'For companies with compliance requirements',
    price: {
      monthly: '$99-$299',
      annual: '$99-$299',
      perUnit: 'per org',
    },
    features: [
      { name: 'Everything in Pro' },
      { name: 'Unlimited AI agent usage' },
      { name: 'SSO (SAML)' },
      { name: 'Audit logs' },
      { name: 'SLAs' },
      { name: 'Custom retention' },
      { name: 'Custom policy pack' },
      { name: 'Dedicated account support' },
      { name: 'Private cloud / on-prem (optional)' },
    ],
  },
];

// In-memory cache for stale-while-revalidate (keyed by org id)
const orgMembersCache: Record<string, OrganizationMember[]> = {};
const orgRolesCache: Record<string, OrganizationRole[]> = {};

const CACHE_KEY_MEMBERS = (orgId: string) => `org_members_${orgId}`;
const CACHE_KEY_ROLES = (orgId: string) => `org_roles_${orgId}`;

const VALID_SETTINGS_SECTIONS = new Set(['general', 'members', 'roles', 'integrations', 'notifications', 'policies', 'audit_logs', 'usage', 'plan']);

/** Renders a tab-specific content skeleton for the org settings loading state. */
function OrgSettingsTabSkeleton({ section }: { section: string }) {
  const pulse = 'bg-muted animate-pulse rounded';
  switch (section) {
    case 'general':
      return (
        <div className="space-y-6">
          <div>
            <div className={`h-8 w-48 ${pulse}`} />
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="p-6">
              <div className={`h-4 w-40 ${pulse} mb-2`} />
              <div className={`h-3 w-full max-w-md ${pulse} mb-4`} />
              <div className={`h-10 w-full max-w-md ${pulse}`} />
            </div>
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="p-6 flex items-start gap-6">
              <div className="flex-1">
                <div className={`h-4 w-36 ${pulse} mb-2`} />
                <div className={`h-3 w-full max-w-sm ${pulse}`} />
              </div>
              <div className="h-20 w-20 rounded-full bg-muted animate-pulse" />
            </div>
          </div>
        </div>
      );
    case 'members':
      return (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className={`h-8 w-32 ${pulse}`} />
            <div className={`h-9 w-24 ${pulse}`} />
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="p-4 border-b border-border flex items-center gap-3">
              <div className={`h-9 flex-1 max-w-xs ${pulse}`} />
              <div className={`h-9 w-28 ${pulse}`} />
            </div>
            <div className="divide-y divide-border">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="px-4 py-3 flex items-center gap-3">
                  <div className="h-10 w-10 rounded-full bg-muted animate-pulse flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className={`h-4 w-36 ${pulse} mb-1`} />
                    <div className={`h-3 w-48 ${pulse}`} />
                  </div>
                  <div className={`h-6 w-16 ${pulse}`} />
                </div>
              ))}
            </div>
          </div>
        </div>
      );
    case 'roles':
      return (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <div className={`h-8 w-24 ${pulse}`} />
            </div>
            <div className={`h-8 w-24 ${pulse}`} />
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-2 border-b border-border bg-background-subtle/30">
              <div className={`h-4 w-16 ${pulse}`} />
            </div>
            <div className="divide-y divide-border">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="px-4 py-3 flex items-center justify-between">
                  <div className="flex items-center gap-3 flex-1">
                    <div className={`h-5 w-28 ${pulse}`} />
                    <div className={`h-4 w-20 ${pulse}`} />
                  </div>
                  <div className={`h-5 w-16 ${pulse}`} />
                </div>
              ))}
            </div>
          </div>
        </div>
      );
    case 'integrations':
      return (
        <div className="space-y-8">
          <div>
            <h2 className="text-2xl font-bold text-foreground">Integrations</h2>
          </div>
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-semibold text-foreground">CI/CD</h3>
            </div>
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <table className="w-full table-fixed">
                <colgroup>
                  <col className="w-[200px]" />
                  <col />
                  <col className="w-[120px]" />
                </colgroup>
                <thead className="bg-background-subtle/30 border-b border-border">
                  <tr>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Account</th>
                    <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {[1, 2, 3, 4].map((i) => (
                    <tr key={i}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2.5">
                          <div className="h-5 w-5 rounded-sm bg-muted animate-pulse flex-shrink-0" />
                          <div className={`h-4 w-20 ${pulse}`} />
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2.5">
                          <div className="h-6 w-6 rounded-full bg-muted animate-pulse flex-shrink-0" />
                          <div className={`h-4 w-28 ${pulse}`} />
                        </div>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className={`h-8 w-20 ${pulse} ml-auto`} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-semibold text-foreground">Notifications</h3>
            </div>
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <table className="w-full table-fixed">
                <colgroup>
                  <col className="w-[200px]" />
                  <col />
                  <col className="w-[120px]" />
                </colgroup>
                <thead className="bg-background-subtle/30 border-b border-border">
                  <tr>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                    <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Account</th>
                    <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {[1, 2, 3].map((i) => (
                    <tr key={i}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2.5">
                          <div className="h-5 w-5 rounded-sm bg-muted animate-pulse flex-shrink-0" />
                          <div className={`h-4 w-20 ${pulse}`} />
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className={`h-4 w-28 ${pulse}`} />
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className={`h-8 w-20 ${pulse} ml-auto`} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      );
    case 'notifications':
      return (
        <div className="space-y-6">
          <div>
            <div className={`h-8 w-48 ${pulse}`} />
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden min-h-[320px] p-12 flex items-center justify-center">
            <div className={`h-4 w-56 ${pulse}`} />
          </div>
        </div>
      );
    case 'policies':
      return (
        <div className="space-y-6 h-full">
          <div>
            <div className={`h-8 w-24 ${pulse}`} />
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden flex flex-col flex-1 min-h-[320px]">
            <div className="px-4 py-2 border-b border-border flex gap-4">
              <div className={`h-8 w-20 ${pulse}`} />
              <div className={`h-8 w-20 ${pulse}`} />
            </div>
            <div className="p-4 flex-1 font-mono text-sm">
              {[1, 2, 3, 4, 5, 6, 7, 8].map((i) => (
                <div key={i} className={`h-4 ${pulse} mb-1`} style={{ width: i % 3 === 0 ? '70%' : i % 3 === 1 ? '90%' : '50%' }} />
              ))}
            </div>
          </div>
        </div>
      );
    case 'audit_logs':
      return (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className={`h-8 w-28 ${pulse}`} />
            <div className="flex gap-2">
              <div className={`h-9 w-28 ${pulse}`} />
              <div className={`h-9 w-24 ${pulse}`} />
            </div>
          </div>
          <div className="space-y-6">
            <div>
              <div className={`h-5 w-36 ${pulse} mb-3`} />
              <div className="space-y-2">
                {[1, 2, 3, 4, 5].map((i) => (
                  <div key={i} className="flex items-center gap-3 py-2">
                    <div className="h-8 w-8 rounded-full bg-muted animate-pulse flex-shrink-0" />
                    <div className="flex-1">
                      <div className={`h-4 w-48 ${pulse} mb-1`} />
                      <div className={`h-3 w-32 ${pulse}`} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      );
    case 'usage':
      return (
        <div className="space-y-6">
          <div>
            <div className={`h-8 w-24 ${pulse}`} />
          </div>
          <div className="bg-background-card border border-border rounded-lg p-12 flex flex-col items-center justify-center text-center">
            <div className="h-16 w-16 rounded-full bg-muted animate-pulse mb-4" />
            <div className={`h-5 w-56 ${pulse} mb-2`} />
            <div className={`h-4 w-72 ${pulse}`} />
          </div>
        </div>
      );
    case 'plan':
      return (
        <div className="space-y-8">
          <div>
            <div className={`h-8 w-36 ${pulse}`} />
          </div>
          <div className="bg-background border border-border rounded-lg p-6">
            <div className={`h-5 w-28 ${pulse} mb-2`} />
            <div className={`h-4 w-full max-w-md ${pulse} mb-4`} />
            <div className={`h-4 w-48 ${pulse}`} />
          </div>
        </div>
      );
    default:
      return (
        <div className="space-y-6">
          <div>
            <div className={`h-8 w-48 ${pulse}`} />
          </div>
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <div className="p-6">
              <div className={`h-4 w-40 ${pulse} mb-2`} />
              <div className={`h-3 w-full max-w-md ${pulse} mb-4`} />
              <div className={`h-10 w-full max-w-md ${pulse}`} />
            </div>
          </div>
        </div>
      );
  }
}

function getCachedMembers(orgId: string): OrganizationMember[] | null {
  if (orgMembersCache[orgId]) return orgMembersCache[orgId];
  try {
    const raw = localStorage.getItem(CACHE_KEY_MEMBERS(orgId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as OrganizationMember[];
    orgMembersCache[orgId] = parsed;
    return parsed;
  } catch {
    return null;
  }
}

function getCachedRoles(orgId: string): OrganizationRole[] | null {
  if (orgRolesCache[orgId]) return orgRolesCache[orgId];
  try {
    const raw = localStorage.getItem(CACHE_KEY_ROLES(orgId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as OrganizationRole[];
    orgRolesCache[orgId] = parsed;
    return parsed;
  } catch {
    return null;
  }
}

export default function OrganizationSettingsPage() {
  const { id, section: sectionParam } = useParams<{ id: string; section?: string }>();
  const { organization, reloadOrganization } = useOutletContext<OrganizationContextType>();
  const { user } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const callbackHandledRef = useRef<string | null>(null);

  // URL is source of truth for active tab; default to general when missing or invalid
  const activeSection = (sectionParam && VALID_SETTINGS_SECTIONS.has(sectionParam) ? sectionParam : 'general');
  const [orgName, setOrgName] = useState(organization?.name || '');
  const [allRoles, setAllRoles] = useState<OrganizationRole[]>([]);
  const [loadingRoles, setLoadingRoles] = useState(false);
  const [cicdConnections, setCicdConnections] = useState<CiCdConnection[]>([]);
  const [loadingConnections, setLoadingConnections] = useState(false);
  const notificationConnections = useMemo(
    () => cicdConnections.filter(c => c.provider === 'slack' || c.provider === 'discord' || c.provider === 'custom_notification' || c.provider === 'email'),
    [cicdConnections]
  );
  const ticketingConnections = useMemo(
    () => cicdConnections.filter(c => c.provider === 'jira' || c.provider === 'linear' || c.provider === 'asana' || c.provider === 'custom_ticketing'),
    [cicdConnections]
  );
  // Initialize isOwner/isAdmin from cached permissions
  const [isOwner, setIsOwner] = useState(() => {
    const cached = organization?.permissions || (() => {
      if (id) {
        const cachedStr = localStorage.getItem(`org_permissions_${id}`);
        if (cachedStr) { try { return JSON.parse(cachedStr); } catch { return null; } }
      }
      return null;
    })();
    // Owner has edit_roles permission
    return cached?.edit_roles === true;
  });
  const [isAdmin, setIsAdmin] = useState(() => {
    const cached = organization?.permissions || (() => {
      if (id) {
        const cachedStr = localStorage.getItem(`org_permissions_${id}`);
        if (cachedStr) { try { return JSON.parse(cachedStr); } catch { return null; } }
      }
      return null;
    })();
    // Admin has view_settings + view_members
    return cached?.edit_roles === true || (cached?.view_settings === true && cached?.view_members === true);
  });
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [loadingMembers, setLoadingMembers] = useState(() => {
    // Initialize to true if user is owner (will load members immediately)
    const cached = organization?.permissions || (() => {
      if (id) {
        const cachedStr = localStorage.getItem(`org_permissions_${id}`);
        if (cachedStr) { try { return JSON.parse(cachedStr); } catch { return null; } }
      }
      return null;
    })();
    return cached?.edit_roles === true;
  });
  const [selectedTransferMemberId, setSelectedTransferMemberId] = useState<string>('');
  const [selectedNewRole, setSelectedNewRole] = useState<string>('admin');
  const [showMemberDropdown, setShowMemberDropdown] = useState(false);
  const [showRoleDropdown, setShowRoleDropdown] = useState(false);
  const [memberSearchTerm, setMemberSearchTerm] = useState('');
  const memberDropdownRef = useRef<HTMLDivElement>(null);
  const roleDropdownRef = useRef<HTMLDivElement>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [editingRoleName, setEditingRoleName] = useState<string>('');
  const [editingRolePermissions, setEditingRolePermissions] = useState<RolePermissions | null>(null);
  const [editingRoleNameId, setEditingRoleNameId] = useState<string | null>(null);
  const [isSavingRole, setIsSavingRole] = useState(false);
  const [deletingRoleId, setDeletingRoleId] = useState<string | null>(null);
  const [draggedRoleId, setDraggedRoleId] = useState<string | null>(null);
  const [dragPreviewRoles, setDragPreviewRoles] = useState<OrganizationRole[] | null>(null);
  const [showAddRoleSidepanel, setShowAddRoleSidepanel] = useState(false);
  const [isSavingOrgName, setIsSavingOrgName] = useState(false);
  const [isUploadingAvatar, setIsUploadingAvatar] = useState(false);
  const [isTransferringOwnership, setIsTransferringOwnership] = useState(false);
  const [isDeletingOrg, setIsDeletingOrg] = useState(false);
  const [showRoleSettingsModal, setShowRoleSettingsModal] = useState(false);
  const [selectedRoleForSettings, setSelectedRoleForSettings] = useState<OrganizationRole | null>(null);
  const [newRoleNameInput, setNewRoleNameInput] = useState('');
  const [newRoleColor, setNewRoleColor] = useState(''); // No default color (plain gray)
  const [editingRoleColor, setEditingRoleColor] = useState('');
  const [newRolePermissions, setNewRolePermissions] = useState<RolePermissions>({
    view_settings: false,
    manage_billing: false,
    view_activity: false,
    view_compliance: false,
    edit_policies: false,
    interact_with_security_agent: false,
    manage_aegis: false,
    view_members: false,
    add_members: false,
    edit_roles: false,
    edit_permissions: false,
    kick_members: false,
    manage_teams_and_projects: false,
    manage_integrations: false,
  });
  const [isCreatingRole, setIsCreatingRole] = useState(false);
  // Initialize userRolePermissions to null to avoid using stale cache for permission checking
  const [userRolePermissions, setUserRolePermissions] = useState<RolePermissions | null>(null);
  const [permissionsChecked, setPermissionsChecked] = useState(false);

  // Integration configuration sidepanel state
  const [showIntegrationConfigSidepanel, setShowIntegrationConfigSidepanel] = useState(false);
  const [selectedIntegration, setSelectedIntegration] = useState<{
    id: string;
    name: string;
    type: 'notification' | 'ticketing';
  } | null>(null);
  const [integrationConfig, setIntegrationConfig] = useState({
    vulnerabilities: true,
    aegis_activity: true,
    administrative: false,
  });

  // Custom integration sidepanel state
  const [showCustomIntegrationSidepanel, setShowCustomIntegrationSidepanel] = useState(false);
  const [customIntegrationType, setCustomIntegrationType] = useState<'notification' | 'ticketing'>('notification');
  const [customIntegrationName, setCustomIntegrationName] = useState('');
  const [customIntegrationWebhookUrl, setCustomIntegrationWebhookUrl] = useState('');
  const [customIntegrationIconFile, setCustomIntegrationIconFile] = useState<File | null>(null);
  const [customIntegrationIconPreview, setCustomIntegrationIconPreview] = useState<string | null>(null);
  const [customIntegrationSaving, setCustomIntegrationSaving] = useState(false);
  const [customIntegrationSecret, setCustomIntegrationSecret] = useState<string | null>(null);
  const [editingCustomIntegration, setEditingCustomIntegration] = useState<CiCdConnection | null>(null);
  const [newlyCreatedIntegrationId, setNewlyCreatedIntegrationId] = useState<string | null>(null);

  // Jira PAT dialog state
  const [showJiraPatDialog, setShowJiraPatDialog] = useState(false);
  const [jiraPatBaseUrl, setJiraPatBaseUrl] = useState('');
  const [jiraPatToken, setJiraPatToken] = useState('');
  const [jiraPatSaving, setJiraPatSaving] = useState(false);

  // Email notification dialog state
  const [showEmailDialog, setShowEmailDialog] = useState(false);
  const [emailToAdd, setEmailToAdd] = useState('');
  const [emailSaving, setEmailSaving] = useState(false);


  // Get cached or organization permissions
  const getCachedPermissions = (): RolePermissions | null => {
    // First check organization.permissions
    if (organization?.permissions) {
      return organization.permissions;
    }
    // Then check localStorage cache
    if (id) {
      const cachedStr = localStorage.getItem(`org_permissions_${id}`);
      if (cachedStr) {
        try {
          return JSON.parse(cachedStr);
        } catch {
          return null;
        }
      }
    }
    return null;
  };

  // Get effective permissions for rendering - use DB permissions if available, otherwise cache
  // Owners always have all permissions (including new ones not yet in DB)
  const isOrgOwner = organization?.role === 'owner';
  // Use fresh permissions from loadRoles() if available, otherwise fallback to cached/org permissions
  // This allows the page to render immediately while loadRoles() is in progress
  const basePermissions = userRolePermissions || getCachedPermissions();
  const effectivePermissions = isOrgOwner ? {
    ...basePermissions,
    view_settings: true,
    manage_billing: true,
    view_activity: true,
    view_compliance: true,
    edit_policies: true,
    interact_with_security_agent: true,
    manage_aegis: true,
    view_members: true,
    add_members: true,
    edit_roles: true,
    edit_permissions: true,
    kick_members: true,
    manage_teams_and_projects: true,
    manage_integrations: true,
  } : basePermissions;

  // Permission check - redirect if user doesn't have view_settings
  useEffect(() => {
    if (organization && id && !permissionsChecked) {
      const cachedPerms = getCachedPermissions();

      // If we have cached permissions and user has view_settings, allow access
      if (cachedPerms?.view_settings === true) {
        setPermissionsChecked(true);
        return;
      }

      // If we have cached permissions and user doesn't have view_settings, redirect
      if (cachedPerms && !cachedPerms.view_settings) {
        navigate(`/organizations/${id}`, { replace: true });
        return;
      }

      // No cached permissions yet - wait for them to load
      // Don't check permissionsChecked yet, let the roles load
      setPermissionsChecked(true);
    }
  }, [organization, id, navigate, permissionsChecked]);

  // Redirect to settings/general when section param is invalid
  useEffect(() => {
    if (id && sectionParam && !VALID_SETTINGS_SECTIONS.has(sectionParam)) {
      navigate(`/organizations/${id}/settings/general`, { replace: true });
    }
  }, [id, sectionParam, navigate]);

  // Normalize legacy ?section=... query to path so refresh and back/forward work
  useEffect(() => {
    const qSection = searchParams.get('section');
    if (!id || !qSection) return;
    if (VALID_SETTINGS_SECTIONS.has(qSection)) {
      navigate(`/organizations/${id}/settings/${qSection}`, { replace: true });
    }
  }, [id, searchParams, navigate]);

  // Seed members and roles from cache when id is available so we show data immediately when returning to the page
  useEffect(() => {
    if (!id) return;
    const cachedMembers = getCachedMembers(id);
    if (cachedMembers?.length) setMembers(cachedMembers);
    const cachedRoles = getCachedRoles(id);
    if (cachedRoles?.length) {
      const sorted = [...cachedRoles].sort((a, b) => a.display_order - b.display_order);
      setAllRoles(sorted);
      if (organization?.role) {
        const userRole = sorted.find(r => r.name === organization.role);
        if (userRole?.permissions) setUserRolePermissions(userRole.permissions);
      }
    }
  }, [id, organization?.role]);

  useEffect(() => {
    if (organization && permissionsChecked) {
      setOrgName(organization.name);
      loadRoles();
    }
  }, [organization, id, permissionsChecked]);

  const loadConnections = async () => {
    if (!id) return;
    setLoadingConnections(true);
    try {
      const data = await api.getOrganizationConnections(id);
      setCicdConnections(data);
    } catch (err: any) {
      setCicdConnections([]);
    } finally {
      setLoadingConnections(false);
    }
  };

  useEffect(() => {
    if (activeSection === 'integrations' && id) {
      loadConnections();
    }
  }, [activeSection, id]);

  // Handle integration connection callbacks (GitHub, GitLab, Bitbucket)
  useEffect(() => {
    const connected = searchParams.get('connected');
    const section = searchParams.get('section');
    const error = searchParams.get('error');
    const message = searchParams.get('message');

    const callbackKey = connected || error ? `${connected || error}-${id}` : null;

    if (!callbackKey || callbackHandledRef.current === callbackKey) {
      return;
    }

    if (connected && id) {
      callbackHandledRef.current = callbackKey;
      const providerLabel = connected === 'github' ? 'GitHub' : connected === 'gitlab' ? 'GitLab' : connected === 'bitbucket' ? 'Bitbucket' : connected === 'slack' ? 'Slack' : connected === 'discord' ? 'Discord' : connected === 'jira' ? 'Jira' : connected === 'linear' ? 'Linear' : connected === 'asana' ? 'Asana' : connected;
      reloadOrganization().then(() => {
        loadConnections();
        toast({
          title: `${providerLabel} Connected`,
          description: `${providerLabel} has been successfully connected to this organization.`,
        });
        navigate(`/organizations/${id}/settings/integrations`, { replace: true });
      }).catch(() => {
        toast({
          title: 'Connection Successful',
          description: `${providerLabel} connected, but failed to refresh. Please refresh the page.`,
        });
        navigate(`/organizations/${id}/settings`, { replace: true });
      });
      return;
    }

    if (error && message) {
      callbackHandledRef.current = callbackKey;
      const providerLabel = error === 'github' ? 'GitHub' : error === 'gitlab' ? 'GitLab' : error === 'bitbucket' ? 'Bitbucket' : error === 'slack' ? 'Slack' : error === 'discord' ? 'Discord' : error === 'jira' ? 'Jira' : error === 'linear' ? 'Linear' : error === 'asana' ? 'Asana' : error;
      toast({
        title: `${providerLabel} Connection Failed`,
        description: decodeURIComponent(message),
        variant: 'destructive',
      });
      setSearchParams({});
    }
  }, [searchParams, id, reloadOrganization, toast, setSearchParams, navigate]);


  // Update isOwner/isAdmin based on userRolePermissions after roles load
  useEffect(() => {
    if (userRolePermissions && organization && id) {
      // Owner has edit_roles permission
      const owner = userRolePermissions.edit_roles === true;
      setIsOwner(owner);
      // Admin has view_settings + view_members
      setIsAdmin(owner || (userRolePermissions.view_settings === true && userRolePermissions.view_members === true));

      // Load members if user can view them
      if ((owner || userRolePermissions.view_members) && id) {
        loadMembers();
      }
    }
  }, [userRolePermissions, organization, id]);

  // Refine permissions check with database values after roles load
  useEffect(() => {
    if (userRolePermissions !== null && organization && id && permissionsChecked) {
      // Double-check with database permissions (more accurate)
      if (!userRolePermissions.view_settings) {
        toast({
          title: 'Access Denied',
          description: 'You do not have permission to view settings.',
          variant: 'destructive',
        });
        navigate(`/organizations/${id}`, { replace: true });
      }
    }
  }, [userRolePermissions, organization, id, navigate, toast, permissionsChecked]);

  const loadRoles = async () => {
    if (!id) return;
    const hasCache = !!(getCachedRoles(id)?.length);
    if (!hasCache) setLoadingRoles(true);
    try {
      const roles = await api.getOrganizationRoles(id);
      // Sort by display_order
      const sortedRoles = roles.sort((a, b) => a.display_order - b.display_order);
      setAllRoles(sortedRoles);
      orgRolesCache[id] = sortedRoles;
      try {
        localStorage.setItem(CACHE_KEY_ROLES(id), JSON.stringify(sortedRoles));
      } catch { /* ignore */ }

      // Load current user's role permissions
      if (organization?.role) {
        const userRole = sortedRoles.find(r => r.name === organization.role);
        console.log('loadRoles Match:', { orgRole: organization.role, foundRole: userRole });

        if (userRole?.permissions) {
          console.log('Setting userRolePermissions:', userRole.permissions);
          setUserRolePermissions(userRole.permissions);
        } else {
          console.warn(`User role '${organization.role}' not found in organization roles.`);
        }
      }
    } catch (error: any) {
      console.error('Failed to load roles:', error);
    } finally {
      setLoadingRoles(false);
    }
  };

  const loadMembers = async () => {
    if (!id) return;
    const hasCache = !!(getCachedMembers(id)?.length);
    if (!hasCache) setLoadingMembers(true);
    try {
      const membersData = await api.getOrganizationMembers(id);
      setMembers(membersData);
      orgMembersCache[id] = membersData;
      try {
        localStorage.setItem(CACHE_KEY_MEMBERS(id), JSON.stringify(membersData));
      } catch { /* ignore */ }
    } catch (error: any) {
      console.error('Failed to load members:', error);
    } finally {
      setLoadingMembers(false);
    }
  };

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (memberDropdownRef.current && !memberDropdownRef.current.contains(event.target as Node)) {
        setShowMemberDropdown(false);
      }
      if (roleDropdownRef.current && !roleDropdownRef.current.contains(event.target as Node)) {
        setShowRoleDropdown(false);
      }
    };

    if (showMemberDropdown || showRoleDropdown) {
      document.addEventListener('mousedown', handleClickOutside);
    } else {
      // Clear search term when dropdown closes
      if (!showMemberDropdown) {
        setMemberSearchTerm('');
      }
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showMemberDropdown, showRoleDropdown]);


  const handleUpdateOrgName = async () => {
    if (!id || !orgName.trim() || isSavingOrgName) return;

    try {
      setIsSavingOrgName(true);
      await api.updateOrganization(id, { name: orgName.trim() });
      await reloadOrganization();
      toast({
        title: 'Organization name updated',
        description: 'The organization name has been updated successfully.',
      });
    } catch (error: any) {
      toast({
        title: 'Update failed',
        description: error.message || 'Failed to update organization name.',
        variant: 'destructive',
      });
    } finally {
      setIsSavingOrgName(false);
    }
  };

  const handleUploadAvatar = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !id) return;

    // Validate file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      toast({
        title: 'File too large',
        description: 'Please upload an image smaller than 5MB.',
        variant: 'destructive',
      });
      return;
    }

    // Validate file type
    if (!file.type.startsWith('image/')) {
      toast({
        title: 'Invalid file type',
        description: 'Please upload an image file.',
        variant: 'destructive',
      });
      return;
    }

    setIsUploadingAvatar(true);
    try {
      const fileExt = file.name.split('.').pop();
      const fileName = `${id}-${Date.now()}.${fileExt}`;
      const filePath = `${id}/${fileName}`;

      // Upload to Supabase Storage
      const { error: uploadError } = await supabase.storage
        .from('organization-avatars')
        .upload(filePath, file, {
          cacheControl: '3600',
          upsert: true,
        });

      if (uploadError) {
        throw uploadError;
      }

      // Get public URL
      const { data: { publicUrl } } = supabase.storage
        .from('organization-avatars')
        .getPublicUrl(filePath);

      // Update organization
      await api.updateOrganization(id, { avatar_url: publicUrl });
      await reloadOrganization();

      toast({
        title: 'Avatar updated',
        description: 'The organization avatar has been updated successfully.',
      });
    } catch (error: any) {
      console.error('Error uploading avatar:', error);
      toast({
        title: 'Upload failed',
        description: error.message || 'Failed to upload avatar. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setIsUploadingAvatar(false);
    }

    e.target.value = '';
  };

  const handleCreateRole = async (permissions: RolePermissions) => {
    if (!id || !newRoleNameInput.trim()) return;

    const roleName = newRoleNameInput.trim().toLowerCase();

    // Check if role already exists
    if (allRoles.some(r => r.name.toLowerCase() === roleName)) {
      toast({
        title: 'Role exists',
        description: 'A role with this name already exists.',
        variant: 'destructive',
      });
      return;
    }

    try {
      setIsCreatingRole(true);
      await api.createOrganizationRole(id, {
        name: roleName,
        display_name: newRoleNameInput.trim(),
        display_order: allRoles.length,
        permissions,
        color: newRoleColor || null,
      });
      await loadRoles();
      setNewRoleNameInput('');
      setNewRoleColor('');
      setNewRolePermissions({
        view_settings: false,
        manage_billing: false,
        view_activity: false,
        view_compliance: false,
        edit_policies: false,
        interact_with_security_agent: false,
        manage_aegis: false,
        view_members: false,
        add_members: false,
        edit_roles: false,
        edit_permissions: false,
        kick_members: false,
        manage_teams_and_projects: false,
        manage_integrations: false,
      });
      setShowAddRoleSidepanel(false);
      toast({
        title: 'Role created',
        description: `The role "${newRoleNameInput.trim()}" has been created.`,
      });
    } catch (error: any) {
      toast({
        title: 'Failed to create role',
        description: error.message || 'Failed to create role. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setIsCreatingRole(false);
    }
  };

  const handleDeleteRole = async (role: OrganizationRole) => {
    if (!id || role.is_default || !role.id || deletingRoleId) return;

    setDeletingRoleId(role.id);
    try {
      await api.deleteOrganizationRole(id, role.id);
      await loadRoles();
      toast({
        title: 'Role deleted',
        description: `The role "${role.display_name || role.name}" has been deleted.`,
      });
    } catch (error: any) {
      toast({
        title: 'Failed to delete role',
        description: error.message || 'Failed to delete role. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setDeletingRoleId(null);
    }
  };

  // Live reorder preview during drag
  const handleDragPreview = (draggedId: string, targetId: string) => {
    const sourceRoles = dragPreviewRoles || allRoles;
    const draggedIndex = sourceRoles.findIndex(r => r.id === draggedId);
    const targetIndex = sourceRoles.findIndex(r => r.id === targetId);

    if (draggedIndex === -1 || targetIndex === -1 || draggedIndex === targetIndex) return;

    // Create new array with the dragged item moved to target position
    const newRoles = [...sourceRoles];
    const [draggedRole] = newRoles.splice(draggedIndex, 1);
    newRoles.splice(targetIndex, 0, draggedRole);

    setDragPreviewRoles(newRoles);
  };

  // Commit the reorder on drop
  const handleDragReorder = async () => {
    if (!id || !dragPreviewRoles) return;

    const userRank = organization?.user_rank ?? 0;
    const isOrgOwner = organization?.role === 'owner';

    // Calculate which roles changed position
    const updates: Array<{ id: string; newOrder: number; originalDisplayOrder: number }> = [];
    dragPreviewRoles.forEach((role, index) => {
      const originalRole = allRoles.find(r => r.id === role.id);
      if (originalRole && originalRole.display_order !== index) {
        updates.push({ id: role.id, newOrder: index, originalDisplayOrder: originalRole.display_order });
      }
    });

    if (updates.length === 0) {
      setDragPreviewRoles(null);
      return;
    }

    // Check if any role that was ORIGINALLY below user's rank would be moved ABOVE user's rank
    // Only perform this check if user is not org owner
    if (!isOrgOwner && userRank !== null && userRank !== undefined) {
      // Find user's role in the NEW (preview) array to get their new position
      const userRoleInPreview = dragPreviewRoles.find(r => r.name === organization?.role);
      const userNewDisplayOrder = userRoleInPreview ? dragPreviewRoles.indexOf(userRoleInPreview) : userRank;

      const invalidUpdate = updates.find(update => {
        // Was this role originally BELOW the user? (higher display_order = lower rank)
        const wasBelow = update.originalDisplayOrder > userRank;
        // Is this role now ABOVE the user in the new ordering? (lower display_order = higher rank)
        const isNowAbove = update.newOrder < userNewDisplayOrder;
        return wasBelow && isNowAbove;
      });

      if (invalidUpdate) {
        toast({
          title: 'Cannot reorder role',
          description: 'You cannot reorder a role to be above your rank.',
          variant: 'destructive',
        });
        setDragPreviewRoles(null);
        return;
      }
    }

    // Commit the preview to actual state
    const finalRoles = dragPreviewRoles.map((role, index) => ({
      ...role,
      display_order: index,
    }));
    setAllRoles(finalRoles);
    setDragPreviewRoles(null);

    // Async update backend
    Promise.all(
      updates.map(({ id: roleId, newOrder }) =>
        api.updateOrganizationRole(id, roleId, { display_order: newOrder })
      )
    ).catch((error: any) => {
      toast({
        title: 'Failed to reorder roles',
        description: error.message || 'Failed to save new order. Please try again.',
        variant: 'destructive',
      });
      loadRoles();
    });
  };

  const handleEditRoleName = (role: OrganizationRole) => {
    if (!role.id) return;
    setEditingRoleNameId(role.id);
    setEditingRoleName(role.display_name || role.name);
  };

  const handleEditRolePermissions = (role: OrganizationRole) => {
    if (!role.id) return;
    setSelectedRoleForSettings(role);
    setEditingRoleName(role.display_name || role.name);
    setEditingRoleColor(role.color || '');
    setEditingRolePermissions(role.permissions || {
      view_settings: false,
      manage_billing: false,
      view_activity: false,
      view_compliance: false,
      edit_policies: false,
      interact_with_security_agent: false,
      manage_aegis: false,
      view_members: false,
      add_members: false,
      edit_roles: false,
      edit_permissions: false,
      kick_members: false,
      manage_teams_and_projects: false,
      manage_integrations: false,
    });
    setShowRoleSettingsModal(true);
  };


  const handleSaveRoleName = async (role: OrganizationRole) => {
    if (!id || !role.id || !editingRoleName.trim()) return;

    try {
      setIsSavingRole(true);
      const updatedRole = await api.updateOrganizationRole(id, role.id, {
        display_name: editingRoleName.trim(),
      });

      // Optimistically update local state immediately
      setAllRoles(prevRoles =>
        prevRoles.map(r =>
          r.id === role.id
            ? { ...r, display_name: updatedRole.display_name }
            : r
        )
      );

      setEditingRoleNameId(null);
      setEditingRoleName('');

      // Dispatch event to notify header to refresh
      window.dispatchEvent(new CustomEvent('rolesUpdated'));

      // Show success immediately
      toast({
        title: 'Role name updated',
        description: 'The role name has been updated successfully.',
      });

      // Refresh roles in the background (don't await)
      loadRoles().catch(error => {
        console.error('Background role refresh failed:', error);
        // Silently fail - we already updated optimistically
      });
    } catch (error: any) {
      toast({
        title: 'Failed to update role',
        description: error.message || 'Failed to update role name. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setIsSavingRole(false);
    }
  };

  const handleSaveRolePermissions = async (role: OrganizationRole, permissions: RolePermissions) => {
    if (!id || !role.id) return;

    try {
      setIsSavingRole(true);
      const updatedRole = await api.updateOrganizationRole(id, role.id, {
        permissions,
        color: editingRoleColor || null,
      });

      // Optimistically update local state immediately
      setAllRoles(prevRoles =>
        prevRoles.map(r =>
          r.id === role.id
            ? { ...r, permissions: updatedRole.permissions, color: updatedRole.color }
            : r
        )
      );

      // Update user role permissions if this is the current user's role
      if (organization?.role === role.name && updatedRole.permissions) {
        setUserRolePermissions(updatedRole.permissions);
      }

      setShowRoleSettingsModal(false);
      setSelectedRoleForSettings(null);
      setEditingRolePermissions(null);

      // Dispatch event to notify header to refresh
      window.dispatchEvent(new CustomEvent('rolesUpdated'));

      // Show success immediately
      toast({
        title: 'Permissions updated',
        description: 'The role permissions have been updated successfully.',
      });

      // Refresh roles in the background (don't await)
      loadRoles().catch(error => {
        console.error('Background role refresh failed:', error);
        // Silently fail - we already updated optimistically
      });
    } catch (error: any) {
      toast({
        title: 'Failed to update permissions',
        description: error.message || 'Failed to update permissions. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setIsSavingRole(false);
    }
  };

  const getRoleDisplayName = (roleName: string): string => {
    const role = allRoles.find(r => r.name === roleName);
    if (role?.display_name) {
      return role.display_name;
    }
    if (roleName === 'owner') return 'Owner';
    if (roleName === 'admin') return 'Admin';
    if (roleName === 'member') return 'Member';
    return roleName.charAt(0).toUpperCase() + roleName.slice(1);
  };

  const handleTransferOwnership = async () => {
    if (!id || !selectedTransferMemberId || isTransferringOwnership) return;

    const selectedMember = members.find(m => m.user_id === selectedTransferMemberId);
    if (!selectedMember) return;

    try {
      setIsTransferringOwnership(true);
      await api.transferOrganizationOwnership(id, selectedTransferMemberId, selectedNewRole);
      toast({
        title: 'Ownership transferred',
        description: `Organization ownership has been transferred to ${selectedMember.full_name || selectedMember.email}. You are now a ${getRoleDisplayName(selectedNewRole)}.`,
      });
      setSelectedTransferMemberId('');
      setSelectedNewRole('admin');
      await reloadOrganization();
      await loadMembers(); // Reload members to update the list
    } catch (error: any) {
      toast({
        title: 'Transfer failed',
        description: error.message || 'Failed to transfer ownership. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setIsTransferringOwnership(false);
    }
  };

  const handleDeleteOrganization = async () => {
    if (!id || deleteConfirmText !== organization?.name || isDeletingOrg) return;

    try {
      setIsDeletingOrg(true);
      await api.deleteOrganization(id);
      toast({
        title: 'Organization deleted',
        description: 'The organization has been deleted successfully.',
      });
      navigate('/organizations');
    } catch (error: any) {
      toast({
        title: 'Delete failed',
        description: error.message || 'Failed to delete organization. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setIsDeletingOrg(false);
    }
  };

  const orgSettingsSections = [
    // General Category
    {
      id: 'category_general',
      label: 'General',
      isCategory: true,
    },
    {
      id: 'general',
      label: 'General',
      icon: <Settings className="h-4 w-4 tab-icon-shake" />,
    },
    // Conditionally show Members section based on permissions
    ...(effectivePermissions?.view_members ? [{
      id: 'members',
      label: 'Members',
      icon: <UserCircle className="h-4 w-4 tab-icon-shake" />,
    }] : []),
    // Show Roles section if user can view/edit roles
    ...(effectivePermissions?.edit_roles ? [{
      id: 'roles',
      label: 'Roles',
      icon: <Users className="h-4 w-4 tab-icon-shake" />,
    }] : []),
    // Show Integrations section if user can manage integrations
    ...(effectivePermissions?.manage_integrations ? [{
      id: 'integrations',
      label: 'Integrations',
      icon: <Plug className="h-4 w-4 tab-icon-shake" />,
    }] : []),
    // Notifications section (after Integrations)
    ...(effectivePermissions?.manage_integrations ? [{
      id: 'notifications',
      label: 'Notifications',
      icon: <Bell className="h-4 w-4 tab-icon-shake" />,
    }] : []),

    // Security Category
    {
      id: 'category_security',
      label: 'Security',
      isCategory: true,
    },
    // Show Policies section - everyone can view, only edit_policies can edit
    {
      id: 'policies',
      label: 'Policies',
      icon: <Shield className="h-4 w-4 tab-icon-shake" />,
    },
    // Conditionally show Audit Logs section based on view_activity permission
    ...(effectivePermissions?.view_activity ? [{
      id: 'audit_logs',
      label: 'Audit Logs',
      icon: <FileText className="h-4 w-4 tab-icon-shake" />,
    }] : []),


    // Plan Category - only show if user has manage_billing permission
    ...(effectivePermissions?.manage_billing ? [{
      id: 'category_plan',
      label: 'Plan',
      isCategory: true,
    }] : []),
    // Usage section - placeholder for future implementation (only visible with manage_billing)
    ...(effectivePermissions?.manage_billing ? [{
      id: 'usage',
      label: 'Usage',
      icon: <BarChart className="h-4 w-4 tab-icon-shake" />,
    }] : []),
    // Show Plan & Billing section if user has manage_billing permission
    ...(effectivePermissions?.manage_billing ? [{
      id: 'plan',
      label: 'Plan & Billing',
      icon: <CreditCard className="h-4 w-4 tab-icon-shake" />,
    }] : []),
  ];

  // Don't render if organization not loaded or permissions not checked yet — show full-page settings skeleton with tab-specific content
  if (!organization || !permissionsChecked) {
    const loadingSection = sectionParam && VALID_SETTINGS_SECTIONS.has(sectionParam) ? sectionParam : 'general';
    return (
      <div className="bg-background">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex gap-8 items-start">
            {/* Sidebar skeleton */}
            <aside className="w-64 flex-shrink-0">
              <div className="sticky top-24 pt-8 bg-background z-10">
                <nav className="space-y-1">
                  {[1, 2, 3, 4, 5, 6, 7, 8].map((i) => (
                    <div key={i} className="flex items-center gap-3 px-3 py-2">
                      <div className="h-4 w-4 bg-muted animate-pulse rounded" />
                      <div className="h-4 bg-muted animate-pulse rounded flex-1" style={{ maxWidth: i === 2 ? 48 : 120 }} />
                    </div>
                  ))}
                </nav>
              </div>
            </aside>
            {/* Tab-specific content skeleton */}
            <div className="flex-1 no-scrollbar">
              <OrgSettingsTabSkeleton section={loadingSection} />
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Check actual permissions instead of role name
  if (!effectivePermissions?.view_settings) {
    return null; // Will redirect via useEffect
  }

  return (
    <>
      <div className="bg-background">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex gap-8 items-start">
            {/* Sidebar */}
            <aside className="w-64 flex-shrink-0">
              <div className="sticky top-24 pt-8 bg-background z-10">
                <nav className="space-y-1">
                  {orgSettingsSections.map((section) => {
                    // Render category headers
                    if ('isCategory' in section && section.isCategory) {
                      return (
                        <div
                          key={section.id}
                          className="px-3 pt-4 pb-2 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"
                        >
                          {section.label}
                        </div>
                      );
                    }

                    // Render regular sections — navigate so URL reflects active tab
                    return (
                      <button
                        key={section.id}
                        onClick={() => id && navigate(`/organizations/${id}/settings/${section.id}`)}
                        className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors group ${activeSection === section.id
                          ? 'text-foreground'
                          : 'text-foreground-secondary hover:text-foreground'
                          }`}
                      >
                        {section.icon}
                        {section.label}
                      </button>
                    );
                  })}
                </nav>
              </div>
            </aside>

            {/* Content */}
            <div className="flex-1 no-scrollbar">
              {activeSection === 'general' && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-2xl font-bold text-foreground">General Settings</h2>
                  </div>

                  {/* Organization Name Card */}
                  <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                    <div className="p-6">
                      <h3 className="text-base font-semibold text-foreground mb-1">Organization Name</h3>
                      <p className="text-sm text-foreground-secondary mb-4">
                        This is your organization's visible name. It will be displayed throughout the dashboard.
                      </p>
                      {organization ? (
                        <div className="max-w-md">
                          <input
                            type="text"
                            value={orgName}
                            onChange={(e) => isOrgOwner && setOrgName(e.target.value)}
                            placeholder="Enter organization name"
                            disabled={!isOrgOwner}
                            className={`w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all ${!isOrgOwner ? 'opacity-60 cursor-not-allowed' : ''}`}
                          />
                        </div>
                      ) : (
                        <div className="max-w-md h-10 bg-muted animate-pulse rounded-lg"></div>
                      )}
                    </div>
                    {isOrgOwner && (
                      <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-between">
                        <p className="text-xs text-foreground-secondary">
                          Please use 32 characters at maximum.
                        </p>
                        <Button
                          onClick={handleUpdateOrgName}
                          disabled={isSavingOrgName || orgName === organization?.name}
                          size="sm"
                          className="h-8"
                        >
                          {isSavingOrgName ? (
                            <>
                              <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full mr-2" />
                              Saving
                            </>
                          ) : (
                            'Save'
                          )}
                        </Button>
                      </div>
                    )}
                    {!isOrgOwner && (
                      <div className="px-6 py-3 bg-black/20 border-t border-border">
                        <p className="text-xs text-foreground-secondary flex items-center gap-1.5">
                          <Lock className="h-3 w-3" />
                          Only the organization owner can edit this setting.
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Organization Avatar Card */}
                  <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                    <div className="p-6">
                      <div className="flex items-start justify-between gap-6">
                        <div className="flex-1">
                          <h3 className="text-base font-semibold text-foreground mb-1">Organization Avatar</h3>
                          <p className="text-sm text-foreground-secondary">
                            This is your organization's avatar. Click on the avatar to upload a custom one from your files.
                          </p>
                          {!isOrgOwner && (
                            <p className="text-xs text-foreground-secondary flex items-center gap-1.5 mt-4">
                              <Lock className="h-3 w-3" />
                              Only the organization owner can change the avatar.
                            </p>
                          )}
                        </div>
                        <div className="flex-shrink-0">
                          {organization ? (
                            isOrgOwner ? (
                              <>
                                <input
                                  type="file"
                                  accept="image/*"
                                  className="hidden"
                                  id="org-avatar-upload"
                                  onChange={handleUploadAvatar}
                                />
                                <label htmlFor="org-avatar-upload" className={`cursor-pointer block group ${isUploadingAvatar ? 'pointer-events-none' : ''}`}>
                                  <div className="relative">
                                    <img
                                      src={organization.avatar_url || '/images/org_profile.png'}
                                      alt={organization.name}
                                      className="h-20 w-20 rounded-full object-cover border-2 border-border group-hover:border-primary/50 transition-all shadow-lg"
                                    />
                                    {isUploadingAvatar ? (
                                      <div className="absolute inset-0 rounded-full bg-black/60 flex items-center justify-center">
                                        <span className="animate-spin h-6 w-6 border-2 border-white border-t-transparent rounded-full" />
                                      </div>
                                    ) : (
                                      <div className="absolute inset-0 rounded-full bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                                        <Edit2 className="h-5 w-5 text-white" />
                                      </div>
                                    )}
                                  </div>
                                </label>
                              </>
                            ) : (
                              <img
                                src={organization.avatar_url || '/images/org_profile.png'}
                                alt={organization.name}
                                className="h-20 w-20 rounded-full object-cover border-2 border-border opacity-75 shadow-lg"
                              />
                            )
                          ) : (
                            <div className="h-20 w-20 rounded-full bg-muted animate-pulse border-2 border-border"></div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Transfer Ownership Card - Only visible to organization owner */}
                  {isOrgOwner && (
                    <div className="bg-background-card border border-border rounded-lg overflow-visible">
                      <div className="p-6">
                        <h3 className="text-base font-semibold text-foreground mb-1">Transfer Ownership</h3>
                        <p className="text-sm text-foreground-secondary mb-5">
                          Transfer ownership of this organization to another member. You will be assigned a new role after the transfer.
                        </p>
                        {members.filter(m => m.user_id !== user?.id).length > 0 || loadingMembers ? (
                          <div className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                              <div className="space-y-2">
                                <label className="text-sm font-medium text-foreground">New Owner</label>
                                <div className="relative" ref={memberDropdownRef}>
                                  <button
                                    type="button"
                                    onClick={() => setShowMemberDropdown(!showMemberDropdown)}
                                    className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary flex items-center justify-between hover:border-foreground-secondary/50 transition-all"
                                  >
                                    <div className="flex items-center gap-2 flex-1 min-w-0 text-left">
                                      {selectedTransferMemberId && !loadingMembers ? (
                                        (() => {
                                          const selectedMember = members.find(m => m.user_id === selectedTransferMemberId);
                                          if (!selectedMember) return <span className="text-foreground-secondary">Select a member...</span>;
                                          return (
                                            <>
                                              <img
                                                src={selectedMember.avatar_url || '/images/blank_profile_image.png'}
                                                alt={selectedMember.full_name || selectedMember.email}
                                                className="h-5 w-5 rounded-full object-cover border border-border flex-shrink-0"
                                                onError={(e) => {
                                                  e.currentTarget.src = '/images/blank_profile_image.png';
                                                }}
                                              />
                                              <span className="truncate">{selectedMember.full_name || selectedMember.email.split('@')[0]}</span>
                                            </>
                                          );
                                        })()
                                      ) : (
                                        <span className="text-foreground-secondary">Select a member...</span>
                                      )}
                                    </div>
                                    {loadingMembers ? (
                                      <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary flex-shrink-0" />
                                    ) : (
                                      <ChevronDown className={`h-4 w-4 text-foreground-secondary flex-shrink-0 transition-transform ${showMemberDropdown ? 'rotate-180' : ''}`} />
                                    )}
                                  </button>

                                  {showMemberDropdown && !loadingMembers && (() => {
                                    const filteredMembers = members.filter(m => {
                                      if (m.user_id === user?.id) return false;
                                      if (!memberSearchTerm) return true;
                                      const searchLower = memberSearchTerm.toLowerCase();
                                      const nameMatch = (m.full_name || '').toLowerCase().includes(searchLower);
                                      const emailMatch = m.email.toLowerCase().includes(searchLower);
                                      return nameMatch || emailMatch;
                                    });

                                    return (
                                      <div className="absolute z-50 w-full mt-2 bg-background-card border border-border rounded-lg shadow-xl overflow-hidden">
                                        {/* Search Input */}
                                        <div className="p-2 border-b border-border">
                                          <div className="relative">
                                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
                                            <input
                                              type="text"
                                              value={memberSearchTerm}
                                              onChange={(e) => setMemberSearchTerm(e.target.value)}
                                              placeholder="Search members..."
                                              className="w-full pl-9 pr-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary"
                                              autoFocus
                                            />
                                          </div>
                                        </div>
                                        {/* Members List */}
                                        <div className="max-h-60 overflow-auto">
                                          {filteredMembers.length > 0 ? (
                                            <div className="py-1">
                                              {filteredMembers.map((member) => (
                                                <button
                                                  key={member.user_id}
                                                  type="button"
                                                  onClick={() => {
                                                    setSelectedTransferMemberId(member.user_id);
                                                    setShowMemberDropdown(false);
                                                  }}
                                                  className={`w-full px-3 py-2.5 flex items-center gap-3 hover:bg-background-subtle/20 transition-colors text-left ${selectedTransferMemberId === member.user_id ? 'bg-background-subtle/50' : ''}`}
                                                >
                                                  <img
                                                    src={member.avatar_url || '/images/blank_profile_image.png'}
                                                    alt={member.full_name || member.email}
                                                    className="h-8 w-8 rounded-full object-cover border border-border flex-shrink-0"
                                                    referrerPolicy="no-referrer"
                                                    onError={(e) => {
                                                      e.currentTarget.src = '/images/blank_profile_image.png';
                                                    }}
                                                  />
                                                  <div className="flex-1 min-w-0">
                                                    <div className="text-sm font-medium text-foreground truncate">
                                                      {member.full_name || member.email.split('@')[0]}
                                                    </div>
                                                    <div className="text-xs text-foreground-secondary truncate">
                                                      {member.email}
                                                    </div>
                                                  </div>
                                                  <div className="px-2 py-0.5 rounded text-xs font-medium border border-border bg-transparent text-foreground-secondary flex-shrink-0">
                                                    {getRoleDisplayName(member.role)}
                                                  </div>
                                                </button>
                                              ))}
                                            </div>
                                          ) : (
                                            <div className="py-8 text-center text-sm text-foreground-secondary">
                                              No members found
                                            </div>
                                          )}
                                        </div>
                                      </div>
                                    );
                                  })()}
                                </div>
                              </div>
                              <div className="space-y-2">
                                <label className="text-sm font-medium text-foreground">Your New Role</label>
                                <div className="relative" ref={roleDropdownRef}>
                                  <button
                                    type="button"
                                    onClick={() => setShowRoleDropdown(!showRoleDropdown)}
                                    className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary flex items-center justify-between hover:border-foreground-secondary/50 transition-all"
                                  >
                                    <div className="flex items-center gap-2">
                                      {(() => {
                                        const selectedRole = allRoles.find(r => r.name === selectedNewRole);
                                        if (!selectedRole || loadingMembers) return <span className="text-foreground-secondary">Select a role...</span>;
                                        return (
                                          <>
                                            <span className="text-foreground">{selectedRole.display_name || selectedRole.name}</span>
                                            <RoleBadge
                                              role={selectedRole.name}
                                              roleDisplayName={selectedRole.display_name}
                                              roleColor={selectedRole.color}
                                            />
                                          </>
                                        );
                                      })()}
                                    </div>
                                    {loadingMembers ? (
                                      <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary flex-shrink-0" />
                                    ) : (
                                      <ChevronDown className={`h-4 w-4 text-foreground-secondary flex-shrink-0 transition-transform ${showRoleDropdown ? 'rotate-180' : ''}`} />
                                    )}
                                  </button>

                                  {showRoleDropdown && !loadingMembers && (
                                      <div className="absolute z-50 w-full mt-2 bg-background-card border border-border rounded-lg shadow-xl overflow-hidden">
                                        <div className="max-h-60 overflow-auto">
                                          <div className="py-1">
                                            {allRoles.filter(r => r.name !== 'owner').map((role) => {
                                              const memberCount = members.filter(m => m.role === role.name).length;
                                              const isSelected = role.name === selectedNewRole;

                                              return (
                                                <button
                                                  key={role.id || role.name}
                                                  type="button"
                                                  onClick={() => {
                                                    setSelectedNewRole(role.name);
                                                    setShowRoleDropdown(false);
                                                  }}
                                                  className={`w-full px-3 py-2.5 flex items-center justify-between hover:bg-background-subtle/20 transition-colors text-left ${isSelected ? 'bg-background-subtle/50' : ''
                                                    }`}
                                                >
                                                  <div className="flex flex-col gap-1 min-w-0 flex-1">
                                                    <div className="flex items-center gap-2">
                                                      <span className="text-sm font-medium text-foreground truncate">
                                                        {role.display_name || role.name}
                                                      </span>
                                                      {role.is_default && (
                                                        <span className="text-xs text-foreground-secondary">· Default</span>
                                                      )}
                                                    </div>
                                                    <div className="flex items-center gap-1 text-foreground-secondary">
                                                      <Users className="h-3 w-3" />
                                                      <span className="text-xs">
                                                        {memberCount} {memberCount === 1 ? 'member' : 'members'}
                                                      </span>
                                                    </div>
                                                  </div>
                                                  <RoleBadge
                                                    role={role.name}
                                                    roleDisplayName={role.display_name}
                                                    roleColor={role.color}
                                                  />
                                                </button>
                                              );
                                            })}
                                          </div>
                                        </div>
                                      </div>
                                    )}
                                </div>
                              </div>
                            </div>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 text-sm text-foreground-secondary bg-black/20 rounded-lg p-3 border border-border">
                            <Users className="h-4 w-4 flex-shrink-0" />
                            <span>No other members available to transfer ownership to. Invite members first.</span>
                          </div>
                        )}
                      </div>
                      {members.filter(m => m.user_id !== user?.id).length > 0 && (
                        <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-between">
                          <p className="text-xs text-foreground-secondary">
                            This action is irreversible. Make sure you select the correct member.
                          </p>
                          <Button
                            onClick={handleTransferOwnership}
                            variant="outline"
                            size="sm"
                            className="h-8"
                            disabled={!selectedTransferMemberId || isTransferringOwnership}
                          >
                            {isTransferringOwnership ? (
                              <>
                                <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full mr-2" />
                                Transferring
                              </>
                            ) : (
                              <>
                                <UserPlus className="h-3.5 w-3.5 mr-2" />
                                Transfer
                              </>
                            )}
                          </Button>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Danger Zone - Only visible to organization owner */}
                  {isOrgOwner && (
                    <div className="border border-destructive/30 rounded-lg overflow-hidden bg-destructive/5">
                      <div className="px-6 py-3 border-b border-destructive/30 bg-destructive/10">
                        <h3 className="text-sm font-semibold text-destructive uppercase tracking-wide">Danger Zone</h3>
                      </div>
                      <div className="p-6">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <h4 className="text-base font-semibold text-foreground mb-1">Delete Organization</h4>
                            <p className="text-sm text-foreground-secondary">
                              Permanently delete this organization and all of its data including projects, teams, and member associations. This action cannot be undone.
                            </p>
                          </div>
                          {!showDeleteConfirm && organization && (
                            <Button
                              onClick={() => setShowDeleteConfirm(true)}
                              variant="outline"
                              size="sm"
                              className="flex-shrink-0 h-8 border-destructive/50 text-destructive hover:bg-destructive/10 hover:border-destructive"
                            >
                              <Trash2 className="h-3.5 w-3.5 mr-2" />
                              Delete
                            </Button>
                          )}
                        </div>

                        {showDeleteConfirm && organization && (
                          <div className="mt-4 p-4 bg-background/50 rounded-lg border border-destructive/30 space-y-4">
                            <p className="text-sm text-foreground">
                              To confirm deletion, type <strong className="text-destructive font-mono bg-destructive/10 px-1.5 py-0.5 rounded">{organization.name}</strong> below:
                            </p>
                            <input
                              type="text"
                              value={deleteConfirmText}
                              onChange={(e) => setDeleteConfirmText(e.target.value)}
                              placeholder={organization.name}
                              className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-destructive/50 focus:border-destructive transition-all"
                            />
                            <div className="flex gap-2">
                              <Button
                                onClick={handleDeleteOrganization}
                                variant="destructive"
                                size="sm"
                                disabled={deleteConfirmText !== organization.name || isDeletingOrg}
                                className="h-8"
                              >
                                {isDeletingOrg ? (
                                  <>
                                    <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full mr-2" />
                                    Deleting
                                  </>
                                ) : (
                                  <>
                                    <Trash2 className="h-3.5 w-3.5 mr-2" />
                                    Delete Forever
                                  </>
                                )}
                              </Button>
                              <Button
                                onClick={() => {
                                  setShowDeleteConfirm(false);
                                  setDeleteConfirmText('');
                                }}
                                variant="ghost"
                                size="sm"
                                className="h-8"
                              >
                                Cancel
                              </Button>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeSection === 'plan' && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-2xl font-bold text-foreground">Plan & Billing</h2>
                  </div>

                  {/* Current Plan */}
                  <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                    <div className="px-5 py-3.5 rounded-t-lg bg-background-card-header border-b border-border">
                      <span className="text-sm font-semibold text-foreground">Current Plan</span>
                    </div>
                    <div className="p-6">
                      <p className="text-sm text-foreground-secondary">
                        Your organization is currently on the <strong className="text-foreground capitalize">{organization?.plan || 'free'}</strong> plan.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {activeSection === 'roles' && (
                <div className="space-y-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-2xl font-bold text-foreground">Roles</h2>
                    </div>
                    {effectivePermissions?.edit_roles && (
                      <Button
                        onClick={() => setShowAddRoleSidepanel(true)}
                        className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
                      >
                        <Plus className="h-4 w-4 mr-2" />
                        Add Role
                      </Button>
                    )}
                  </div>

                  {/* Roles List */}
                  {loadingRoles ? (
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      {/* Header */}
                      <div className="px-4 py-2 border-b border-border bg-background-card-header text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                        Roles
                      </div>
                      <div className="divide-y divide-border">
                        {[1, 2, 3].map((i) => (
                          <div key={i} className="px-4 py-3 flex items-center justify-between">
                            <div className="flex items-center gap-3 flex-1">
                              <div className="h-5 w-32 bg-muted animate-pulse rounded"></div>
                              <div className="h-5 w-16 bg-muted animate-pulse rounded"></div>
                            </div>
                            <div className="h-5 w-5 bg-muted animate-pulse rounded"></div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : allRoles.length > 0 ? (
                    <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                      {/* Header */}
                      <div className="px-4 py-2 border-b border-border bg-background-card-header text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                        Roles
                      </div>

                      <div className="divide-y divide-border">
                        {(dragPreviewRoles || allRoles).map((role) => {
                          const isUserRole = organization?.role === role.name;
                          const userRank = organization?.user_rank ?? 0;
                          // Can edit roles at or below your rank (not owner, not your own role)
                          // Use the role's display_order from the current array (preview or actual)
                          const currentDisplayOrder = role.display_order;
                          const canEditRole = role.name !== 'owner' && !isUserRole && currentDisplayOrder >= userRank;
                          const canDrag = effectivePermissions?.edit_roles && role.name !== 'owner' && canEditRole;
                          const isDragging = draggedRoleId === role.id;
                          const memberCount = members.filter(m => m.role === role.name).length;

                          return (
                            <div
                              key={role.id || role.name}
                              className={`px-4 py-3 flex items-center justify-between transition-all duration-150 group ${isDragging ? 'opacity-50 bg-primary/10 scale-[0.98]' : 'hover:bg-table-hover'
                                }`}
                              draggable={canDrag}
                              onDragStart={(e) => {
                                if (!canDrag) return;
                                setDraggedRoleId(role.id);
                                setDragPreviewRoles([...allRoles]);
                                e.dataTransfer.effectAllowed = 'move';
                              }}
                              onDragEnd={() => {
                                if (dragPreviewRoles) {
                                  setDragPreviewRoles(null);
                                }
                                setDraggedRoleId(null);
                              }}
                              onDragOver={(e) => {
                                e.preventDefault();
                                if (draggedRoleId && draggedRoleId !== role.id && role.name !== 'owner') {
                                  handleDragPreview(draggedRoleId, role.id);
                                }
                              }}
                              onDrop={(e) => {
                                e.preventDefault();
                                handleDragReorder();
                                setDraggedRoleId(null);
                              }}
                            >
                              {/* Left: Role Name + Member count subtext + Type + Your Role badge */}
                              <div className="flex items-center gap-2 min-w-0 flex-1">
                                <div className="flex flex-col min-w-0">
                                  <div className="flex items-center gap-2">
                                    {editingRoleNameId === role.id ? (
                                      <input
                                        type="text"
                                        value={editingRoleName}
                                        onChange={(e) => setEditingRoleName(e.target.value)}
                                        onClick={(e) => e.stopPropagation()}
                                        maxLength={24}
                                        onKeyDown={(e) => {
                                          if (e.key === 'Enter' && editingRoleName.trim() && !isSavingRole) {
                                            e.preventDefault();
                                            handleSaveRoleName(role);
                                          } else if (e.key === 'Escape') {
                                            e.preventDefault();
                                            setEditingRoleNameId(null);
                                            setEditingRoleName('');
                                          }
                                        }}
                                        onBlur={() => {
                                          if (editingRoleName.trim() && !isSavingRole) {
                                            handleSaveRoleName(role);
                                          } else {
                                            setEditingRoleNameId(null);
                                            setEditingRoleName('');
                                          }
                                        }}
                                        className="bg-transparent border-b border-primary outline-none text-sm font-medium text-foreground focus:outline-none focus:border-primary p-0"
                                        autoFocus
                                      />
                                    ) : (
                                      <span className="text-sm font-medium text-foreground truncate cursor-default">
                                        {role.display_name || role.name}
                                      </span>
                                    )}
                                    {isUserRole && (
                                      <span className="px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide bg-green-600/15 text-green-500 rounded-full whitespace-nowrap">
                                        Your Role
                                      </span>
                                    )}
                                  </div>
                                  <div className="flex items-center gap-1 text-foreground-secondary">
                                    <Users className="h-3 w-3" />
                                    <span className="text-xs">
                                      {memberCount} {memberCount === 1 ? 'member' : 'members'}
                                      {role.is_default && (
                                        <span className="ml-1">· {role.name === 'owner' ? 'Owner' : 'Default'}</span>
                                      )}
                                    </span>
                                  </div>
                                </div>
                              </div>

                              {/* Right side - Badge transforms to actions on hover */}
                              <div className="flex items-center justify-end flex-shrink-0 w-36 relative">
                                {/* Badge - visible by default, hidden on hover when there are actions */}
                                <div className={`flex justify-end transition-opacity ${effectivePermissions?.edit_roles ? 'group-hover:opacity-0' : ''}`}>
                                  <RoleBadge
                                    role={role.name}
                                    roleDisplayName={role.display_name}
                                    roleColor={role.color}
                                  />
                                </div>

                                {/* Actions - hidden by default, visible on hover */}
                                {effectivePermissions?.edit_roles && (
                                  <div className="absolute inset-0 flex items-center justify-end gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                                    {/* Always show settings button to view role settings */}
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      onClick={() => handleEditRolePermissions(role)}
                                      className="h-7 w-7 text-foreground-secondary hover:text-foreground"
                                      title="Settings"
                                    >
                                      <Settings className="h-4 w-4" />
                                    </Button>

                                    {/* Delete button - only for non-default roles below your rank */}
                                    {!role.is_default && canEditRole && (
                                      <Button
                                        variant="ghost"
                                        size="icon"
                                        onClick={() => handleDeleteRole(role)}
                                        disabled={deletingRoleId === role.id}
                                        className="h-7 w-7 text-foreground-secondary hover:text-destructive disabled:opacity-100"
                                        title="Delete"
                                      >
                                        {deletingRoleId === role.id ? (
                                          <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full" />
                                        ) : (
                                          <Trash2 className="h-4 w-4" />
                                        )}
                                      </Button>
                                    )}

                                    {/* Drag handle - only for roles you can edit */}
                                    {canDrag && (
                                      <div className="cursor-grab active:cursor-grabbing text-foreground-secondary hover:text-foreground transition-colors">
                                        <GripVertical className="h-4 w-4" />
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ) : (
                    <div className="bg-background-card border border-border rounded-lg p-12 flex flex-col items-center justify-center text-center">
                      <div className="h-12 w-12 rounded-full bg-background-subtle flex items-center justify-center mb-4">
                        <Users className="h-6 w-6 text-foreground-secondary" />
                      </div>
                      <h3 className="text-lg font-semibold text-foreground mb-1">No roles found</h3>
                      <p className="text-sm text-foreground-secondary max-w-sm">
                        Create roles to define permissions and access levels for your organization members.
                      </p>
                    </div>
                  )}
                </div>
              )}

              {activeSection === 'integrations' && (
                <div className="space-y-8">
                  <div className="flex items-start justify-between">
                    <div>
                      <h2 className="text-2xl font-bold text-foreground">Integrations</h2>
                    </div>
                    <Link to="/docs/integrations">
                      <Button variant="outline" size="sm" className="text-xs">
                        <BookOpen className="h-3.5 w-3.5 mr-1.5" />
                        Docs
                      </Button>
                    </Link>
                  </div>

                  {/* Permission Check */}
                  {!effectivePermissions?.manage_integrations ? (
                    <div className="bg-background-card border border-border rounded-lg p-12 flex flex-col items-center justify-center text-center">
                      <div className="h-16 w-16 rounded-full bg-background-subtle flex items-center justify-center mb-4">
                        <Lock className="h-8 w-8 text-foreground-secondary" />
                      </div>
                      <h3 className="text-lg font-semibold text-foreground mb-2">Access Denied</h3>
                      <p className="text-sm text-foreground-secondary max-w-md">
                        You don't have permission to manage integrations. Contact an administrator to request access.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-8">
                      {/* CI/CD Section */}
                      <div className="space-y-4">
                        <div className="flex items-center justify-between gap-4 flex-wrap">
                          <div className="flex items-center gap-2">
                            <h3 className="text-lg font-semibold text-foreground">CI/CD</h3>
                            <span className="text-sm text-foreground-secondary">Source code & repositories</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {([
                              { provider: 'github' as CiCdProvider, label: 'GitHub', icon: '/images/integrations/github.png', endpoint: 'github/install' },
                              { provider: 'gitlab' as CiCdProvider, label: 'GitLab', icon: '/images/integrations/gitlab.png', endpoint: 'gitlab/install' },
                              { provider: 'bitbucket' as CiCdProvider, label: 'Bitbucket', icon: '/images/integrations/bitbucket.png', endpoint: 'bitbucket/install' },
                            ]).map(({ provider, label, icon, endpoint }) => (
                              <Button
                                key={provider}
                                variant="outline"
                                size="sm"
                                className="text-xs"
                                onClick={async () => {
                                  if (!organization?.id) return;
                                  try {
                                    const { data: { session } } = await supabase.auth.getSession();
                                    if (!session?.access_token) {
                                      toast({ title: 'Error', description: 'Please log in first.', variant: 'destructive' });
                                      return;
                                    }
                                    const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';
                                    const response = await fetch(`${API_BASE_URL}/api/integrations/${endpoint}?org_id=${organization.id}`, {
                                      headers: { Authorization: `Bearer ${session.access_token}`, 'Content-Type': 'application/json' },
                                    });
                                    if (!response.ok) {
                                      const err = await response.json().catch(() => ({ error: `Failed to connect ${label}` }));
                                      throw new Error(err.error || `Failed to start ${label} connection`);
                                    }
                                    const data = await response.json();
                                    if (data.redirectUrl) {
                                      window.location.href = data.redirectUrl;
                                    }
                                  } catch (err: any) {
                                    toast({ title: 'Error', description: err.message || `Failed to connect ${label}.`, variant: 'destructive' });
                                  }
                                }}
                              >
                                <img src={icon} alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5" />
                                Add {label}
                              </Button>
                            ))}
                          </div>
                        </div>
                        {loadingConnections ? (
                          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                            <table className="w-full table-fixed">
                              <colgroup>
                                <col className="w-[200px]" />
                                <col />
                                <col className="w-[120px]" />
                              </colgroup>
                              <thead className="bg-background-card-header border-b border-border">
                                <tr>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Account</th>
                                  <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-border">
                                {[1, 2, 3, 4].map((i) => (
                                  <tr key={i}>
                                    <td className="px-4 py-3">
                                      <div className="flex items-center gap-2.5">
                                        <div className="h-5 w-5 rounded-sm bg-muted animate-pulse flex-shrink-0" />
                                        <div className="h-4 w-20 bg-muted animate-pulse rounded" />
                                      </div>
                                    </td>
                                    <td className="px-4 py-3">
                                      <div className="flex items-center gap-2.5">
                                        <div className="h-6 w-6 rounded-full bg-muted animate-pulse flex-shrink-0" />
                                        <div className="h-4 w-28 bg-muted animate-pulse rounded" />
                                      </div>
                                    </td>
                                    <td className="px-4 py-3 text-right">
                                      <div className="h-8 w-20 bg-muted animate-pulse rounded ml-auto" />
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                            <table className="w-full table-fixed">
                              <colgroup>
                                <col className="w-[200px]" />
                                <col />
                                <col className="w-[120px]" />
                              </colgroup>
                              <thead className="bg-background-card-header border-b border-border">
                                <tr>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Account</th>
                                  <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-border">
                                {cicdConnections.filter(c => c.provider === 'github' || c.provider === 'gitlab' || c.provider === 'bitbucket').length === 0 ? (
                                  <tr>
                                    <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                      No source code integrations. Connect a Git provider above to start scanning repositories.
                                    </td>
                                  </tr>
                                ) : cicdConnections.filter(c => c.provider === 'github' || c.provider === 'gitlab' || c.provider === 'bitbucket').map((conn) => {
                                      const providerIcon = conn.provider === 'github' ? '/images/integrations/github.png'
                                        : conn.provider === 'gitlab' ? '/images/integrations/gitlab.png'
                                        : '/images/integrations/bitbucket.png';
                                      const providerLabel = conn.provider === 'github' ? 'GitHub'
                                        : conn.provider === 'gitlab' ? 'GitLab' : 'Bitbucket';
                                      const accountAvatarUrl = conn.provider === 'github' ? (conn.metadata as { account_avatar_url?: string } | undefined)?.account_avatar_url : undefined;
                                      return (
                                        <tr key={conn.id} className="group hover:bg-table-hover transition-colors">
                                          <td className="px-4 py-3">
                                            <div className="flex items-center gap-2.5">
                                              <img src={providerIcon} alt="" className="h-5 w-5 rounded-sm flex-shrink-0" />
                                              <span className="text-sm font-medium text-foreground">{providerLabel}</span>
                                            </div>
                                          </td>
                                          <td className="px-4 py-3 min-w-0">
                                            <div className="flex items-center gap-2.5 min-w-0">
                                              {accountAvatarUrl ? <img src={accountAvatarUrl} alt="" className="h-6 w-6 rounded-full flex-shrink-0 bg-muted" /> : null}
                                              <span className="text-sm text-foreground truncate">{conn.display_name || conn.installation_id || '-'}</span>
                                            </div>
                                          </td>
                                          <td className="px-4 py-3 text-right">
                                            <Button
                                              variant="outline"
                                              size="sm"
                                              className="text-xs hover:bg-destructive/10 hover:border-destructive/30 opacity-0 group-hover:opacity-100 transition-opacity"
                                              onClick={async () => {
                                                if (!confirm(`Disconnect this ${providerLabel} connection (${conn.display_name || conn.installation_id})?`)) return;
                                                try {
                                                  const result = await api.deleteOrganizationConnection(organization!.id, conn.id);
                                                  if (result.revokeUrl) {
                                                    window.open(result.revokeUrl, '_blank');
                                                    toast({ title: `Opening ${providerLabel}`, description: 'Complete revoke in the opened tab.' });
                                                  } else if (result.provider === 'github' && result.installationId) {
                                                    window.open(`https://github.com/settings/installations/${result.installationId}`, '_blank');
                                                    toast({ title: 'Opening GitHub', description: 'Complete uninstall in the opened tab.' });
                                                  }
                                                  await reloadOrganization();
                                                  await loadConnections();
                                                  toast({ title: 'Disconnected', description: `${providerLabel} connection removed.` });
                                                } catch (err: any) {
                                                  toast({ title: 'Error', description: err.message || 'Failed to disconnect.', variant: 'destructive' });
                                                }
                                              }}
                                            >
                                              Disconnect
                                            </Button>
                                          </td>
                                        </tr>
                                      );
                                    })}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>

                      {/* Notifications Section */}
                      <div className="space-y-4">
                        <div className="flex items-center justify-between gap-4 flex-wrap">
                          <div className="flex items-center gap-2">
                            <h3 className="text-lg font-semibold text-foreground">Notifications</h3>
                            <span className="text-sm text-foreground-secondary">Alerts & messaging</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              className="text-xs"
                              onClick={() => {
                                setEmailToAdd('');
                                setShowEmailDialog(true);
                              }}
                            >
                              <Mail className="h-3.5 w-3.5 mr-1.5" />
                              Add Email
                            </Button>
                            {([
                              { provider: 'slack' as const, label: 'Slack', icon: '/images/integrations/slack.png', getRedirect: api.connectSlackOrg },
                              { provider: 'discord' as const, label: 'Discord', icon: '/images/integrations/discord.png', getRedirect: api.connectDiscordOrg },
                            ]).map(({ provider, label, icon, getRedirect }) => (
                              <Button
                                key={provider}
                                variant="outline"
                                size="sm"
                                className="text-xs"
                                onClick={async () => {
                                  if (!organization?.id) return;
                                  try {
                                    const { redirectUrl } = await getRedirect(organization.id);
                                    window.location.href = redirectUrl;
                                  } catch (err: any) {
                                    toast({ title: 'Error', description: err.message || `Failed to start ${label} connection.`, variant: 'destructive' });
                                  }
                                }}
                              >
                                <img src={icon} alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5 object-contain" />
                                Add {label}
                              </Button>
                            ))}
                            <Button
                              variant="outline"
                              size="sm"
                              className="text-xs"
                              onClick={() => {
                                setCustomIntegrationType('notification');
                                setEditingCustomIntegration(null);
                                setCustomIntegrationName('');
                                setCustomIntegrationWebhookUrl('');
                                setCustomIntegrationIconFile(null);
                                setCustomIntegrationIconPreview(null);
                                setCustomIntegrationSecret(null);
                                setShowCustomIntegrationSidepanel(true);
                              }}
                            >
                              <Webhook className="h-3.5 w-3.5 mr-1.5" />
                              Add Custom
                            </Button>
                          </div>
                        </div>
                        {loadingConnections ? (
                          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                            <table className="w-full table-fixed">
                              <colgroup>
                                <col className="w-[200px]" />
                                <col />
                                <col className="w-[160px]" />
                              </colgroup>
                              <thead className="bg-background-card-header border-b border-border">
                                <tr>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                                  <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-border">
                                {[1, 2, 3].map((i) => (
                                  <tr key={i}>
                                    <td className="px-4 py-3">
                                      <div className="flex items-center gap-2.5">
                                        <div className="h-5 w-5 rounded-sm bg-muted animate-pulse flex-shrink-0" />
                                        <div className="h-4 w-20 bg-muted animate-pulse rounded" />
                                      </div>
                                    </td>
                                    <td className="px-4 py-3">
                                      <div className="h-4 w-28 bg-muted animate-pulse rounded" />
                                    </td>
                                    <td className="px-4 py-3 text-right">
                                      <div className="h-8 w-20 bg-muted animate-pulse rounded ml-auto" />
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                            <table className="w-full table-fixed">
                              <colgroup>
                                <col className="w-[200px]" />
                                <col />
                                <col className="w-[160px]" />
                              </colgroup>
                              <thead className="bg-background-card-header border-b border-border">
                                <tr>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                                  <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-border">
                                {notificationConnections.length === 0 ? (
                                  <tr>
                                    <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                      No notification integrations. Add Slack, Discord, or Email above to receive alerts.
                                    </td>
                                  </tr>
                                ) : notificationConnections.map((conn) => {
                                      const isCustom = conn.provider === 'custom_notification';
                                      const isEmail = conn.provider === 'email';
                                      const hasCustomIcon = isCustom && conn.metadata?.icon_url;
                                      const providerLabel = isCustom
                                        ? (conn.metadata?.custom_name || conn.display_name || 'Custom')
                                        : isEmail ? 'Email' : conn.provider === 'slack' ? 'Slack' : 'Discord';
                                      const providerIconSrc = !isCustom && !isEmail
                                        ? (conn.provider === 'slack' ? '/images/integrations/slack.png' : '/images/integrations/discord.png')
                                        : (hasCustomIcon ? conn.metadata.icon_url : null);

                                      const channelRaw = conn.metadata?.channel || conn.metadata?.incoming_webhook?.channel || null;
                                      const channelFormatted = channelRaw ? (channelRaw.startsWith('#') ? channelRaw : `#${channelRaw}`) : null;
                                      const connectionDisplay = conn.provider === 'slack'
                                        ? { primary: conn.display_name || conn.metadata?.team_name || 'Slack Workspace', secondary: channelFormatted }
                                        : conn.provider === 'discord'
                                          ? { primary: conn.display_name !== 'Discord Server' ? conn.display_name : (conn.metadata?.guild_name || conn.display_name || 'Discord Server'), secondary: null }
                                          : isEmail
                                            ? { primary: conn.metadata?.email || conn.display_name || 'Email', secondary: null }
                                            : isCustom
                                              ? { primary: conn.metadata?.webhook_url ? conn.metadata.webhook_url.replace(/^https?:\/\//, '').slice(0, 45) : 'Webhook', secondary: null }
                                              : { primary: conn.display_name || 'Connected', secondary: null };

                                      const showNewSecret = customIntegrationSecret && newlyCreatedIntegrationId === conn.id;

                                      return (
                                        <tr key={conn.id} className="group hover:bg-table-hover transition-colors">
                                          <td className="px-4 py-3">
                                            <div className="flex items-center gap-2.5">
                                              {providerIconSrc ? (
                                                <img src={providerIconSrc} alt="" className="h-5 w-5 rounded-sm flex-shrink-0 object-contain" />
                                              ) : isEmail ? (
                                                <div className="h-5 w-5 rounded-sm flex-shrink-0 flex items-center justify-center text-foreground-secondary">
                                                  <Mail className="h-3.5 w-3.5" />
                                                </div>
                                              ) : (
                                                <div className="h-5 w-5 rounded-sm flex-shrink-0 flex items-center justify-center text-foreground-secondary">
                                                  <Webhook className="h-3.5 w-3.5" />
                                                </div>
                                              )}
                                              <span className="text-sm font-medium text-foreground">{providerLabel}</span>
                                            </div>
                                          </td>
                                          <td className="px-4 py-3 min-w-0">
                                            {showNewSecret ? (
                                              <div className="flex items-center gap-2">
                                                <code className="text-xs bg-background-card px-2 py-1 rounded border border-border font-mono truncate max-w-[280px]">{customIntegrationSecret}</code>
                                                <button
                                                  onClick={() => {
                                                    navigator.clipboard.writeText(customIntegrationSecret!);
                                                    toast({ title: 'Copied', description: 'Secret copied to clipboard.' });
                                                  }}
                                                  className="text-foreground-secondary hover:text-foreground transition-colors flex-shrink-0"
                                                >
                                                  <Copy className="h-3.5 w-3.5" />
                                                </button>
                                              </div>
                                            ) : (
                                              <div className={cn(
                                                "flex flex-col gap-0.5 truncate",
                                                connectionDisplay.secondary ? "min-w-0" : ""
                                              )}>
                                                <span className="text-sm text-foreground truncate">{connectionDisplay.primary}</span>
                                                {connectionDisplay.secondary && (
                                                  <span className="text-xs text-foreground-muted truncate">{connectionDisplay.secondary}</span>
                                                )}
                                              </div>
                                            )}
                                          </td>
                                          <td className="px-4 py-3 text-right">
                                            <div className="flex items-center justify-end gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
                                              {isCustom && !isEmail && (
                                                <button
                                                  className="h-7 w-7 rounded-md flex items-center justify-center text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
                                                  onClick={() => {
                                                    setEditingCustomIntegration(conn);
                                                    setCustomIntegrationType('notification');
                                                    setCustomIntegrationName(conn.metadata?.custom_name || conn.display_name || '');
                                                    setCustomIntegrationWebhookUrl(conn.metadata?.webhook_url || '');
                                                    setCustomIntegrationIconPreview(conn.metadata?.icon_url || null);
                                                    setCustomIntegrationIconFile(null);
                                                    setCustomIntegrationSecret(null);
                                                    setShowCustomIntegrationSidepanel(true);
                                                  }}
                                                >
                                                  <Pencil className="h-3.5 w-3.5" />
                                                </button>
                                              )}
                                              <Button
                                                variant="outline"
                                                size="sm"
                                                className="text-xs hover:bg-destructive/10 hover:border-destructive/30"
                                                onClick={async () => {
                                                  const label = isCustom ? (conn.metadata?.custom_name || 'custom integration') : isEmail ? (conn.metadata?.email || 'email') : providerLabel;
                                                  if (!confirm(`${isCustom || isEmail ? 'Remove' : 'Disconnect'} this ${label} connection?`)) return;
                                                  try {
                                                    const result = await api.deleteOrganizationConnection(organization!.id, conn.id);
                                                    if (!isCustom && !isEmail && result.revokeUrl) {
                                                      window.open(result.revokeUrl, '_blank');
                                                      toast({ title: 'Disconnected', description: `${label} removed. Complete app removal in the opened tab.` });
                                                    } else {
                                                      toast({ title: isCustom || isEmail ? 'Removed' : 'Disconnected', description: `${label} connection removed.` });
                                                    }
                                                    await loadConnections();
                                                  } catch (err: any) {
                                                    toast({ title: 'Error', description: err.message || 'Failed to disconnect.', variant: 'destructive' });
                                                  }
                                                }}
                                              >
                                                {isCustom || isEmail ? 'Remove' : 'Disconnect'}
                                              </Button>
                                            </div>
                                          </td>
                                        </tr>
                                      );
                                    })}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>

                      {/* Ticketing Section */}
                      <div className="space-y-4">
                        <div className="flex items-center justify-between gap-4 flex-wrap">
                          <div className="flex items-center gap-2">
                            <h3 className="text-lg font-semibold text-foreground">Ticketing</h3>
                            <span className="text-sm text-foreground-secondary">Issue tracking & project management</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="outline" size="sm" className="text-xs">
                                  <img src="/images/integrations/jira.png" alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5 object-contain" />
                                  Add Jira
                                  <ChevronDown className="h-3 w-3 ml-1" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                <DropdownMenuItem onClick={async () => {
                                  if (!organization?.id) return;
                                  try {
                                    const { redirectUrl } = await api.connectJiraOrg(organization.id);
                                    window.location.href = redirectUrl;
                                  } catch (err: any) {
                                    toast({ title: 'Error', description: err.message || 'Failed to start Jira connection.', variant: 'destructive' });
                                  }
                                }}>
                                  Jira Cloud (OAuth)
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => {
                                  setJiraPatBaseUrl('');
                                  setJiraPatToken('');
                                  setShowJiraPatDialog(true);
                                }}>
                                  Jira Data Center (PAT)
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                            {([
                              { label: 'Linear', icon: '/images/integrations/linear.png', getRedirect: api.connectLinearOrg },
                              { label: 'Asana', icon: '/images/integrations/asana.png', getRedirect: api.connectAsanaOrg },
                            ]).map(({ label, icon, getRedirect }) => (
                              <Button
                                key={label}
                                variant="outline"
                                size="sm"
                                className="text-xs"
                                onClick={async () => {
                                  if (!organization?.id) return;
                                  try {
                                    const { redirectUrl } = await getRedirect(organization.id);
                                    window.location.href = redirectUrl;
                                  } catch (err: any) {
                                    toast({ title: 'Error', description: err.message || `Failed to start ${label} connection.`, variant: 'destructive' });
                                  }
                                }}
                              >
                                <img src={icon} alt="" className="h-3.5 w-3.5 rounded-sm mr-1.5 object-contain" />
                                Add {label}
                              </Button>
                            ))}
                            <Button
                              variant="outline"
                              size="sm"
                              className="text-xs"
                              onClick={() => {
                                setCustomIntegrationType('ticketing');
                                setEditingCustomIntegration(null);
                                setCustomIntegrationName('');
                                setCustomIntegrationWebhookUrl('');
                                setCustomIntegrationIconFile(null);
                                setCustomIntegrationIconPreview(null);
                                setCustomIntegrationSecret(null);
                                setShowCustomIntegrationSidepanel(true);
                              }}
                            >
                              <Webhook className="h-3.5 w-3.5 mr-1.5" />
                              Add Custom
                            </Button>
                          </div>
                        </div>
                        {loadingConnections ? (
                          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                            <table className="w-full table-fixed">
                              <colgroup>
                                <col className="w-[200px]" />
                                <col />
                                <col className="w-[160px]" />
                              </colgroup>
                              <thead className="bg-background-card-header border-b border-border">
                                <tr>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                                  <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-border">
                                {[1, 2].map((i) => (
                                  <tr key={i}>
                                    <td className="px-4 py-3">
                                      <div className="flex items-center gap-2.5">
                                        <div className="h-5 w-5 rounded-sm bg-muted animate-pulse flex-shrink-0" />
                                        <div className="h-4 w-20 bg-muted animate-pulse rounded" />
                                      </div>
                                    </td>
                                    <td className="px-4 py-3"><div className="h-4 w-28 bg-muted animate-pulse rounded" /></td>
                                    <td className="px-4 py-3 text-right"><div className="h-8 w-20 bg-muted animate-pulse rounded ml-auto" /></td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                            <table className="w-full table-fixed">
                              <colgroup>
                                <col className="w-[200px]" />
                                <col />
                                <col className="w-[160px]" />
                              </colgroup>
                              <thead className="bg-background-card-header border-b border-border">
                                <tr>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                                  <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-border">
                                {ticketingConnections.length === 0 ? (
                                  <tr>
                                    <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                      No ticketing integrations. Add Jira, Linear, or Asana above to create issues automatically.
                                    </td>
                                  </tr>
                                ) : ticketingConnections.map((conn) => {
                                      const isCustom = conn.provider === 'custom_ticketing';
                                      const hasCustomIcon = isCustom && conn.metadata?.icon_url;
                                      const providerLabel = isCustom
                                        ? (conn.metadata?.custom_name || conn.display_name || 'Custom')
                                        : conn.provider === 'jira'
                                          ? (conn.metadata?.type === 'data_center' ? 'Jira DC' : 'Jira')
                                          : conn.provider === 'linear' ? 'Linear' : 'Asana';
                                      const providerIconSrc = !isCustom
                                        ? (conn.provider === 'jira' ? '/images/integrations/jira.png'
                                          : conn.provider === 'linear' ? '/images/integrations/linear.png'
                                          : '/images/integrations/asana.png')
                                        : (hasCustomIcon ? conn.metadata.icon_url : null);

                                      const connectionDisplay = isCustom
                                        ? (conn.metadata?.webhook_url ? conn.metadata.webhook_url.replace(/^https?:\/\//, '').slice(0, 45) : 'Webhook')
                                        : (conn.display_name || 'Connected');

                                      const showNewSecret = customIntegrationSecret && newlyCreatedIntegrationId === conn.id;

                                      return (
                                        <tr key={conn.id} className="group hover:bg-table-hover transition-colors">
                                          <td className="px-4 py-3">
                                            <div className="flex items-center gap-2.5">
                                              {providerIconSrc ? (
                                                <img src={providerIconSrc} alt="" className="h-5 w-5 rounded-sm flex-shrink-0 object-contain" />
                                              ) : (
                                                <div className="h-5 w-5 rounded-sm flex-shrink-0 flex items-center justify-center text-foreground-secondary">
                                                  <Webhook className="h-3.5 w-3.5" />
                                                </div>
                                              )}
                                              <span className="text-sm font-medium text-foreground">{providerLabel}</span>
                                            </div>
                                          </td>
                                          <td className="px-4 py-3 min-w-0">
                                            {showNewSecret ? (
                                              <div className="flex items-center gap-2">
                                                <code className="text-xs bg-background-card px-2 py-1 rounded border border-border font-mono truncate max-w-[280px]">{customIntegrationSecret}</code>
                                                <button
                                                  onClick={() => {
                                                    navigator.clipboard.writeText(customIntegrationSecret!);
                                                    toast({ title: 'Copied', description: 'Secret copied to clipboard.' });
                                                  }}
                                                  className="text-foreground-secondary hover:text-foreground transition-colors flex-shrink-0"
                                                >
                                                  <Copy className="h-3.5 w-3.5" />
                                                </button>
                                              </div>
                                            ) : (
                                              <span className="text-sm text-foreground truncate block">{connectionDisplay}</span>
                                            )}
                                          </td>
                                          <td className="px-4 py-3 text-right">
                                            <div className="flex items-center justify-end gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
                                              {isCustom && (
                                                <button
                                                  className="h-7 w-7 rounded-md flex items-center justify-center text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
                                                  onClick={() => {
                                                    setEditingCustomIntegration(conn);
                                                    setCustomIntegrationType('ticketing');
                                                    setCustomIntegrationName(conn.metadata?.custom_name || conn.display_name || '');
                                                    setCustomIntegrationWebhookUrl(conn.metadata?.webhook_url || '');
                                                    setCustomIntegrationIconPreview(conn.metadata?.icon_url || null);
                                                    setCustomIntegrationIconFile(null);
                                                    setCustomIntegrationSecret(null);
                                                    setShowCustomIntegrationSidepanel(true);
                                                  }}
                                                >
                                                  <Pencil className="h-3.5 w-3.5" />
                                                </button>
                                              )}
                                              <Button
                                                variant="outline"
                                                size="sm"
                                                className="text-xs hover:bg-destructive/10 hover:border-destructive/30"
                                                onClick={async () => {
                                                  const label = isCustom ? (conn.metadata?.custom_name || 'custom integration') : providerLabel;
                                                  if (!confirm(`${isCustom ? 'Remove' : 'Disconnect'} this ${label} connection?`)) return;
                                                  try {
                                                    await api.deleteOrganizationConnection(organization!.id, conn.id);
                                                    toast({ title: isCustom ? 'Removed' : 'Disconnected', description: `${label} connection removed.` });
                                                    await loadConnections();
                                                  } catch (err: any) {
                                                    toast({ title: 'Error', description: err.message || 'Failed to disconnect.', variant: 'destructive' });
                                                  }
                                                }}
                                              >
                                                {isCustom ? 'Remove' : 'Disconnect'}
                                              </Button>
                                            </div>
                                          </td>
                                        </tr>
                                      );
                                    })}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeSection === 'notifications' && <NotificationRulesSection />}

              {activeSection === 'members' && (
                <div className="space-y-8">
                  <div className="flex items-center justify-between">
                    <h2 className="text-2xl font-bold text-foreground">Members</h2>
                  </div>
                  <div>
                    <MembersPage isSettingsSubpage={true} />
                  </div>
                </div>
              )}



              {activeSection === 'policies' && (
                <div className="h-full">
                  <PoliciesPage isSettingsSubpage={true} />
                </div>
              )}

              {activeSection === 'audit_logs' && (
                <div className="h-full">
                  <AuditLogsSection />
                </div>
              )}

              {activeSection === 'usage' && (
                <div className="space-y-6">
                  <div>
                    <h2 className="text-2xl font-bold text-foreground">Usage</h2>
                  </div>

                  <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                    <div className="px-5 py-3.5 rounded-t-lg bg-background-card-header border-b border-border">
                      <span className="text-sm font-semibold text-foreground">Usage</span>
                    </div>
                    <div className="p-6">
                      <p className="text-sm text-foreground-secondary">
                        You are on the free plan. You are not over your limit yet.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Create New Role – Vercel-style right-side popup panel */}
              {showAddRoleSidepanel && (
                <div className="fixed inset-0 z-50">
                  <div
                    className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
                    onClick={() => {
                      setShowAddRoleSidepanel(false);
                      setNewRoleNameInput('');
                      setNewRoleColor('#3b82f6');
                      setNewRolePermissions({
                        view_settings: false,
                        manage_billing: false,
                        view_activity: false,
                        view_compliance: false,
                        edit_policies: false,
                        interact_with_security_agent: false,
                        manage_aegis: false,
                        view_members: false,
                        add_members: false,
                        edit_roles: false,
                        edit_permissions: false,
                        kick_members: false,
                        view_all_teams_and_projects: false,
                        manage_teams_and_projects: false,
                        manage_integrations: false,
                        view_overview: false,
                      });
                    }}
                  />

                  {/* Right-side popup panel – Vercel style: rounded corners, floating feel */}
                  <div
                    className="fixed right-4 top-4 bottom-4 w-full max-w-[420px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {/* Header – no X, no border */}
                    <div className="px-6 py-5 flex-shrink-0">
                      <h2 className="text-xl font-semibold text-foreground">Create New Role</h2>
                      <p className="text-sm text-foreground-secondary mt-0.5">
                        Define a custom role with specific permissions.
                      </p>
                    </div>

                    {/* Content */}
                    <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
                      <div className="space-y-6">
                        {/* Role Name Input */}
                        <div className="space-y-3">
                          <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                            <Tag className="h-5 w-5 text-foreground-secondary" />
                            Role Name
                          </label>
                          <input
                            type="text"
                            placeholder="e.g. Developer, Manager"
                            value={newRoleNameInput}
                            onChange={(e) => setNewRoleNameInput(e.target.value)}
                            maxLength={24}
                            className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all"
                            autoFocus
                            disabled={isCreatingRole}
                          />
                        </div>

                        {/* Divider */}
                        <div className="border-t border-border" />

                        {/* Role Color Section */}
                        <div className="space-y-3">
                          <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                            <Palette className="h-5 w-5 text-foreground-secondary" />
                            Role Color
                          </label>

                          {/* Color Presets */}
                          <div className="flex flex-wrap items-center gap-2">
                            {/* Preset Colors */}
                            {[
                              { color: '#ef4444', name: 'Red' },
                              { color: '#f97316', name: 'Orange' },
                              { color: '#eab308', name: 'Yellow' },
                              { color: '#22c55e', name: 'Green' },
                              { color: '#14b8a6', name: 'Teal' },
                              { color: '#3b82f6', name: 'Blue' },
                              { color: '#8b5cf6', name: 'Purple' },
                              { color: '#ec4899', name: 'Pink' },
                            ].map(({ color, name }) => (
                              <Tooltip key={color}>
                                <TooltipTrigger asChild>
                                  <button
                                    type="button"
                                    onClick={() => setNewRoleColor(color)}
                                    disabled={isCreatingRole}
                                    className={`h-8 w-8 rounded-lg border-2 transition-all flex items-center justify-center ${newRoleColor === color
                                      ? 'border-white scale-110 shadow-lg'
                                      : 'border-transparent hover:scale-105'
                                      }`}
                                    style={{ backgroundColor: color }}
                                  >
                                    {newRoleColor === color && (
                                      <Check className="h-4 w-4 text-white drop-shadow-md" />
                                    )}
                                  </button>
                                </TooltipTrigger>
                                <TooltipContent>{name}</TooltipContent>
                              </Tooltip>
                            ))}

                            {/* Custom Color Picker */}
                            <Tooltip>
                              <TooltipTrigger asChild>
                            <div className="relative">
                              <input
                                type="color"
                                value={newRoleColor || '#6b7280'}
                                onChange={(e) => setNewRoleColor(e.target.value)}
                                className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
                                disabled={isCreatingRole}
                              />
                              <div
                                className={`h-8 w-8 rounded-lg border-2 cursor-pointer transition-all flex items-center justify-center ${newRoleColor && ![
                                  '#ef4444', '#f97316', '#eab308', '#22c55e',
                                  '#14b8a6', '#3b82f6', '#8b5cf6', '#ec4899'
                                ].includes(newRoleColor)
                                  ? 'border-white scale-110 shadow-lg'
                                  : 'border-dashed border-border hover:border-foreground-secondary/50'
                                  }`}
                                style={{
                                  backgroundColor: newRoleColor && ![
                                    '#ef4444', '#f97316', '#eab308', '#22c55e',
                                    '#14b8a6', '#3b82f6', '#8b5cf6', '#ec4899'
                                  ].includes(newRoleColor) ? newRoleColor : 'transparent'
                                }}
                              >
                                {(!newRoleColor || [
                                  '#ef4444', '#f97316', '#eab308', '#22c55e',
                                  '#14b8a6', '#3b82f6', '#8b5cf6', '#ec4899'
                                ].includes(newRoleColor)) && (
                                    <Plus className="h-4 w-4 text-foreground-secondary" />
                                  )}
                                {newRoleColor && ![
                                  '#ef4444', '#f97316', '#eab308', '#22c55e',
                                  '#14b8a6', '#3b82f6', '#8b5cf6', '#ec4899'
                                ].includes(newRoleColor) && (
                                    <Check className="h-4 w-4 text-white drop-shadow-md" />
                                  )}
                              </div>
                            </div>
                              </TooltipTrigger>
                              <TooltipContent>Custom color</TooltipContent>
                            </Tooltip>

                            {/* Clear color button - only show when a color is selected */}
                            {newRoleColor && (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <button
                                    type="button"
                                    onClick={() => setNewRoleColor('')}
                                    disabled={isCreatingRole}
                                    className="h-8 w-8 rounded-lg border border-border text-foreground-secondary hover:text-foreground hover:border-foreground-secondary/50 transition-all flex items-center justify-center"
                                  >
                                    <X className="h-4 w-4" />
                                  </button>
                                </TooltipTrigger>
                                <TooltipContent>Clear color</TooltipContent>
                              </Tooltip>
                            )}
                          </div>

                          {/* Live Preview */}
                          {newRoleNameInput && (
                            <div className="pt-3 border-t border-border/50">
                              <div className="flex items-center gap-2">
                                <span className="text-xs text-foreground-secondary">Preview:</span>
                                <RoleBadge
                                  role={newRoleNameInput.toLowerCase()}
                                  roleDisplayName={newRoleNameInput}
                                  roleColor={newRoleColor || null}
                                />
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Permissions Editor */}
                        <div className="pt-4 border-t border-border">
                          <div className="mb-4">
                            <h3 className="flex items-center gap-2 text-base font-semibold text-foreground">
                              <Shield className="h-5 w-5 text-foreground-secondary" />
                              Permissions
                            </h3>
                          </div>

                          <PermissionEditor
                            permissions={newRolePermissions}
                            onSave={async () => { }}
                            onChange={setNewRolePermissions}
                            hideActions={true}
                            currentUserPermissions={effectivePermissions}
                            isOrgOwner={isOrgOwner}
                          />
                        </div>
                      </div>
                    </div>

                    {/* Footer */}
                    <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border">
                      <Button
                        variant="outline"
                        onClick={() => {
                          setShowAddRoleSidepanel(false);
                          setNewRoleNameInput('');
                          setNewRoleColor('#3b82f6');
                          setNewRolePermissions({
                            view_settings: false,
                            manage_billing: false,
                            view_activity: false,
                            view_compliance: false,
                            edit_policies: false,
                            interact_with_security_agent: false,
                            manage_aegis: false,
                            view_members: false,
                            add_members: false,
                            edit_roles: false,
                            edit_permissions: false,
                            kick_members: false,
                            manage_teams_and_projects: false,
                            manage_integrations: false,
                            view_overview: false,
                          });
                        }}
                        disabled={isCreatingRole}
                      >
                        Cancel
                      </Button>
                      <Button
                        onClick={async () => {
                          await handleCreateRole(newRolePermissions);
                        }}
                        disabled={isCreatingRole || !newRoleNameInput.trim()}
                        className="bg-primary/90 text-primary-foreground hover:bg-primary/80 border border-primary-foreground/10 hover:border-primary-foreground/20"
                      >
                        {isCreatingRole ? (
                          <>
                            <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                            Create Role
                          </>
                        ) : (
                          <>
                            <Save className="h-4 w-4 mr-2" />
                            Create Role
                          </>
                        )}
                      </Button>
                    </div>
                  </div>
                </div>
              )}

              {/* Role Settings Side Panel */}
              {showRoleSettingsModal && selectedRoleForSettings && editingRolePermissions && (() => {
                // Calculate if this role can be edited
                const userRank = organization?.user_rank ?? 0;
                const isViewingOwnRole = organization?.role === selectedRoleForSettings.name;
                const isRoleAboveRank = selectedRoleForSettings.display_order < userRank;
                const canEditThisRole = selectedRoleForSettings.name !== 'owner' && !isViewingOwnRole && !isRoleAboveRank;
                // Owner can edit owner role's name/color; for other roles use canEditThisRole
                const canEditNameAndColor = selectedRoleForSettings.name === 'owner' ? isOrgOwner : canEditThisRole;

                return (
                  <div className="fixed inset-0 z-50">
                    {/* Backdrop */}
                    <div
                      className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
                      onClick={() => {
                        setShowRoleSettingsModal(false);
                        setSelectedRoleForSettings(null);
                        setEditingRolePermissions(null);
                        setEditingRoleName('');
                      }}
                    />

                    {/* Side Panel */}
                    <div
                      className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {/* Header */}
                      <div className="px-6 py-5 border-b border-border bg-background-card-header flex-shrink-0">
                        <h2 className="text-xl font-semibold text-foreground">
                          {selectedRoleForSettings.display_name || selectedRoleForSettings.name.charAt(0).toUpperCase() + selectedRoleForSettings.name.slice(1)} Settings
                        </h2>
                      </div>

                      {/* Content */}
                      <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
                        <div className="space-y-6">
                          {/* Read-only notice when user cannot edit name/color */}
                          {!canEditNameAndColor && (
                            <div className="px-4 py-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
                              <p className="text-sm text-amber-400">
                                {selectedRoleForSettings.name === 'owner'
                                  ? 'The owner role cannot be modified.'
                                  : isViewingOwnRole
                                    ? 'You cannot edit your own role.'
                                    : 'You cannot edit roles above your rank.'}
                              </p>
                            </div>
                          )}

                          {/* Role Name - owner can edit when they are the org owner */}
                          <div className="space-y-3">
                            <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                              <Tag className="h-5 w-5 text-foreground-secondary" />
                              Role Name
                            </label>
                            <input
                              type="text"
                              value={editingRoleName}
                              onChange={(e) => setEditingRoleName(e.target.value)}
                              placeholder="Enter role name"
                              maxLength={24}
                              disabled={!canEditNameAndColor}
                              className={`w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all ${!canEditNameAndColor ? 'opacity-60 cursor-not-allowed' : ''}`}
                            />
                          </div>

                          {/* Divider */}
                          <div className="border-t border-border" />

                          {/* Role Color */}
                          <div className="space-y-3">
                            <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                              <Palette className="h-5 w-5 text-foreground-secondary" />
                              Role Color
                            </label>

                            {/* Color Presets */}
                            <div className="flex flex-wrap items-center gap-2">
                              {/* Preset Colors */}
                              {[
                                { color: '#ef4444', name: 'Red' },
                                { color: '#f97316', name: 'Orange' },
                                { color: '#eab308', name: 'Yellow' },
                                { color: '#22c55e', name: 'Green' },
                                { color: '#14b8a6', name: 'Teal' },
                                { color: '#3b82f6', name: 'Blue' },
                                { color: '#8b5cf6', name: 'Purple' },
                                { color: '#ec4899', name: 'Pink' },
                              ].map(({ color, name }) => (
                                <Tooltip key={color}>
                                  <TooltipTrigger asChild>
                                    <button
                                      type="button"
                                    onClick={() => setEditingRoleColor(color)}
                                    disabled={isSavingRole || !canEditNameAndColor}
                                      className={`h-8 w-8 rounded-lg border-2 transition-all flex items-center justify-center ${editingRoleColor === color
                                        ? 'border-white scale-110 shadow-lg'
                                        : 'border-transparent hover:scale-105'
                                        } ${!canEditNameAndColor ? 'opacity-60 cursor-not-allowed' : ''}`}
                                      style={{ backgroundColor: color }}
                                    >
                                      {editingRoleColor === color && (
                                        <Check className="h-4 w-4 text-white drop-shadow-md" />
                                      )}
                                    </button>
                                  </TooltipTrigger>
                                  <TooltipContent>{name}</TooltipContent>
                                </Tooltip>
                              ))}

                              {/* Custom Color Picker */}
                              <Tooltip>
                                <TooltipTrigger asChild>
                              <div className={`relative ${!canEditNameAndColor ? 'opacity-60 pointer-events-none' : ''}`}>
                                <input
                                  type="color"
                                  value={editingRoleColor || '#6b7280'}
                                  onChange={(e) => setEditingRoleColor(e.target.value)}
                                  className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
                                  disabled={isSavingRole || !canEditNameAndColor}
                                />
                                <div
                                  className={`h-8 w-8 rounded-lg border-2 cursor-pointer transition-all flex items-center justify-center ${editingRoleColor && ![
                                    '#ef4444', '#f97316', '#eab308', '#22c55e',
                                    '#14b8a6', '#3b82f6', '#8b5cf6', '#ec4899'
                                  ].includes(editingRoleColor)
                                    ? 'border-white scale-110 shadow-lg'
                                    : 'border-dashed border-border hover:border-foreground-secondary/50'
                                    }`}
                                  style={{
                                    backgroundColor: editingRoleColor && ![
                                      '#ef4444', '#f97316', '#eab308', '#22c55e',
                                      '#14b8a6', '#3b82f6', '#8b5cf6', '#ec4899'
                                    ].includes(editingRoleColor) ? editingRoleColor : 'transparent'
                                  }}
                                >
                                  {(!editingRoleColor || [
                                    '#ef4444', '#f97316', '#eab308', '#22c55e',
                                    '#14b8a6', '#3b82f6', '#8b5cf6', '#ec4899'
                                  ].includes(editingRoleColor)) && (
                                      <Plus className="h-4 w-4 text-foreground-secondary" />
                                    )}
                                  {editingRoleColor && ![
                                    '#ef4444', '#f97316', '#eab308', '#22c55e',
                                    '#14b8a6', '#3b82f6', '#8b5cf6', '#ec4899'
                                  ].includes(editingRoleColor) && (
                                      <Check className="h-4 w-4 text-white drop-shadow-md" />
                                    )}
                                </div>
                              </div>
                              </TooltipTrigger>
                              <TooltipContent>Custom color</TooltipContent>
                            </Tooltip>

                              {/* Clear color button - only show when a color is selected */}
                              {editingRoleColor && canEditNameAndColor && (
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <button
                                      type="button"
                                      onClick={() => setEditingRoleColor('')}
                                      disabled={isSavingRole}
                                      className="h-8 w-8 rounded-lg border border-border text-foreground-secondary hover:text-foreground hover:border-foreground-secondary/50 transition-all flex items-center justify-center"
                                    >
                                      <X className="h-4 w-4" />
                                    </button>
                                  </TooltipTrigger>
                                  <TooltipContent>Clear color</TooltipContent>
                                </Tooltip>
                              )}
                            </div>

                            {/* Live Preview */}
                            {editingRoleName && (
                              <div className="pt-3 border-t border-border/50">
                                <div className="flex items-center gap-2">
                                  <span className="text-xs text-foreground-secondary">Preview:</span>
                                  <RoleBadge
                                    role={editingRoleName.toLowerCase()}
                                    roleDisplayName={editingRoleName}
                                    roleColor={editingRoleColor || null}
                                  />
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Permissions - only for non-default roles OR member role */}
                          {(!selectedRoleForSettings.is_default || selectedRoleForSettings.name === 'member') && (
                            <div className={`space-y-4 pt-4 border-t border-border ${!canEditThisRole ? 'opacity-60 pointer-events-none' : ''}`}>
                              <div>
                                <h3 className="flex items-center gap-2 text-base font-semibold text-foreground">
                                  <Shield className="h-5 w-5 text-foreground-secondary" />
                                  Permissions
                                </h3>
                              </div>

                              <PermissionEditor
                                permissions={editingRolePermissions}
                                onSave={(perms) => handleSaveRolePermissions(selectedRoleForSettings, perms)}
                                onChange={(perms) => canEditThisRole && setEditingRolePermissions(perms)}
                                hideActions={true}
                                isLoading={isSavingRole}
                                currentUserPermissions={effectivePermissions}
                                isOrgOwner={isOrgOwner}
                              />
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Footer - fixed at bottom, always visible */}
                      <div className="flex-shrink-0 px-6 py-4 border-t border-border bg-background flex items-center justify-end gap-3">
                        {canEditNameAndColor || canEditThisRole ? (
                          <>
                            <Button
                              variant="outline"
                              onClick={() => {
                                setShowRoleSettingsModal(false);
                                setSelectedRoleForSettings(null);
                                setEditingRolePermissions(null);
                                setEditingRoleName('');
                              }}
                              disabled={isSavingRole}
                            >
                              Cancel
                            </Button>
                            <Button
                              onClick={async () => {
                                if (!id || !selectedRoleForSettings.id || !editingRoleName.trim()) return;
                                try {
                                  setIsSavingRole(true);
                                  const isMember = selectedRoleForSettings.name === 'member';
                                  const payload: { display_name: string; color: string | null; permissions?: RolePermissions } = {
                                    display_name: editingRoleName.trim(),
                                    color: editingRoleColor || null,
                                  };
                                  if ((!selectedRoleForSettings.is_default || isMember) && canEditThisRole) {
                                    payload.permissions = editingRolePermissions;
                                  }
                                  const updatedRole = await api.updateOrganizationRole(id, selectedRoleForSettings.id, payload);

                                  setAllRoles(prevRoles =>
                                    prevRoles.map(r =>
                                      r.id === selectedRoleForSettings.id
                                        ? { ...r, display_name: updatedRole.display_name, color: updatedRole.color, permissions: updatedRole.permissions || r.permissions }
                                        : r
                                    )
                                  );

                                  setShowRoleSettingsModal(false);
                                  setSelectedRoleForSettings(null);
                                  setEditingRolePermissions(null);
                                  setEditingRoleName('');
                                  window.dispatchEvent(new CustomEvent('rolesUpdated'));
                                  toast({ title: 'Role updated', description: 'The role has been updated successfully.' });
                                  loadRoles().catch(() => {});
                                } catch (error: any) {
                                  toast({ title: 'Failed to update role', description: error.message || 'Failed to update role. Please try again.', variant: 'destructive' });
                                } finally {
                                  setIsSavingRole(false);
                                }
                              }}
                              disabled={isSavingRole || !editingRoleName.trim()}
                              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                            >
                              {isSavingRole ? (
                                <>
                                  <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                                  Save Changes
                                </>
                              ) : (
                                <>
                                  <Save className="h-4 w-4 mr-2" />
                                  Save Changes
                                </>
                              )}
                            </Button>
                          </>
                        ) : (
                          <Button
                            variant="outline"
                            onClick={() => {
                              setShowRoleSettingsModal(false);
                              setSelectedRoleForSettings(null);
                              setEditingRolePermissions(null);
                              setEditingRoleName('');
                            }}
                          >
                            Close
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Integration Configuration Sidepanel */}
              {showIntegrationConfigSidepanel && selectedIntegration && (
                <div className="fixed inset-0 z-50">
                  {/* Backdrop */}
                  <div
                    className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
                    onClick={() => {
                      setShowIntegrationConfigSidepanel(false);
                      setSelectedIntegration(null);
                    }}
                  />

                  {/* Side Panel */}
                  <div
                    className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {/* Header */}
                    <div className="px-6 py-5 border-b border-border flex items-center justify-between flex-shrink-0">
                      <div className="flex items-center gap-3">
                        <img
                          src={`/images/integrations/${selectedIntegration.id}.png`}
                          alt={selectedIntegration.name}
                          className="h-8 w-8 rounded"
                        />
                        <div>
                          <h2 className="text-xl font-semibold text-foreground">Configure {selectedIntegration.name}</h2>
                          <p className="text-sm text-foreground-secondary">
                            {selectedIntegration.type === 'notification' ? 'Choose what triggers notifications' : 'Choose what creates tickets'}
                          </p>
                        </div>
                      </div>
                      <button
                        onClick={() => {
                          setShowIntegrationConfigSidepanel(false);
                          setSelectedIntegration(null);
                        }}
                        className="text-foreground-secondary hover:text-foreground transition-colors"
                      >
                        <X className="h-5 w-5" />
                      </button>
                    </div>

                    {/* Content */}
                    <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
                      <div className="space-y-6">
                        <p className="text-sm text-foreground-secondary">
                          {selectedIntegration.type === 'notification'
                            ? `Select which events should trigger a ${selectedIntegration.name} notification:`
                            : `Select which events should automatically create a ${selectedIntegration.name} ticket:`
                          }
                        </p>

                        {/* Event Toggles */}
                        <div className="space-y-4">
                          {/* Vulnerabilities */}
                          <div className="flex items-center justify-between p-4 bg-background-card border border-border rounded-lg">
                            <div className="flex items-center gap-3">
                              <div className="h-10 w-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                                <Shield className="h-5 w-5 text-red-500" />
                              </div>
                              <div>
                                <h4 className="font-medium text-foreground">Vulnerabilities</h4>
                                <p className="text-sm text-foreground-secondary">
                                  New vulnerability findings and security alerts
                                </p>
                              </div>
                            </div>
                            <button
                              onClick={() => setIntegrationConfig(prev => ({ ...prev, vulnerabilities: !prev.vulnerabilities }))}
                              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${integrationConfig.vulnerabilities ? 'bg-primary' : 'bg-foreground-secondary/30'
                                }`}
                            >
                              <span
                                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${integrationConfig.vulnerabilities ? 'translate-x-6' : 'translate-x-1'
                                  }`}
                              />
                            </button>
                          </div>

                          {/* Aegis Activity */}
                          <div className="flex items-center justify-between p-4 bg-background-card border border-border rounded-lg">
                            <div className="flex items-center gap-3">
                              <div className="h-10 w-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
                                <svg className="h-5 w-5 text-purple-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                  <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
                                </svg>
                              </div>
                              <div>
                                <h4 className="font-medium text-foreground">Aegis Activity</h4>
                                <p className="text-sm text-foreground-secondary">
                                  AI agent actions, recommendations, and updates
                                </p>
                              </div>
                            </div>
                            <button
                              onClick={() => setIntegrationConfig(prev => ({ ...prev, aegis_activity: !prev.aegis_activity }))}
                              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${integrationConfig.aegis_activity ? 'bg-primary' : 'bg-foreground-secondary/30'
                                }`}
                            >
                              <span
                                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${integrationConfig.aegis_activity ? 'translate-x-6' : 'translate-x-1'
                                  }`}
                              />
                            </button>
                          </div>

                          {/* Administrative */}
                          <div className="flex items-center justify-between p-4 bg-background-card border border-border rounded-lg">
                            <div className="flex items-center gap-3">
                              <div className="h-10 w-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
                                <Users className="h-5 w-5 text-blue-500" />
                              </div>
                              <div>
                                <h4 className="font-medium text-foreground">Administrative</h4>
                                <p className="text-sm text-foreground-secondary">
                                  Member changes, role updates, and org settings
                                </p>
                              </div>
                            </div>
                            <button
                              onClick={() => setIntegrationConfig(prev => ({ ...prev, administrative: !prev.administrative }))}
                              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${integrationConfig.administrative ? 'bg-primary' : 'bg-foreground-secondary/30'
                                }`}
                            >
                              <span
                                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${integrationConfig.administrative ? 'translate-x-6' : 'translate-x-1'
                                  }`}
                              />
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Footer */}
                    <div className="px-6 py-4 border-t border-border flex items-center justify-end gap-3 flex-shrink-0">
                      <Button
                        variant="outline"
                        onClick={() => {
                          setShowIntegrationConfigSidepanel(false);
                          setSelectedIntegration(null);
                        }}
                      >
                        Cancel
                      </Button>
                      <Button
                        onClick={() => {
                          // TODO: Save integration config when integrations are implemented
                          toast({
                            title: 'Configuration saved',
                            description: `${selectedIntegration.name} notification settings have been updated.`,
                          });
                          setShowIntegrationConfigSidepanel(false);
                          setSelectedIntegration(null);
                        }}
                      >
                        <Save className="h-4 w-4 mr-2" />
                        Save Configuration
                      </Button>
                    </div>
                  </div>
                </div>
              )}

              {/* Custom Integration Dialog */}
              <Dialog open={showCustomIntegrationSidepanel} onOpenChange={(open) => {
                if (!open) {
                  setShowCustomIntegrationSidepanel(false);
                  setEditingCustomIntegration(null);
                  // Don't clear customIntegrationSecret here - it's needed to display after create
                }
              }}>
                <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden">
                  <div className="px-6 pt-6 pb-4 border-b border-border">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <DialogTitle>
                          {editingCustomIntegration ? 'Edit custom integration' : 'Add custom integration'}
                        </DialogTitle>
                        <DialogDescription className="mt-1">
                          {editingCustomIntegration
                            ? 'Update the webhook configuration for this integration.'
                            : customIntegrationType === 'notification'
                              ? 'Set up a custom webhook endpoint for notifications.'
                              : 'Set up a custom webhook endpoint for ticketing.'}
                        </DialogDescription>
                      </div>
                      <Link to="/docs/integrations" target="_blank" rel="noopener noreferrer">
                        <Button variant="outline" size="sm" className="text-xs shrink-0">
                          <BookOpen className="h-3.5 w-3.5 mr-1.5" />
                          Docs
                        </Button>
                      </Link>
                    </div>
                  </div>

                  <div className="px-6 py-4 grid gap-4 bg-background">
                    <div className="grid gap-2">
                      <Label htmlFor="custom-name">Name</Label>
                      <Input
                        id="custom-name"
                        value={customIntegrationName}
                        onChange={(e) => setCustomIntegrationName(e.target.value)}
                        placeholder=""
                      />
                    </div>

                    <div className="grid gap-2">
                      <div className="flex items-center gap-2">
                        <Label htmlFor="custom-webhook" className="flex-1">Webhook URL</Label>
                        {editingCustomIntegration && (
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs shrink-0"
                            onClick={async () => {
                              if (!organization?.id || !editingCustomIntegration) return;
                              if (!confirm('Regenerate the signing secret? The old secret will stop working immediately.')) return;
                              try {
                                const result = await api.updateCustomIntegration(organization.id, editingCustomIntegration.id, { regenerate_secret: true });
                                if (result.secret) {
                                  setNewlyCreatedIntegrationId(editingCustomIntegration.id);
                                  setCustomIntegrationSecret(result.secret);
                                  toast({ title: 'Secret regenerated', description: 'The new secret is shown in the table.' });
                                }
                              } catch (err: any) {
                                toast({ title: 'Error', description: err.message || 'Failed to regenerate secret.', variant: 'destructive' });
                              }
                            }}
                          >
                            Regenerate Secret
                          </Button>
                        )}
                      </div>
                      <Input
                        id="custom-webhook"
                        type="url"
                        value={customIntegrationWebhookUrl}
                        onChange={(e) => setCustomIntegrationWebhookUrl(e.target.value)}
                        placeholder=""
                      />
                    </div>

                    <div className="grid gap-2">
                      <Label>Icon (optional)</Label>
                      <div className="flex items-center gap-3">
                        <div className="relative flex-shrink-0">
                          {(customIntegrationIconPreview || customIntegrationIconFile) ? (
                            <>
                              <img
                                src={customIntegrationIconFile ? URL.createObjectURL(customIntegrationIconFile) : (customIntegrationIconPreview || '')}
                                alt=""
                                className="h-9 w-9 rounded-md border border-border object-contain bg-background-card"
                              />
                              <button
                                type="button"
                                onClick={() => {
                                  setCustomIntegrationIconFile(null);
                                  setCustomIntegrationIconPreview(null);
                                }}
                                className="absolute -top-1.5 -right-1.5 h-4 w-4 rounded-full bg-destructive text-destructive-foreground flex items-center justify-center hover:bg-destructive/90 transition-colors"
                                aria-label="Remove icon"
                              >
                                <X className="h-2.5 w-2.5" />
                              </button>
                            </>
                          ) : (
                            <div className="h-9 w-9 rounded-md flex items-center justify-center text-foreground-secondary">
                              <Webhook className="h-4 w-4" />
                            </div>
                          )}
                        </div>
                        <label className="cursor-pointer">
                          <div className="inline-flex items-center gap-2 h-9 rounded-md border border-border bg-background-card px-3 py-2.5 text-sm text-foreground transition-colors hover:border-foreground-secondary/40 file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-foreground-secondary focus-within:outline-none focus-within:ring-2 focus-within:ring-primary/50 focus-within:border-primary">
                            <Upload className="h-3.5 w-3.5 text-foreground-secondary shrink-0" />
                            <span>{customIntegrationIconFile ? customIntegrationIconFile.name : 'Upload image'}</span>
                          </div>
                          <input
                            type="file"
                            accept="image/png,image/jpeg,image/webp"
                            className="hidden"
                            onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (file) {
                                if (file.size > 256 * 1024) {
                                  toast({ title: 'Error', description: 'Image must be under 256KB.', variant: 'destructive' });
                                  return;
                                }
                                setCustomIntegrationIconFile(file);
                              }
                            }}
                          />
                        </label>
                      </div>
                    </div>

                  </div>

                  <DialogFooter className="px-6 py-4 bg-background">
                    <Button variant="outline" onClick={() => { setShowCustomIntegrationSidepanel(false); setEditingCustomIntegration(null); setCustomIntegrationSecret(null); }}>
                      Cancel
                    </Button>
                    <Button
                      className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                      disabled={!customIntegrationName.trim() || !customIntegrationWebhookUrl.trim() || customIntegrationSaving || !/^https?:\/\/[^\s]+$/i.test(customIntegrationWebhookUrl.trim())}
                      onClick={async () => {
                        if (!organization?.id) return;
                        setCustomIntegrationSaving(true);
                        try {
                          let iconUrl = customIntegrationIconPreview || undefined;
                          if (customIntegrationIconFile) {
                            const uploaded = await api.uploadIntegrationIcon(organization.id, customIntegrationIconFile);
                            iconUrl = uploaded.url;
                          }

                          if (editingCustomIntegration) {
                            await api.updateCustomIntegration(organization.id, editingCustomIntegration.id, {
                              name: customIntegrationName.trim(),
                              webhook_url: customIntegrationWebhookUrl.trim(),
                              icon_url: iconUrl,
                            });
                            toast({ title: 'Updated', description: 'Custom integration updated.' });
                            setShowCustomIntegrationSidepanel(false);
                            setEditingCustomIntegration(null);
                          } else {
                            const result = await api.createCustomIntegration(organization.id, {
                              name: customIntegrationName.trim(),
                              type: customIntegrationType,
                              webhook_url: customIntegrationWebhookUrl.trim(),
                              icon_url: iconUrl,
                            });
                            setNewlyCreatedIntegrationId(result.id);
                            setCustomIntegrationSecret(result.secret);
                            setShowCustomIntegrationSidepanel(false);
                            setEditingCustomIntegration(null);
                            toast({ title: 'Created', description: 'Custom integration created. Copy the signing secret from the table.' });
                          }
                          await loadConnections();
                        } catch (err: any) {
                          toast({ title: 'Error', description: err.message || 'Failed to save.', variant: 'destructive' });
                        } finally {
                          setCustomIntegrationSaving(false);
                        }
                      }}
                    >
                      {customIntegrationSaving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
                      {editingCustomIntegration ? 'Save changes' : 'Create connection'}
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>

              {/* Jira Data Center PAT Dialog */}
              <Dialog open={showJiraPatDialog} onOpenChange={setShowJiraPatDialog}>
                <DialogContent hideClose className="sm:max-w-[440px] bg-background p-0 gap-0">
                  <div className="px-6 pt-6 pb-4 border-b border-border">
                    <div className="flex items-center gap-3">
                      <img src="/images/integrations/jira.png" alt="Jira" className="h-7 w-7 rounded object-contain" />
                      <div>
                        <DialogTitle>Jira Data Center</DialogTitle>
                        <DialogDescription>Connect via Personal Access Token</DialogDescription>
                      </div>
                    </div>
                  </div>

                  <div className="px-6 py-6 grid gap-4 bg-background">
                    <div className="grid gap-2">
                      <Label htmlFor="jira-url">Server URL</Label>
                      <Input
                        id="jira-url"
                        type="url"
                        value={jiraPatBaseUrl}
                        onChange={(e) => setJiraPatBaseUrl(e.target.value)}
                        placeholder=""
                      />
                    </div>

                    <div className="grid gap-2">
                      <Label htmlFor="jira-pat">Personal Access Token</Label>
                      <Input
                        id="jira-pat"
                        type="password"
                        value={jiraPatToken}
                        onChange={(e) => setJiraPatToken(e.target.value)}
                        placeholder=""
                      />
                    </div>
                  </div>

                  <DialogFooter className="px-6 py-4 bg-background">
                    <Button variant="outline" onClick={() => setShowJiraPatDialog(false)}>Cancel</Button>
                    <Button
                      className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                      disabled={!jiraPatBaseUrl.trim() || !jiraPatToken.trim() || jiraPatSaving}
                      onClick={async () => {
                        if (!organization?.id) return;
                        setJiraPatSaving(true);
                        try {
                          await api.connectJiraPatOrg(organization.id, jiraPatBaseUrl.trim(), jiraPatToken.trim());
                          toast({ title: 'Connected', description: 'Jira Data Center connected successfully.' });
                          setShowJiraPatDialog(false);
                          await loadConnections();
                        } catch (err: any) {
                          toast({ title: 'Error', description: err.message || 'Failed to connect.', variant: 'destructive' });
                        } finally {
                          setJiraPatSaving(false);
                        }
                      }}
                    >
                      {jiraPatSaving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
                      Create connection
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>

              {/* Email Notification Dialog */}
              <Dialog open={showEmailDialog} onOpenChange={setShowEmailDialog}>
                <DialogContent hideClose className="sm:max-w-[440px] bg-background p-0 gap-0">
                  <div className="px-6 pt-6 pb-4 border-b border-border">
                    <div className="flex items-center gap-3">
                      <div className="h-7 w-7 rounded flex items-center justify-center text-foreground-secondary">
                        <Mail className="h-7 w-7" />
                      </div>
                      <div>
                        <DialogTitle>Add Email</DialogTitle>
                        <DialogDescription>Add an email address to receive notification alerts.</DialogDescription>
                      </div>
                    </div>
                  </div>

                  <div className="px-6 py-6 grid gap-4 bg-background">
                    <div className="grid gap-2">
                      <Label htmlFor="email-to-add">Email address</Label>
                      <Input
                        id="email-to-add"
                        type="email"
                        value={emailToAdd}
                        onChange={(e) => setEmailToAdd(e.target.value)}
                        placeholder="alerts@example.com"
                      />
                    </div>
                  </div>

                  <DialogFooter className="px-6 py-4 bg-background">
                    <Button variant="outline" onClick={() => setShowEmailDialog(false)}>Cancel</Button>
                    <Button
                      className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                      disabled={!emailToAdd.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailToAdd.trim()) || emailSaving}
                      onClick={async () => {
                        if (!organization?.id) return;
                        setEmailSaving(true);
                        try {
                          await api.createEmailNotification(organization.id, emailToAdd.trim());
                          toast({ title: 'Added', description: 'Email notification added successfully.' });
                          setShowEmailDialog(false);
                          setEmailToAdd('');
                          await loadConnections();
                        } catch (err: any) {
                          toast({ title: 'Error', description: err.message || 'Failed to add email.', variant: 'destructive' });
                        } finally {
                          setEmailSaving(false);
                        }
                      }}
                    >
                      {emailSaving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
                      Add
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>

            </div>
          </div>
        </div>
      </div>

      <Toaster position="bottom-right" />
    </>
  );
}



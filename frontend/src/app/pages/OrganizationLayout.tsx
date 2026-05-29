import { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, Outlet, useNavigate } from 'react-router-dom';
import OrgSidebar from '../../components/OrgSidebar';
import { SidebarInset, SidebarProvider } from '../../components/ui/sidebar';
import { InviteMemberDialog } from '../../components/InviteMemberDialog';
import { api, Organization, RolePermissions } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { useAuth } from '../../contexts/AuthContext';
import { getAvatarUrl, getDisplayNameOrNull } from '../../lib/userIdentity';
import { Toaster } from '../../components/ui/toaster';
import { BillingProvider } from '../../contexts/PlanContext';

export default function OrganizationLayout() {
  const { id } = useParams<{ id: string }>();
  // Initialize with cached data if available for instant display
  const [organization, setOrganization] = useState<Organization | null>(() => {
    if (!id) return null;
    return api.getCachedOrganization(id);
  });
  const { toast } = useToast();
  const navigate = useNavigate();
  const { user, signOut } = useAuth();
  const avatarUrl = getAvatarUrl(user);
  const fullName = getDisplayNameOrNull(user);

  // Cached permissions for instant tab display
  const cachedPermissions = useMemo(() => {
    if (!id) return null;
    const permissionsStr = localStorage.getItem(`org_permissions_${id}`);
    if (permissionsStr) {
      try {
        const perms = JSON.parse(permissionsStr);
        return perms as RolePermissions;
      } catch {
        return null;
      }
    }
    return null;
  }, [id]);

  const [dbPermissions, setDbPermissions] = useState<RolePermissions | null>(null);
  const [showInviteMemberDialog, setShowInviteMemberDialog] = useState(false);

  // Prefer DB permissions, fall back to cache, then to org payload.
  const userPermissions = useMemo(() => {
    if (dbPermissions) return dbPermissions;
    if (cachedPermissions) return cachedPermissions;
    if (organization?.permissions) return organization.permissions;
    return null;
  }, [organization?.permissions, cachedPermissions, dbPermissions]);

  useEffect(() => {
    if (!organization?.id || !organization?.role) {
      setDbPermissions(null);
      return;
    }

    if (organization.permissions != null && typeof organization.permissions === 'object') {
      setDbPermissions(organization.permissions);
      return;
    }

    const loadDbPermissions = async () => {
      try {
        const roles = await api.getOrganizationRoles(organization.id);
        const userRole = roles.find(r => r.name === organization.role);

        if (userRole?.permissions) {
          setDbPermissions(userRole.permissions);
          localStorage.setItem(`org_permissions_${organization.id}`, JSON.stringify(userRole.permissions));
        } else {
          console.warn(`Role ${organization.role} has no permissions defined in database`);
        }
      } catch (error) {
        console.error('Failed to load permissions:', error);
      }
    };

    loadDbPermissions();
  }, [organization?.id, organization?.role, organization?.permissions]);

  // OrgSidebar uses this to notify the rest of the app that teams may have
  // changed (e.g. after creating one) so listeners can refetch on their own.
  // We don't keep a local teams cache here — consumers self-fetch.
  const refetchTeamsAndNotify = useCallback(async () => {
    window.dispatchEvent(new CustomEvent('organization:teamsUpdated'));
  }, []);

  // InviteMemberDialog self-fetches members/invitations/roles when it opens.
  // We used to prefetch them here on every org page mount to make the dialog feel
  // instant, but that fired three API calls on every navigation — including pages
  // that never opened the dialog. The dialog has a ~50ms loading state on first
  // open in exchange.

  // Tab title: "Organization name | Deptex"
  useEffect(() => {
    if (!organization?.name) return;
    const prev = document.title;
    document.title = `${organization.name} | Deptex`;
    return () => { document.title = prev; };
  }, [organization?.name]);

  useEffect(() => {
    if (id) {
      const cachedOrg = api.getCachedOrganization(id);
      if (cachedOrg) {
        setOrganization(cachedOrg);
      } else if (organization && organization.id !== id) {
        // Navigating to a new id with no cache entry — clear stale org so the
        // sidebar shows the skeleton instead of the previous org's name/role.
        setOrganization(null);
      }
      loadOrganization();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  // Listen for overview-page "Invite member"
  useEffect(() => {
    const handler = () => setShowInviteMemberDialog(true);
    window.addEventListener('organization:openInvite', handler);
    return () => window.removeEventListener('organization:openInvite', handler);
  }, []);

  const loadOrganization = async () => {
    if (!id) return;

    try {
      const data = await api.getOrganization(id, false);
      setOrganization(data);
      if (data.role) {
        localStorage.setItem(`org_role_${id}`, data.role);
      }
    } catch (error: any) {
      console.error('Failed to load organization:', error);

      const status = error.response?.status || error.status;
      if (status === 403) {
        toast({ title: 'Access Denied', description: 'You do not have permission to view this organization' });
      } else if (status === 404) {
        toast({ title: 'Not Found', description: 'This organization does not exist' });
      } else {
        toast({ title: 'Error', description: error.message || 'Failed to load organization' });
      }

      if (status === 404 || status === 403) {
        localStorage.removeItem('deptex_default_org');
      }
      navigate('/organizations', { replace: true });
    }
  };

  // With a patch, update org state locally with no refetch — used after a
  // mutation whose new values are already known (e.g. renaming the org).
  // Called with no args it does a full refetch.
  const reloadOrganization = async (patch?: Partial<Organization>) => {
    if (patch) {
      setOrganization((prev) => (prev ? { ...prev, ...patch } : prev));
      return;
    }
    await loadOrganization();
  };

  if (!id) return null;

  return (
    <>
      <BillingProvider organizationId={id}>
        <SidebarProvider defaultOpen>
          <OrgSidebar
            organizationId={id}
            organization={organization}
            userPermissions={userPermissions}
            onRefetchTeams={refetchTeamsAndNotify}
            user={user}
            avatarUrl={avatarUrl}
            fullName={fullName}
            onSignOut={signOut}
          />
          <SidebarInset>
            <Outlet context={{ organization, reloadOrganization, userPermissions }} />
          </SidebarInset>
        </SidebarProvider>
      </BillingProvider>

      {organization && (
        <InviteMemberDialog
          open={showInviteMemberDialog}
          onOpenChange={setShowInviteMemberDialog}
          organizationId={id}
          organization={organization}
        />
      )}

      <Toaster position="bottom-right" />
    </>
  );
}

import { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, Outlet, useNavigate } from 'react-router-dom';
import OrgSidebar from '../../components/OrgSidebar';
import { SidebarInset, SidebarProvider } from '../../components/ui/sidebar';
import { CreateProjectSidebar } from '../../components/CreateProjectSidebar';
import { InviteMemberDialog } from '../../components/InviteMemberDialog';
import { api, Organization, RolePermissions, Team, Project, OrganizationMember, OrganizationInvitation, OrganizationRole } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { useAuth } from '../../contexts/AuthContext';
import { useUserProfile } from '../../hooks/useUserProfile';
import { Toaster } from '../../components/ui/toaster';
import { PlanProvider } from '../../contexts/PlanContext';

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
  const { avatarUrl } = useUserProfile();

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
  const [teams, setTeams] = useState<Team[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [showCreateProjectSidebar, setShowCreateProjectSidebar] = useState(false);
  const [createProjectLockedTeam, setCreateProjectLockedTeam] = useState<Team | null>(null);
  const [showInviteMemberDialog, setShowInviteMemberDialog] = useState(false);
  // Prefetched for Invite Member dialog so it opens instantly
  const [inviteMembers, setInviteMembers] = useState<OrganizationMember[]>([]);
  const [inviteInvitations, setInviteInvitations] = useState<OrganizationInvitation[]>([]);
  const [inviteRoles, setInviteRoles] = useState<OrganizationRole[]>([]);

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

  // Load teams (used by CreateProjectSidebar + InviteMemberDialog)
  const refetchTeams = useMemo(() => {
    if (!id) return async () => {};
    return async () => {
      try {
        const data = await api.getTeams(id);
        setTeams(data);
      } catch {
        setTeams([]);
      }
    };
  }, [id]);

  const refetchTeamsAndNotify = useCallback(async () => {
    await refetchTeams();
    window.dispatchEvent(new CustomEvent('organization:teamsUpdated'));
  }, [refetchTeams]);

  useEffect(() => {
    if (!id) {
      setTeams([]);
      return;
    }
    let cancelled = false;
    api.getTeams(id)
      .then((data) => { if (!cancelled) setTeams(data); })
      .catch(() => { if (!cancelled) setTeams([]); });
    return () => { cancelled = true; };
  }, [id]);

  // Load projects (used by CreateProjectSidebar event payloads)
  const refetchProjects = useMemo(() => {
    if (!id) return async () => {};
    return async () => {
      try {
        const data = await api.getProjects(id);
        setProjects(data);
      } catch {
        setProjects([]);
      }
    };
  }, [id]);

  const refetchProjectsAndNotify = useCallback(async () => {
    await refetchProjects();
    window.dispatchEvent(new CustomEvent('organization:projectsUpdated'));
  }, [refetchProjects]);

  useEffect(() => {
    if (!id) {
      setProjects([]);
      return;
    }
    let cancelled = false;
    api.getProjects(id)
      .then((data) => { if (!cancelled) setProjects(data); })
      .catch(() => { if (!cancelled) setProjects([]); });
    return () => { cancelled = true; };
  }, [id]);

  // Prefetch members/invitations/roles so Invite Member dialog opens instantly
  const refetchInviteData = useMemo(() => {
    if (!id) return async () => {};
    return async () => {
      try {
        const [membersData, invitationsData, rolesData] = await Promise.all([
          api.getOrganizationMembers(id),
          api.getOrganizationInvitations(id),
          api.getOrganizationRoles(id).catch(() => []),
        ]);
        setInviteMembers(membersData);
        setInviteInvitations(invitationsData);
        setInviteRoles(rolesData);
      } catch {
        setInviteMembers([]);
        setInviteInvitations([]);
        setInviteRoles([]);
      }
    };
  }, [id]);

  useEffect(() => {
    if (!id) {
      setInviteMembers([]);
      setInviteInvitations([]);
      setInviteRoles([]);
      return;
    }
    let cancelled = false;
    Promise.all([
      api.getOrganizationMembers(id),
      api.getOrganizationInvitations(id),
      api.getOrganizationRoles(id).catch(() => []),
    ])
      .then(([membersData, invitationsData, rolesData]) => {
        if (!cancelled) {
          setInviteMembers(membersData);
          setInviteInvitations(invitationsData);
          setInviteRoles(rolesData);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setInviteMembers([]);
          setInviteInvitations([]);
          setInviteRoles([]);
        }
      });
    return () => { cancelled = true; };
  }, [id]);

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
      if (cachedOrg && (!organization || organization.id !== id)) {
        setOrganization(cachedOrg);
      }
      loadOrganization();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  // Listen for overview-page "Create project" so Plus dropdown can open the sidebar
  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail;
      setCreateProjectLockedTeam(detail?.lockedTeam ?? null);
      setShowCreateProjectSidebar(true);
    };
    window.addEventListener('organization:openCreateProject', handler);
    return () => window.removeEventListener('organization:openCreateProject', handler);
  }, []);

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

  const reloadOrganization = async () => {
    await loadOrganization();
  };

  if (!id) return null;

  return (
    <>
      <PlanProvider organizationId={id}>
        <SidebarProvider defaultOpen>
          <OrgSidebar
            organizationId={id}
            organization={organization}
            userPermissions={userPermissions}
            onRefetchTeams={refetchTeamsAndNotify}
            user={user}
            avatarUrl={avatarUrl}
            onSignOut={signOut}
          />
          <SidebarInset>
            <Outlet context={{ organization, reloadOrganization, userPermissions }} />
          </SidebarInset>
        </SidebarProvider>
      </PlanProvider>

      {showCreateProjectSidebar && (
        <CreateProjectSidebar
          open={showCreateProjectSidebar}
          onClose={() => { setShowCreateProjectSidebar(false); setCreateProjectLockedTeam(null); }}
          organizationId={id}
          teams={teams}
          lockedTeam={createProjectLockedTeam}
          onProjectsReload={refetchProjectsAndNotify}
          onProjectCreated={(project, framework) => {
            window.dispatchEvent(new CustomEvent('organization:projectCreated', {
              detail: {
                id: project.id,
                name: project.name,
                owner_team_id: project.owner_team_id ?? null,
                team_ids: project.team_ids ?? [],
                framework: framework ?? project.framework ?? null,
              },
            }));
          }}
        />
      )}

      {organization && (
        <InviteMemberDialog
          open={showInviteMemberDialog}
          onOpenChange={setShowInviteMemberDialog}
          organizationId={id}
          organization={organization}
          sharedMembers={inviteMembers}
          sharedInvitations={inviteInvitations}
          sharedTeams={teams}
          sharedRoles={inviteRoles}
          onSuccess={refetchInviteData}
        />
      )}

      <Toaster position="bottom-right" />
    </>
  );
}

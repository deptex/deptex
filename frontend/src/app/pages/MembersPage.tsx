import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, useOutletContext } from 'react-router-dom';
import { Search, Link as LinkIcon, MoreVertical, Mail, Check, Plus, X, Loader2, Send } from 'lucide-react';
import { api, OrganizationMember, OrganizationInvitation, Team, Organization, OrganizationRole, RolePermissions } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { useAuth } from '../../contexts/AuthContext';
import { Button } from '../../components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
} from '../../components/ui/dialog';
import { RoleDropdown } from '../../components/RoleDropdown';
import { RoleBadge } from '../../components/RoleBadge';
import { TeamDropdown } from '../../components/TeamDropdown';
import { ProjectTeamMultiSelect } from '../../components/ProjectTeamMultiSelect';

interface InviteForm {
  email: string;
  role: string;
  team_ids?: string[];
}

interface OrganizationContextType {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

interface MembersPageProps {
  isSettingsSubpage?: boolean;
  inviteModalOpen?: boolean;
  onInviteModalOpenChange?: (open: boolean) => void;
}

export default function MembersPage({ isSettingsSubpage = false, inviteModalOpen, onInviteModalOpenChange }: MembersPageProps) {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();
  const { organization } = useOutletContext<OrganizationContextType>();
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [teams, setTeams] = useState<Team[]>([]);
  const [loading, setLoading] = useState(true);
  const [inviting, setInviting] = useState(false);
  const [changingRole, setChangingRole] = useState(false);
  const [addingToTeam, setAddingToTeam] = useState(false);
  const [activeTab, setActiveTab] = useState<'members' | 'invitations'>('members');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTeamFilter, setSelectedTeamFilter] = useState<string>('all');
  const [selectedRoleFilter, setSelectedRoleFilter] = useState<string>('all');
  const [inviteForms, setInviteForms] = useState<InviteForm[]>([{ email: '', role: 'member', team_ids: [] }]);
  const [shareLinkCopied, setShareLinkCopied] = useState(false);
  const [internalShowInviteModal, setInternalShowInviteModal] = useState(false);
  const showInviteModal = isSettingsSubpage && inviteModalOpen !== undefined
    ? inviteModalOpen
    : internalShowInviteModal;
  const setShowInviteModal = isSettingsSubpage && onInviteModalOpenChange
    ? onInviteModalOpenChange
    : setInternalShowInviteModal;
  const [showRoleSidebar, setShowRoleSidebar] = useState(false);
  const [showRemoveDialog, setShowRemoveDialog] = useState(false);
  const [showAddToTeamSidebar, setShowAddToTeamSidebar] = useState(false);
  const [selectedMember, setSelectedMember] = useState<OrganizationMember | null>(null);
  const [newRole, setNewRole] = useState<string>('member');
  const [selectedTeamIds, setSelectedTeamIds] = useState<string[]>([]);
  const [customRoles, setCustomRoles] = useState<OrganizationRole[]>([]);
  const [permissionsChecked, setPermissionsChecked] = useState(false);
  const [userRolePermissions, setUserRolePermissions] = useState<RolePermissions | null>(null);
  const { toast } = useToast();
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Get cached permissions
  const getCachedPermissions = (): RolePermissions | null => {
    if (organization?.permissions) return organization.permissions;
    if (id) {
      const cachedStr = localStorage.getItem(`org_permissions_${id}`);
      if (cachedStr) {
        try { return JSON.parse(cachedStr); } catch { return null; }
      }
    }
    return null;
  };

  // Permission check - redirect if user doesn't have view_members
  useEffect(() => {
    if (organization && id && !permissionsChecked) {
      const cachedPerms = getCachedPermissions();

      // If we have cached permissions and user doesn't have view_members, redirect
      if (cachedPerms && cachedPerms.view_members !== true) {
        navigate(`/organizations/${id}/projects`, { replace: true });
        return;
      }

      // Allow page to load
      setPermissionsChecked(true);
    }
  }, [organization, id, navigate, permissionsChecked]);

  useEffect(() => {
    if (id && permissionsChecked) {
      loadData();
    }
  }, [id, permissionsChecked]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && searchQuery) {
        setSearchQuery('');
        searchInputRef.current?.blur();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [searchQuery]);

  // Refine permissions check with database values after roles load
  useEffect(() => {
    if (customRoles.length > 0 && organization && id && permissionsChecked) {
      const userRole = customRoles.find(r => r.name === organization.role);
      if (userRole?.permissions) {
        setUserRolePermissions(userRole.permissions);

        // Double-check with database permissions (more accurate)
        if (!userRole.permissions.view_members) {
          navigate(`/organizations/${id}/projects`, { replace: true });
        }
      }
    }
  }, [customRoles, organization, id, navigate, permissionsChecked]);

  const loadData = async () => {
    if (!id) return;

    try {
      setLoading(true);
      const [membersData, invitationsData, teamsData, rolesData] = await Promise.all([
        api.getOrganizationMembers(id),
        api.getOrganizationInvitations(id),
        api.getTeams(id).catch(() => []),
        api.getOrganizationRoles(id).catch(() => []),
      ]);
      setMembers(membersData);
      setInvitations(invitationsData);
      setTeams(teamsData);
      setCustomRoles(rolesData);
    } catch (error: any) {
      console.error('Failed to load data:', error);
      toast({
        title: 'Error',
        description: error.message || 'Failed to load data',
      });
    } finally {
      setLoading(false);
    }
  };

  const getAllRoles = () => {
    const defaultRoles = [
      { name: 'owner', is_default: true },
      { name: 'member', is_default: true },
    ];
    // Combine and deduplicate by name
    const allRoles = [...defaultRoles, ...customRoles];
    const uniqueRoles = allRoles.filter((role, index, self) =>
      index === self.findIndex(r => r.name === role.name)
    );
    return uniqueRoles;
  };

  // Get roles that the user can assign based on hierarchy AND permissions
  const getAssignableRoles = () => {
    const userRank = organization?.user_rank ?? 0;
    const isOrgOwner = organization?.role === 'owner';
    const currentPermissions = userRolePermissions || getCachedPermissions();

    return customRoles
      .filter(role => {
        // 1. Hierarchy Check
        if (role.display_order < userRank || role.name === 'owner') {
          return false;
        }

        // 2. Permission Check
        if (isOrgOwner) return true; // Owners can assign anything below them

        // If we can't determine current permissions, don't allow assigning potentiallly powerful roles
        if (!currentPermissions) return false;

        // If target role has permissions, verify user has all of them
        if (role.permissions) {
          for (const [key, value] of Object.entries(role.permissions)) {
            // If target role has a permission enabled, user must also have it enabled
            if (value === true && !currentPermissions[key as keyof RolePermissions]) {
              return false;
            }
          }
        }

        return true;
      })
      .sort((a, b) => a.display_order - b.display_order);
  };

  const getRoleDisplayName = (roleName: string): string => {
    // First check custom roles (from database)
    const customRole = customRoles.find(r => r.name === roleName);
    if (customRole && 'display_name' in customRole && customRole.display_name) {
      return customRole.display_name;
    }

    // Fallback to default roles
    if (roleName === 'owner') return 'Owner';
    if (roleName === 'member') return 'Member';

    // Default: capitalize first letter
    return roleName.charAt(0).toUpperCase() + roleName.slice(1);
  };

  const getRoleColor = (roleName: string): string | undefined => {
    // First check custom roles (from database)
    const customRole = customRoles.find(r => r.name === roleName);
    return customRole?.color || undefined;
  };


  const handleInviteChange = (index: number, field: keyof InviteForm, value: string | string[]) => {
    const updated = [...inviteForms];
    updated[index] = { ...updated[index], [field]: value };
    setInviteForms(updated);
  };

  const handleSendInvites = async () => {
    if (!id) return;

    const form = inviteForms[0];
    if (!form || !form.email.trim()) {
      toast({
        title: 'Error',
        description: 'Please enter an email address',
      });
      return;
    }

    // Check if this email is already invited or already a member
    const emailLower = form.email.trim().toLowerCase();
    const alreadyInvited = invitations.some(inv => inv.email.toLowerCase() === emailLower);
    const alreadyMember = members.some(member => member.email.toLowerCase() === emailLower);

    if (alreadyMember) {
      toast({
        title: 'Already a Member',
        description: 'This person is already a member of the organization',
        variant: 'destructive',
      });
      return;
    }

    if (alreadyInvited) {
      toast({
        title: 'Already Invited',
        description: 'This person has already been invited',
        variant: 'destructive',
      });
      return;
    }

    setInviting(true);
    try {
      await api.createInvitation(id, form.email.trim(), form.role, form.team_ids && form.team_ids.length > 0 ? form.team_ids : undefined);

      // Clear the form and close modal
      setInviteForms([{ email: '', role: 'member', team_ids: [] }]);
      setShowInviteModal(false);

      // Switch to invitations tab and reload data
      setActiveTab('invitations');
      await loadData();

      toast({
        title: 'Success',
        description: 'Invitation sent successfully',
      });
    } catch (error: any) {
      // Check if it's a duplicate invitation error
      if (error.message?.includes('Already invited this person')) {
        toast({
          title: 'Already Invited',
          description: 'This person has already been invited',
          variant: 'destructive',
        });
      } else {
        toast({
          title: 'Error',
          description: error.message || 'Failed to send invitation',
          variant: 'destructive',
        });
      }
    } finally {
      setInviting(false);
    }
  };

  const handleCancelInvitation = async (invitationId: string) => {
    if (!id) return;

    // Find the invitation to restore if API call fails
    const invitationToCancel = invitations.find(inv => inv.id === invitationId);
    if (!invitationToCancel) return;

    // Optimistically remove invitation immediately
    setInvitations(prev => prev.filter(inv => inv.id !== invitationId));

    // Show success immediately
    toast({
      title: 'Success',
      description: 'Invitation cancelled',
    });

    // Cancel invitation in the background
    try {
      await api.cancelInvitation(id, invitationId);
    } catch (error: any) {
      // Restore invitation on error
      setInvitations(prev => {
        // Check if it's not already there (avoid duplicates)
        if (!prev.find(inv => inv.id === invitationId)) {
          return [...prev, invitationToCancel].sort((a, b) =>
            new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
          );
        }
        return prev;
      });

      toast({
        title: 'Error',
        description: error.message || 'Failed to cancel invitation',
        variant: 'destructive',
      });
    }
  };

  const handleChangeRole = (member: OrganizationMember) => {
    setSelectedMember(member);
    setNewRole(member.role);
    setShowRoleSidebar(true);
  };

  const handleUpdateRole = async () => {
    if (!id || !selectedMember) return;

    setChangingRole(true);
    try {
      await api.updateMemberRole(id, selectedMember.user_id, newRole);

      // Close sidebar and reset
      setShowRoleSidebar(false);
      setSelectedMember(null);

      // Reload data to get updated member
      await loadData();

      toast({
        title: 'Success',
        description: 'Member role updated successfully',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to update member role',
        variant: 'destructive',
      });
    } finally {
      setChangingRole(false);
    }
  };

  const handleRemoveMember = (member: OrganizationMember) => {
    setSelectedMember(member);
    setShowRemoveDialog(true);
  };

  const handleAddToTeam = (member: OrganizationMember) => {
    setSelectedMember(member);
    // Filter out teams the member is already in
    const memberTeamIds = member.teams?.map(t => t.id) || [];
    const availableTeams = teams.filter(team => !memberTeamIds.includes(team.id));
    if (availableTeams.length === 0) {
      toast({
        title: 'No Teams Available',
        description: 'This member is already in all teams.',
        variant: 'destructive',
      });
      return;
    }
    setSelectedTeamIds([]);
    setShowAddToTeamSidebar(true);
  };

  const handleAddToTeams = async () => {
    if (!id || !selectedMember || selectedTeamIds.length === 0) return;

    setAddingToTeam(true);
    try {
      await Promise.all(
        selectedTeamIds.map(teamId =>
          api.addTeamMember(id, teamId, selectedMember.user_id)
        )
      );

      // Close sidebar and reset
      setShowAddToTeamSidebar(false);
      setSelectedMember(null);
      setSelectedTeamIds([]);

      // Reload data to get updated member
      await loadData();

      toast({
        title: 'Success',
        description: `Member added to ${selectedTeamIds.length} team${selectedTeamIds.length > 1 ? 's' : ''}`,
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to add member to teams',
        variant: 'destructive',
      });
    } finally {
      setAddingToTeam(false);
    }
  };

  const handleConfirmRemove = async () => {
    if (!id || !selectedMember) return;

    const isSelf = user && selectedMember.user_id === user.id;
    const memberToRemove = selectedMember;

    // If removing self, navigate immediately (user is leaving)
    if (isSelf) {
      setShowRemoveDialog(false);
      setSelectedMember(null);
      navigate('/organizations');

      // Remove member in the background
      try {
        await api.removeMember(id, memberToRemove.user_id);
      } catch (error: any) {
        // If leaving fails, show error but user is already navigated away
        console.error('Failed to leave organization:', error);
      }
      return;
    }

    // For removing others, use optimistic update
    // Optimistically remove member immediately
    setMembers(prev => prev.filter(member => member.user_id !== memberToRemove.user_id));

    // Show success immediately
    toast({
      title: 'Success',
      description: 'Member removed successfully',
    });

    // Close dialog immediately
    setShowRemoveDialog(false);
    setSelectedMember(null);

    // Remove member in the background
    try {
      await api.removeMember(id, memberToRemove.user_id);
    } catch (error: any) {
      // Restore member on error
      setMembers(prev => {
        // Check if it's not already there (avoid duplicates)
        if (!prev.find(m => m.user_id === memberToRemove.user_id)) {
          return [...prev, memberToRemove].sort((a, b) =>
            a.email.localeCompare(b.email)
          );
        }
        return prev;
      });

      toast({
        title: 'Error',
        description: error.message || 'Failed to remove member',
        variant: 'destructive',
      });
    }
  };

  const handleResendInvitation = async (invitationId: string) => {
    if (!id) return;

    try {
      await api.resendInvitation(id, invitationId);

      toast({
        title: 'Success',
        description: 'Invitation resent',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to resend invitation',
      });
    }
  };

  const handleCopyShareLink = () => {
    if (!id) return;

    // Get the selected teams from the invite form if available
    const selectedTeamIds = inviteForms[0]?.team_ids || [];
    let shareLink = `${window.location.origin}/join/${id}`;

    if (selectedTeamIds.length > 0) {
      shareLink += `?teams=${selectedTeamIds.join(',')}`;
    }

    navigator.clipboard.writeText(shareLink);
    setShareLinkCopied(true);
    toast({
      title: 'Copied!',
      description: 'Share link copied to clipboard',
    });

    setTimeout(() => {
      setShareLinkCopied(false);
    }, 2000);
  };

  const filteredMembers = members
    .filter(member => {
      const matchesSearch = member.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
        member.full_name?.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesTeam = selectedTeamFilter === 'all' ||
        (member.teams?.map(t => t.id) || []).includes(selectedTeamFilter);

      const matchesRole = selectedRoleFilter === 'all' || member.role === selectedRoleFilter;

      return matchesSearch && matchesTeam && matchesRole;
    })
    .sort((a, b) => (a.rank ?? 999) - (b.rank ?? 999));

  const filteredInvitations = invitations.filter(invitation =>
    invitation.email.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Don't render if organization not loaded or permissions not checked yet
  if (!organization || !permissionsChecked) {
    return (
      <div className={isSettingsSubpage ? "h-full" : "mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8"}>
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </div>
    );
  }

  // Check permissions - if user doesn't have view_members, don't render (will redirect via useEffect)
  const currentPermissions = userRolePermissions || getCachedPermissions();
  if (!currentPermissions?.view_members) {
    return null;
  }

  if (loading) {
    return (
      <div className={isSettingsSubpage ? "h-full" : "mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8"}>
        {/* Tabs */}
        <div className="flex items-center justify-between border-b border-border mb-6">
          <div className="flex items-center gap-6">
            <button
              className="pb-3 text-sm font-medium text-foreground border-b-2 border-foreground"
            >
              Members
            </button>
            <button
              className="pb-3 text-sm font-medium text-foreground-secondary hover:text-foreground"
            >
              Pending Invitations
            </button>
          </div>
          {!isSettingsSubpage && (
            <Button
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm mb-1"
              disabled
            >
              <Plus className="h-4 w-4 mr-2" />
              Invite
            </Button>
          )}
        </div>

        {/* Search and Filters */}
        <div className="flex items-center gap-4 mb-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
            <input
              type="text"
              placeholder="Filter..."
              disabled
              className="w-full pl-9 pr-4 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary"
            />
          </div>
          <div className="relative min-w-[200px]">
            <select
              disabled
              className="w-full h-9 px-3 bg-background-card border border-border rounded-md text-sm text-foreground"
            >
              <option>All Roles</option>
            </select>
          </div>
          {teams.length > 0 && (
            <div className="relative min-w-[200px]">
              <select
                disabled
                className="w-full h-9 px-3 bg-background-card border border-border rounded-md text-sm text-foreground"
              >
                <option>All Teams</option>
              </select>
            </div>
          )}
        </div>

        {/* Loading Skeleton for Members List */}
        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          <table className="w-full table-fixed">
            <colgroup>
              <col style={{ width: 'auto' }} />
              <col style={{ width: '192px' }} />
              <col style={{ width: '40px' }} />
            </colgroup>
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Member
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Role
                </th>
                <th></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {[1, 2, 3].map((i) => (
                <tr key={i} className="animate-pulse">
                  <td className="px-4 py-3 min-w-0 overflow-hidden">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="h-10 w-10 rounded-full bg-muted flex-shrink-0" />
                      <div className="space-y-1">
                        <div className="h-4 bg-muted rounded w-32" />
                        <div className="h-3 bg-muted rounded w-48" />
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="h-5 w-16 bg-muted rounded" />
                  </td>
                  <td className="px-4 py-3">
                    <div className="h-4 w-4 bg-muted rounded" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  return (
    <div className={isSettingsSubpage ? "h-full" : "mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8"}>
      {/* Tabs */}
      <div className="flex items-center justify-between border-b border-border mb-6">
        <div className="flex items-center gap-6">
          <button
            onClick={() => setActiveTab('members')}
            className={`pb-3 text-sm font-medium transition-colors ${activeTab === 'members'
              ? 'text-foreground border-b-2 border-foreground'
              : 'text-foreground-secondary hover:text-foreground'
              }`}
          >
            Members
          </button>
          <button
            onClick={() => setActiveTab('invitations')}
            className={`pb-3 text-sm font-medium transition-colors ${activeTab === 'invitations'
              ? 'text-foreground border-b-2 border-foreground'
              : 'text-foreground-secondary hover:text-foreground'
              }`}
          >
            Pending Invitations
          </button>
        </div>
        {!isSettingsSubpage && (
          <Button
            onClick={() => setShowInviteModal(true)}
            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm mb-1"
          >
            <Plus className="h-4 w-4 mr-2" />
            Invite
          </Button>
        )}
      </div>

      {/* Search and Filters */}
      <div className="flex items-center gap-4 mb-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary pointer-events-none" />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Filter..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className={`w-full pl-9 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent ${searchQuery ? 'pr-14' : 'pr-4'}`}
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-xs font-medium text-foreground-secondary hover:text-foreground bg-transparent border border-border/60 hover:border-border transition-colors"
              aria-label="Clear search (Esc)"
            >
              Esc
            </button>
          )}
        </div>
        <div className="relative">
          <RoleDropdown
            value={selectedRoleFilter}
            onChange={(value) => setSelectedRoleFilter(value)}
            roles={[{ name: 'all', display_name: 'All Roles', is_default: true }, ...getAllRoles()]}
            getRoleDisplayName={(roleName) => {
              if (roleName === 'all') return 'All Roles';
              return getRoleDisplayName(roleName);
            }}
            getRoleColor={(roleName) => {
              if (roleName === 'all') return undefined;
              return getRoleColor(roleName);
            }}
            memberCounts={(() => {
              const counts: Record<string, number> = {};
              getAllRoles().forEach(role => {
                counts[role.name] = members.filter(m => m.role === role.name).length;
              });
              counts['all'] = members.length;
              return counts;
            })()}
            showBadges={true}
            className="min-w-[200px] [&>button]:h-9 [&>button]:py-0"
          />
        </div>
        {teams.length > 0 && (
          <div className="relative">
            <TeamDropdown
              value={selectedTeamFilter}
              onChange={(value) => setSelectedTeamFilter(value)}
              teams={teams}
              className="min-w-[200px] [&>button]:h-9 [&>button]:py-0"
              memberCounts={(() => {
                const counts: Record<string, number> = { all: members.length };
                teams.forEach(team => {
                  counts[team.id] = members.filter(m => (m.teams?.map(t => t.id) || []).includes(team.id)).length;
                });
                return counts;
              })()}
              showMemberCounts={true}
            />
          </div>
        )}
      </div>

      {/* Members/Invitations List */}
      {activeTab === 'members' || (activeTab === 'invitations' && invitations.length > 0) ? (
        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          {activeTab === 'members' ? (
            <table className="w-full table-fixed">
              <colgroup>
                <col style={{ width: 'auto' }} />
                <col style={{ width: '192px' }} />
                <col style={{ width: '40px' }} />
              </colgroup>
              <thead className="bg-background-card-header border-b border-border">
                <tr>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Member
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Role
                  </th>
                  <th></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
              {filteredMembers.length === 0 ? (
                <tr>
                  <td colSpan={3} className="px-4 py-8 text-center text-sm text-foreground-secondary">
                    No members matched this search.
                  </td>
                </tr>
              ) : filteredMembers.map((member) => (
                <tr key={member.user_id} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3 min-w-0 overflow-hidden">
                    <div className="flex items-center gap-3 min-w-0">
                      <img
                        src={member.avatar_url || '/images/blank_profile_image.png'}
                        alt={member.full_name || member.email}
                        className="h-10 w-10 rounded-full object-cover border border-border"
                        referrerPolicy="no-referrer"
                        onError={(e) => {
                          e.currentTarget.src = '/images/blank_profile_image.png';
                        }}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-foreground truncate flex items-center gap-2">
                          {member.full_name || member.email.split('@')[0]}
                          {user && member.email.toLowerCase() === user.email?.toLowerCase() && (
                            <span className="text-xs text-foreground-secondary font-normal">
                              (You)
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-foreground-secondary truncate flex items-center gap-2">
                          {member.email}
                          {member.teams && member.teams.length > 0 && (
                            <span className="text-xs text-foreground-secondary">
                              • {member.teams.map(t => t.name).join(', ')}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <RoleBadge
                      role={member.role}
                      roleDisplayName={getRoleDisplayName(member.role)}
                      roleColor={getRoleColor(member.role)}
                    />
                  </td>
                  <td className="px-4 py-3">
                  {/* Only show dropdown if there are actions available */
                    (() => {
                      const isCurrentUser = user && member.user_id === user.id;
                      // Fallback for permissions if user is owner (as owner should have all permissions)
                      const isOrgOwner = organization?.role === 'owner';
                      const canEditRoles = isOrgOwner || userRolePermissions?.edit_roles;
                      const canKickMembers = isOrgOwner || userRolePermissions?.kick_members;

                      // Hierarchy check: user's rank vs member's rank
                      const userRank = organization?.user_rank ?? 0;
                      const memberRank = member.rank ?? 0;
                      // Can only manage members with rank > user's rank (higher number = lower rank)
                      const canManageThisMember = memberRank > userRank;

                      // Check if there are any actions available for this member
                      // Current user can only leave, others can be managed if user has permissions and hierarchy allows
                      const hasActions = isCurrentUser ||
                        (canEditRoles && canManageThisMember) || // For Add to Team & Change Role
                        (canKickMembers && canManageThisMember); // For Remove Member

                      if (!hasActions) return null;

                      return (
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <button className="p-1 text-foreground-secondary hover:text-foreground transition-colors">
                              <MoreVertical className="h-4 w-4" />
                            </button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            {isCurrentUser ? (
                              <>
                                {isOrgOwner && (
                                  <DropdownMenuItem onClick={() => handleAddToTeam(member)}>
                                    Add to Team
                                  </DropdownMenuItem>
                                )}
                                <DropdownMenuItem
                                  onClick={() => {
                                    // Find current user's member record to check their role
                                    const currentUserMember = members.find(m => m.user_id === user.id);
                                    if (currentUserMember?.role === 'owner') {
                                      // Check if there are other owners
                                      const otherOwners = members.filter(m => m.role === 'owner' && m.user_id !== user.id);
                                      if (otherOwners.length === 0) {
                                        toast({
                                          title: 'Cannot Leave',
                                          description: 'Please promote someone else to owner first before leaving.',
                                          variant: 'destructive',
                                        });
                                        return;
                                      }
                                    }
                                    handleRemoveMember(member);
                                  }}
                                >
                                  Leave Organization
                                </DropdownMenuItem>
                              </>
                            ) : (
                              <>
                                {canEditRoles && canManageThisMember && (
                                  <DropdownMenuItem onClick={() => handleAddToTeam(member)}>
                                    Add to Team
                                  </DropdownMenuItem>
                                )}
                                {canEditRoles && canManageThisMember && (
                                  <DropdownMenuItem onClick={() => handleChangeRole(member)}>
                                    Change Role
                                  </DropdownMenuItem>
                                )}
                                {canKickMembers && canManageThisMember && (
                                  <DropdownMenuItem onClick={() => handleRemoveMember(member)}>
                                    Remove Member
                                  </DropdownMenuItem>
                                )}
                              </>
                            )}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      );
                    })()}
                  </td>
                </tr>
              ))}
              </tbody>
            </table>
          ) : (
            <table className="w-full">
              <thead className="bg-background-card-header border-b border-border">
                <tr>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Member
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Role / Teams
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Status
                  </th>
                  <th className="w-10"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
              {filteredInvitations.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-sm text-foreground-secondary">
                    No invitations matched this search.
                  </td>
                </tr>
              ) : filteredInvitations.map((invitation) => (
                <tr key={invitation.id} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="h-10 w-10 rounded-full bg-background-subtle flex items-center justify-center">
                        <Mail className="h-5 w-5 text-foreground-secondary" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-foreground truncate">{invitation.email}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-foreground-secondary">
                      Invited as {invitation.role}
                      {(() => {
                        const teamNames = invitation.team_names && invitation.team_names.length > 0
                          ? invitation.team_names
                          : (invitation.team_name ? [invitation.team_name] : []);
                        if (teamNames.length === 1) {
                          return ` for ${teamNames[0]}`;
                        } else if (teamNames.length > 1) {
                          return ` for ${teamNames.length} teams`;
                        }
                        return null;
                      })()}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="px-2 py-1 rounded text-xs font-medium border border-border bg-transparent text-foreground-secondary">
                      Pending
                    </div>
                  </td>
                  <td className="px-4 py-3">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <button className="p-1 text-foreground-secondary hover:text-foreground transition-colors">
                        <MoreVertical className="h-4 w-4" />
                      </button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={() => handleResendInvitation(invitation.id)}>
                        Resend Invitation
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => handleCancelInvitation(invitation.id)}>
                        Cancel Invitation
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                  </td>
                </tr>
              ))}
              </tbody>
            </table>
          )}
        </div>
      ) : (
        <div className="text-center py-12">
          {activeTab === 'invitations' && !isSettingsSubpage && (
            <Button
              onClick={() => setShowInviteModal(true)}
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
            >
              <Plus className="h-4 w-4 mr-2" />
              Invite Member
            </Button>
          )}
        </div>
      )}

      {/* Invite Dialog */}
      <Dialog open={showInviteModal} onOpenChange={(open) => {
        if (!open) {
          setShowInviteModal(false);
          setInviteForms([{ email: '', role: 'member', team_ids: [] }]);
        }
      }}>
        <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
          <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
            <DialogTitle>Invite new member</DialogTitle>
            <DialogDescription className="mt-1">
              Invite new members to your organization by email. You can assign them a role and optionally add them to a team.
            </DialogDescription>
          </div>

          <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
            <div className="grid gap-2">
              <label htmlFor="invite-email" className="text-sm font-medium text-foreground">Email Address</label>
              <input
                id="invite-email"
                type="email"
                placeholder=""
                value={inviteForms[0]?.email || ''}
                onChange={(e) => handleInviteChange(0, 'email', e.target.value)}
                className="w-full px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && inviteForms[0]?.email) {
                    handleSendInvites();
                  }
                }}
              />
            </div>

            <div className="grid gap-2">
              <label className="text-sm font-medium text-foreground">Role</label>
              <RoleDropdown
                value={inviteForms[0]?.role || 'member'}
                onChange={(value) => handleInviteChange(0, 'role', value)}
                roles={getAssignableRoles()}
                getRoleDisplayName={getRoleDisplayName}
                getRoleColor={getRoleColor}
                memberCounts={(() => {
                  const counts: Record<string, number> = {};
                  getAssignableRoles().forEach(role => {
                    counts[role.name] = members.filter(m => m.role === role.name).length;
                  });
                  return counts;
                })()}
                showBadges={true}
                variant="modal"
              />
            </div>

            {teams.length > 0 && (
              <div className="grid gap-2">
                <label className="text-sm font-medium text-foreground">Teams</label>
                <ProjectTeamMultiSelect
                  value={inviteForms[0]?.team_ids || []}
                  onChange={(value) => handleInviteChange(0, 'team_ids', value)}
                  teams={teams}
                  variant="modal"
                />
              </div>
            )}

            <div className="pt-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleCopyShareLink}
                className="text-xs"
              >
                {shareLinkCopied ? (
                  <>
                    <Check className="h-3 w-3 mr-1" />
                    Copied!
                  </>
                ) : (
                  <>
                    <LinkIcon className="h-3 w-3 mr-1" />
                    Copy Invite Link
                  </>
                )}
              </Button>
            </div>
          </div>

          <DialogFooter className="px-6 py-4 bg-background">
            <Button
              variant="outline"
              onClick={() => {
                setShowInviteModal(false);
                setInviteForms([{ email: '', role: 'member', team_ids: [] }]);
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleSendInvites}
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              disabled={inviting}
            >
              {inviting ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Send className="h-4 w-4 mr-2" />}
              Send Invitation
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Change Role Dialog */}
      <Dialog open={!!(showRoleSidebar && selectedMember)} onOpenChange={(open) => {
        if (!open) {
          setShowRoleSidebar(false);
          setSelectedMember(null);
        }
      }}>
        <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
          {selectedMember && (
            <>
              <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
                <DialogTitle>Change Role</DialogTitle>
                <DialogDescription className="mt-1">
                  Select a new role for {selectedMember.full_name || selectedMember.email.split('@')[0]}.
                </DialogDescription>
              </div>

              <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
                <div className="flex items-center gap-3 p-3 bg-background-card border border-border rounded-md">
                  <img
                    src={selectedMember.avatar_url || '/images/blank_profile_image.png'}
                    alt={selectedMember.full_name || selectedMember.email}
                    className="h-10 w-10 rounded-full object-cover border border-border"
                    onError={(e) => {
                      e.currentTarget.src = '/images/blank_profile_image.png';
                    }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-foreground truncate">
                      {selectedMember.full_name || selectedMember.email.split('@')[0]}
                    </div>
                    <div className="text-xs text-foreground-secondary truncate">
                      {selectedMember.email}
                    </div>
                  </div>
                </div>

                <div className="grid gap-2">
                  <label className="text-sm font-medium text-foreground">Role</label>
                  <RoleDropdown
                    value={newRole}
                    onChange={(value) => setNewRole(value)}
                    roles={getAssignableRoles()}
                    getRoleDisplayName={getRoleDisplayName}
                    getRoleColor={getRoleColor}
                    memberCounts={(() => {
                      const counts: Record<string, number> = {};
                      getAssignableRoles().forEach(role => {
                        counts[role.name] = members.filter(m => m.role === role.name).length;
                      });
                      return counts;
                    })()}
                    showBadges={true}
                    variant="modal"
                  />
                  <p className="text-xs text-foreground-secondary">
                    You can only assign roles at or below your rank level.
                  </p>
                </div>
              </div>

              <DialogFooter className="px-6 py-4 bg-background">
                <Button
                  variant="outline"
                  onClick={() => {
                    setShowRoleSidebar(false);
                    setSelectedMember(null);
                  }}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleUpdateRole}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                  disabled={changingRole}
                >
                  {changingRole ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Check className="h-4 w-4 mr-2" />}
                  Update Role
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Add to Team Dialog */}
      <Dialog open={!!(showAddToTeamSidebar && selectedMember)} onOpenChange={(open) => {
        if (!open) {
          setShowAddToTeamSidebar(false);
          setSelectedMember(null);
          setSelectedTeamIds([]);
        }
      }}>
        <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-visible max-h-[90vh] flex flex-col">
          {selectedMember && (
            <>
              <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
                <DialogTitle>Add to Team</DialogTitle>
                <DialogDescription className="mt-1">
                  Select one or more teams to add {selectedMember.full_name || selectedMember.email.split('@')[0]} to.
                </DialogDescription>
              </div>

              <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
                <div className="flex items-center gap-3 p-3 bg-background-card border border-border rounded-md">
                  <img
                    src={selectedMember.avatar_url || '/images/blank_profile_image.png'}
                    alt={selectedMember.full_name || selectedMember.email}
                    className="h-10 w-10 rounded-full object-cover border border-border"
                    onError={(e) => {
                      e.currentTarget.src = '/images/blank_profile_image.png';
                    }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-foreground truncate">
                      {selectedMember.full_name || selectedMember.email.split('@')[0]}
                    </div>
                    <div className="text-xs text-foreground-secondary truncate">
                      {selectedMember.email}
                    </div>
                  </div>
                </div>

                {teams.length > 0 ? (
                  <div className="grid gap-2">
                    <label className="text-sm font-medium text-foreground">Teams</label>
                    {(() => {
                      const memberTeamIds = selectedMember.teams?.map(t => t.id) || [];
                      const availableTeams = teams.filter(team => !memberTeamIds.includes(team.id));

                      if (availableTeams.length === 0) {
                        return (
                          <div className="p-4 bg-background-subtle border border-border rounded-md text-sm text-foreground-secondary">
                            This member is already in all teams.
                          </div>
                        );
                      }

                      return (
                        <ProjectTeamMultiSelect
                          value={selectedTeamIds}
                          onChange={setSelectedTeamIds}
                          teams={availableTeams}
                          variant="modal"
                        />
                      );
                    })()}
                  </div>
                ) : (
                  <div className="p-4 bg-background-subtle border border-border rounded-md text-sm text-foreground-secondary">
                    No teams available. Create a team first.
                  </div>
                )}
              </div>

              <DialogFooter className="px-6 py-4 bg-background">
                <Button
                  variant="outline"
                  onClick={() => {
                    setShowAddToTeamSidebar(false);
                    setSelectedMember(null);
                    setSelectedTeamIds([]);
                  }}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleAddToTeams}
                  disabled={selectedTeamIds.length === 0 || addingToTeam}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                >
                  {addingToTeam ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
                  {`Add to Team${selectedTeamIds.length > 1 ? 's' : ''}`}
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Remove Member Dialog */}
      {showRemoveDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-background-card border border-border rounded-lg shadow-lg w-full max-w-md">
            <div className="p-6 border-b border-border">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-semibold text-foreground">
                  {user && selectedMember?.user_id === user.id
                    ? 'Leave Organization'
                    : 'Remove Member'}
                </h2>
                <button
                  onClick={() => setShowRemoveDialog(false)}
                  className="p-1 text-foreground-secondary hover:text-foreground transition-colors"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>
            <div className="p-6">
              <p className="text-sm text-foreground-secondary">
                {user && selectedMember && selectedMember.user_id === user.id
                  ? `Are you sure you want to leave ${organization?.name || 'this organization'}? You will lose access to all organization resources.`
                  : `Are you sure you want to remove ${selectedMember?.full_name || selectedMember?.email || 'this member'} from the organization? This action cannot be undone.`}
              </p>
            </div>
            <div className="p-6 border-t border-border flex items-center justify-end gap-3">
              <Button variant="outline" onClick={() => setShowRemoveDialog(false)}>
                Cancel
              </Button>
              <Button
                onClick={handleConfirmRemove}
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              >
                {user && selectedMember && selectedMember.user_id === user.id ? 'Leave' : 'Remove'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


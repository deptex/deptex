import { useState, useEffect, useMemo } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import { Search, Plus, Users, MoreVertical, Check } from 'lucide-react';
import { api, TeamWithRole, TeamPermissions, TeamMember, TeamRole, OrganizationMember } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import { RoleDropdown } from '../../components/RoleDropdown';
import { RoleBadge } from '../../components/RoleBadge';
import { useAuth } from '../../contexts/AuthContext';

interface TeamContextType {
  team: TeamWithRole | null;
  reloadTeam: () => Promise<void>;
  organizationId: string;
  userPermissions: TeamPermissions | null;
  organization: { permissions?: { manage_teams_and_projects?: boolean }; } | null;
}

interface TeamMembersPageProps {
  isSettingsSubpage?: boolean;
}

export default function TeamMembersPage({ isSettingsSubpage = false }: TeamMembersPageProps) {
  const { team, organizationId, userPermissions, reloadTeam, organization } = useOutletContext<TeamContextType>();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [roles, setRoles] = useState<TeamRole[]>([]);
  const [orgMembers, setOrgMembers] = useState<OrganizationMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [addSearchQuery, setAddSearchQuery] = useState('');
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [selectedRoleId, setSelectedRoleId] = useState<string>('member');
  const [addingMember, setAddingMember] = useState(false);
  const [showRoleChangeModal, setShowRoleChangeModal] = useState(false);
  const [memberToChangeRole, setMemberToChangeRole] = useState<TeamMember | null>(null);
  const [newRole, setNewRole] = useState<string>('member');
  const [updatingRole, setUpdatingRole] = useState(false);
  const [showLeaveConfirmModal, setShowLeaveConfirmModal] = useState(false);
  const [memberToRemove, setMemberToRemove] = useState<string | null>(null);
  const [removingMember, setRemovingMember] = useState(false);
  const { toast } = useToast();

  const canManageMembers = userPermissions?.manage_members || userPermissions?.kick_members || false;
  const canAddMembers = userPermissions?.add_members || false;
  const canEditRoles = userPermissions?.edit_roles || false;

  // Get user's rank from team membership. If user has org-level permissions
  // (like org admin/owner), they get rank 0 (can assign any role)
  const userMembership = members.find(m => m.user_id === user?.id);
  // Check if user has org-level admin access (they're not a team member but have edit permissions)
  const isOrgLevelAccess = !userMembership && userPermissions?.edit_roles;
  // Check if user has org-level manage_teams_and_projects permission
  const hasOrgManagePermission = organization?.permissions?.manage_teams_and_projects || false;
  // Calculate the maximum valid rank (least powerful role) - used as fallback
  const maxValidRank = useMemo(() => {
    if (roles.length === 0) return 1; // Default "member" rank
    return Math.max(...roles.map(r => r.display_order));
  }, [roles]);
  // Calculate user's rank:
  // - Org-level admins get rank 0 (can assign any role)
  // - Team members use their membership rank
  // - If rank is invalid (999 or null), fall back to maxValidRank so they can assign at least that level
  const memberRank = userMembership?.rank;
  const isValidRank = memberRank !== null && memberRank !== undefined && memberRank <= maxValidRank;
  const userRank = isOrgLevelAccess ? 0 : (isValidRank ? memberRank : maxValidRank);

  // Filter members based on search query and always sort by team rank
  const filteredMembers = useMemo(() => {
    let result = members;

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      result = result.filter(member =>
        member.email.toLowerCase().includes(query) ||
        member.full_name?.toLowerCase().includes(query)
      );
    }

    // Always sort by team rank (lower rank number = higher priority)
    result = [...result].sort((a, b) => {
      const rankA = a.rank ?? 999;
      const rankB = b.rank ?? 999;
      return rankA - rankB;
    });

    return result;
  }, [members, searchQuery]);

  // Filter org members for adding (exclude current team members)
  const availableOrgMembers = useMemo(() => {
    const teamMemberIds = new Set(members.map(m => m.user_id));
    return orgMembers.filter(m => !teamMemberIds.has(m.user_id));
  }, [orgMembers, members]);

  const filteredAvailableMembers = useMemo(() => {
    if (!addSearchQuery.trim()) {
      return availableOrgMembers;
    }
    const query = addSearchQuery.toLowerCase();
    return availableOrgMembers.filter(member =>
      member.email.toLowerCase().includes(query) ||
      member.full_name?.toLowerCase().includes(query)
    );
  }, [availableOrgMembers, addSearchQuery]);

  // Calculate member counts per role for the dropdown
  const memberCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    members.forEach(member => {
      const roleName = member.role || 'member';
      counts[roleName] = (counts[roleName] || 0) + 1;
    });
    return counts;
  }, [members]);

  useEffect(() => {
    if (organizationId && team?.id) {
      loadData();
    }
  }, [organizationId, team?.id]);

  const loadData = async () => {
    if (!organizationId || !team?.id) return;

    try {
      setLoading(true);
      const [membersData, rolesData, orgMembersData] = await Promise.all([
        api.getTeamMembers(organizationId, team.id),
        api.getTeamRoles(organizationId, team.id),
        api.getOrganizationMembers(organizationId),
      ]);
      setMembers(membersData);
      setRoles(rolesData);
      setOrgMembers(orgMembersData);
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

  const handleAddMember = async () => {
    if (!organizationId || !team?.id || selectedUserIds.length === 0) return;

    try {
      setAddingMember(true);
      // Find the actual role ID for the selected role name
      const roleToUse = roles.find(r => r.name === selectedRoleId);
      const roleIdToSend = roleToUse?.id;

      await Promise.all(
        selectedUserIds.map(userId =>
          api.addTeamMember(organizationId, team.id, userId, roleIdToSend || undefined)
        )
      );
      toast({
        title: 'Success',
        description: selectedUserIds.length === 1 ? 'Member added to team' : 'Members added to team',
      });
      setShowAddModal(false);
      setSelectedUserIds([]);
      setSelectedRoleId('member');
      setAddSearchQuery('');
      loadData();
      reloadTeam();
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to add member',
        variant: 'destructive',
      });
    } finally {
      setAddingMember(false);
    }
  };

  // Open the confirmation modal instead of using native confirm()
  const handleRemoveMember = (userId: string) => {
    if (!organizationId || !team?.id) return;
    setMemberToRemove(userId);
    setShowLeaveConfirmModal(true);
  };

  // Actually perform the removal after confirmation
  const confirmRemoveMember = async () => {
    if (!organizationId || !team?.id || !memberToRemove) return;

    const userId = memberToRemove;
    const isSelf = user?.id === userId;

    try {
      setRemovingMember(true);
      await api.removeTeamMember(organizationId, team.id, userId);

      if (isSelf) {
        toast({
          title: 'Left Team',
          description: 'You have left the team.',
        });
        navigate(`/organizations/${organizationId}`);
      } else {
        setMembers(members.filter(m => m.user_id !== userId));
        toast({
          title: 'Success',
          description: 'Member removed from team',
        });
        reloadTeam();
      }
      setShowLeaveConfirmModal(false);
      setMemberToRemove(null);
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to remove member',
        variant: 'destructive',
      });
    } finally {
      setRemovingMember(false);
    }
  };

  const handleChangeRole = (member: TeamMember) => {
    setMemberToChangeRole(member);
    setNewRole(member.role);
    setShowRoleChangeModal(true);
  };

  const handleUpdateRole = async () => {
    if (!organizationId || !team?.id || !memberToChangeRole) return;

    const oldRole = memberToChangeRole.role;

    // Find the role ID for the new role name
    const roleToUse = roles.find(r => r.name === newRole);
    if (!roleToUse?.id) return;

    try {
      setUpdatingRole(true);
      await api.updateTeamMemberRole(organizationId, team.id, memberToChangeRole.user_id, roleToUse.id);
      setMembers(members.map(m => {
        if (m.user_id === memberToChangeRole.user_id) {
          return {
            ...m,
            role: newRole,
            role_display_name: roleToUse.display_name || newRole,
            role_color: roleToUse.color || null,
          };
        }
        return m;
      }));
      toast({
        title: 'Success',
        description: 'Member role updated',
      });
      setShowRoleChangeModal(false);
      setMemberToChangeRole(null);
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to update role',
        variant: 'destructive',
      });
    } finally {
      setUpdatingRole(false);
    }
  };

  const closeModal = () => {
    setShowAddModal(false);
    setSelectedUserIds([]);
    setSelectedRoleId('member');
    setAddSearchQuery('');
  };

  return (
    <main className={isSettingsSubpage ? "w-full" : "mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8"}>
      {/* Header */}
      <div className="flex items-center justify-between gap-4 mb-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
          <input
            type="text"
            placeholder="Filter members..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-64 pl-9 pr-4 h-8 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
          />
        </div>
        {(canAddMembers || hasOrgManagePermission) && (
          <Button
            onClick={() => setShowAddModal(true)}
            className="bg-primary text-primary-foreground hover:bg-primary/90 h-8 text-sm"
          >
            <Plus className="h-4 w-4 mr-2" />
            Add Member
          </Button>
        )}
      </div>

      {/* Members List */}
      {loading ? (
        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          <div className="px-4 py-3 bg-background-card-header border-b border-border grid grid-cols-[1fr_auto_32px] gap-4 items-center">
            <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Member</div>
            <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider justify-self-end">Role</div>
            <div className="sr-only">Actions</div>
          </div>

          <div className="divide-y divide-border">
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="px-4 py-3 grid grid-cols-[1fr_auto_32px] gap-4 items-center animate-pulse"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="h-10 w-10 bg-muted rounded-full border border-border"></div>
                  <div className="min-w-0">
                    <div className="h-4 bg-muted rounded w-24 mb-1"></div>
                    <div className="h-3 bg-muted rounded w-32"></div>
                  </div>
                </div>
                <div className="justify-self-end">
                  <div className="h-6 bg-muted rounded w-20 border border-border"></div>
                </div>
                <div className="justify-self-end">
                  <div className="h-4 w-4 bg-muted rounded-full" />
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : filteredMembers.length === 0 ? (
        <div className="py-8 text-center">
          {members.length === 0 ? (
            // No members in team at all - show actionable empty state
            <>
              <h3 className="text-lg font-semibold text-foreground mb-2">This team is empty</h3>
              <p className="text-foreground-secondary mb-6 max-w-sm mx-auto">
                Get started by adding members to collaborate on projects together.
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
                {/* Show "Add Yourself" button if user is in org but not in team */}
                {user && availableOrgMembers.some(m => m.user_id === user.id) && (canAddMembers || hasOrgManagePermission) && (
                  <Button
                    onClick={async () => {
                      if (!organizationId || !team?.id || !user?.id) return;
                      try {
                        setAddingMember(true);
                        // Add yourself as top ranked role (display_order 0)
                        const topRole = roles.find(r => r.display_order === 0);
                        await api.addTeamMember(organizationId, team.id, user.id, topRole?.id);
                        toast({
                          title: 'Welcome!',
                          description: `You have joined the team as ${topRole?.display_name || topRole?.name || 'admin'}.`,
                        });
                        loadData();
                        reloadTeam();
                      } catch (error: any) {
                        toast({
                          title: 'Error',
                          description: error.message || 'Failed to join team',
                          variant: 'destructive',
                        });
                      } finally {
                        setAddingMember(false);
                      }
                    }}
                    disabled={addingMember}
                    className="bg-primary text-primary-foreground hover:bg-primary/90"
                  >
                    {addingMember ? (
                      <>
                        <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                        Joining
                      </>
                    ) : (
                      <>
                        <Users className="h-4 w-4 mr-2" />
                        Join this team
                      </>
                    )}
                  </Button>
                )}
                {(canAddMembers || hasOrgManagePermission) && (
                  <Button
                    onClick={() => setShowAddModal(true)}
                    variant={user && availableOrgMembers.some(m => m.user_id === user.id) ? "outline" : "default"}
                    className={user && availableOrgMembers.some(m => m.user_id === user.id) ? "" : "bg-primary text-primary-foreground hover:bg-primary/90"}
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Add members
                  </Button>
                )}
                {!(canAddMembers || hasOrgManagePermission) && (
                  <p className="text-sm text-foreground-secondary">
                    Contact a team admin to add members.
                  </p>
                )}
              </div>
            </>
          ) : (
            // Has members but search returned no results
            <>
              <h3 className="text-lg font-semibold text-foreground mb-2">No members found</h3>
              <p className="text-foreground-secondary">No members match your search criteria.</p>
              <Button
                variant="ghost"
                onClick={() => setSearchQuery('')}
                className="mt-4 text-primary hover:text-primary/90"
              >
                Clear search
              </Button>
            </>
          )}
        </div>
      ) : (
        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          <div className="px-4 py-3 bg-background-card-header border-b border-border grid grid-cols-[1fr_auto_32px] gap-4 items-center">
            <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Member</div>
            <div className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider justify-self-end">Role</div>
            <div className="sr-only">Actions</div>
          </div>

          <div className="divide-y divide-border">
            {filteredMembers.map((member) => {
              const isCurrentUser = user && member.user_id === user.id;
              const isOwner = member.role === 'owner';

              const actions = (() => {
                const memberTeamRank = member.rank ?? 999;
                const memberOrgRank = member.org_rank ?? 999;

                // Get current user's org rank from the team response (user_org_rank is the actual org role rank)
                const currentUserOrgRank = (team as any)?.user_org_rank ?? 999;

                // Check if user_org_rank is loaded (not undefined)
                // If not loaded yet but user has org manage permission, assume they can manage
                // This fixes the race condition where members render before team data fully loads
                const isUserOrgRankLoaded = (team as any)?.user_org_rank !== undefined;

                // Permission hierarchy:
                // 1. If target has LOWER org rank (higher number) → can manage
                // 2. If SAME org rank AND target has lower team rank (higher number) → can manage
                // 3. If target has HIGHER org rank → cannot manage (even with lower team rank)
                // 4. If org rank not loaded yet but user has org manage permission → allow (will re-render when loaded)
                const canManageByHierarchy =
                  (!isUserOrgRankLoaded && hasOrgManagePermission) ||
                  memberOrgRank > currentUserOrgRank ||
                  (memberOrgRank === currentUserOrgRank && memberTeamRank > userRank);

                // Can kick if: has kick permission AND target is not owner AND hierarchy allows
                const canKickThisMember = (canManageMembers || hasOrgManagePermission) && !isOwner && canManageByHierarchy;

                // Can change role if: has edit_roles permission AND target is not owner AND hierarchy allows
                const canChangeThisMemberRole = (canEditRoles || hasOrgManagePermission) && !isOwner && canManageByHierarchy;

                // Allow changing own role ONLY if user has org-level manage_teams_and_projects
                const canChangeOwnRole = isCurrentUser && hasOrgManagePermission;

                const hasAnyAction = isCurrentUser || canChangeThisMemberRole || canKickThisMember;
                if (!hasAnyAction) return null;

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
                          {canChangeOwnRole && (
                            <DropdownMenuItem onClick={() => handleChangeRole(member)}>
                              Change Role
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuItem
                            onClick={() => {
                              if (isOwner) {
                                toast({
                                  title: 'Cannot Leave',
                                  description: 'Must transfer team ownership in the settings first.',
                                  variant: 'destructive',
                                });
                                return;
                              }
                              handleRemoveMember(member.user_id);
                            }}
                          >
                            Leave Team
                          </DropdownMenuItem>
                        </>
                      ) : (
                        <>
                          {canChangeThisMemberRole && (
                            <DropdownMenuItem onClick={() => handleChangeRole(member)}>
                              Change Role
                            </DropdownMenuItem>
                          )}
                          {canKickThisMember && (
                            <DropdownMenuItem onClick={() => handleRemoveMember(member.user_id)}>
                              Remove from Team
                            </DropdownMenuItem>
                          )}
                        </>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                );
              })();

              return (
                <div
                  key={member.user_id}
                  className="px-4 py-3 grid grid-cols-[1fr_auto_32px] gap-4 items-center hover:bg-table-hover transition-colors"
                >
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
                    <div className="min-w-0">
                      <div className="text-sm font-medium text-foreground truncate flex items-center gap-2">
                        {member.full_name || 'Unknown'}
                        {isCurrentUser && (
                          <span className="text-xs text-foreground-secondary font-normal">
                            (You)
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-foreground-secondary truncate">{member.email}</div>
                    </div>
                  </div>

                  <div className="justify-self-end">
                    <RoleBadge
                      role={member.role}
                      roleDisplayName={member.role_display_name}
                      roleColor={member.role_color}
                    />
                  </div>

                  <div className="justify-self-end">
                    {actions ?? <div className="w-6" />}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Add Member Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50">
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm"
            onClick={closeModal}
          />
          <div
            className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
              <h2 className="text-xl font-semibold text-foreground">Add Team Member</h2>
            </div>

            <div className="flex-1 overflow-y-auto px-6 py-6">
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-foreground mb-2">
                    Select Member
                  </label>
                  <div className="relative mb-2">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
                    <input
                      type="text"
                      placeholder="Search organization members..."
                      value={addSearchQuery}
                      onChange={(e) => setAddSearchQuery(e.target.value)}
                      className="w-full pl-9 pr-4 py-2 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                    />
                  </div>
                  <div className="max-h-48 overflow-y-auto border border-border rounded-md">
                    {filteredAvailableMembers.length === 0 ? (
                      <div className="p-4 text-sm text-foreground-secondary text-center">
                        No members available to add
                      </div>
                    ) : (
                      filteredAvailableMembers.map((member) => (
                        <button
                          key={member.user_id}
                          onClick={() => {
                            setSelectedUserIds((prev) =>
                              prev.includes(member.user_id)
                                ? prev.filter(id => id !== member.user_id)
                                : [...prev, member.user_id]
                            );
                          }}
                          className={`w-full flex items-center gap-3 px-3 py-2 text-left transition-colors ${
                            selectedUserIds.includes(member.user_id)
                              ? 'bg-background-card/80'
                              : 'hover:bg-background-card/60'
                          }`}
                        >
                          <img
                            src={member.avatar_url || '/images/blank_profile_image.png'}
                            alt={member.full_name || member.email}
                            className="h-8 w-8 rounded-full object-cover border border-border"
                            referrerPolicy="no-referrer"
                            onError={(e) => {
                              e.currentTarget.src = '/images/blank_profile_image.png';
                            }}
                          />
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium text-foreground">
                              {member.full_name || 'Unknown'}
                            </div>
                            <div className="text-xs text-foreground-secondary">{member.email}</div>
                          </div>
                          {selectedUserIds.includes(member.user_id) && (
                            <Check className="h-4 w-4 text-white flex-shrink-0" />
                          )}
                        </button>
                      ))
                    )}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-foreground mb-2">
                    Role
                  </label>
                  <RoleDropdown
                    value={selectedRoleId}
                    onChange={(value) => setSelectedRoleId(value)}
                    roles={hasOrgManagePermission ? roles.filter(r => r.name !== 'owner') : roles.filter(r => r.name !== 'owner' && r.display_order >= userRank)}
                    variant="modal"
                    className="w-full"
                    showBadges={true}
                    memberCounts={memberCounts}
                  />
                </div>
              </div>
            </div>

            <div className="px-6 py-5 flex items-center justify-end gap-3">
              <Button variant="outline" onClick={closeModal}>
                Cancel
              </Button>
              <Button
                onClick={handleAddMember}
                disabled={selectedUserIds.length === 0 || addingMember}
                className="bg-primary text-primary-foreground hover:bg-primary/90"
              >
                {addingMember ? (
                  <>
                    <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                    Adding
                  </>
                ) : (
                  selectedUserIds.length <= 1 ? 'Add Member' : `Add ${selectedUserIds.length} Members`
                )}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Change Role Modal */}
      {showRoleChangeModal && memberToChangeRole && (
        <div className="fixed inset-0 z-50">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
            onClick={() => {
              setShowRoleChangeModal(false);
              setMemberToChangeRole(null);
            }}
          />

          {/* Modal */}
          <div
            className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
              <h2 className="text-xl font-semibold text-foreground">
                Change Role
              </h2>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
              <div className="space-y-6">
                <div>
                  <p className="text-sm text-foreground-secondary mb-4">
                    Change the role for <strong>{memberToChangeRole.full_name || memberToChangeRole.email}</strong>
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-foreground mb-2">
                    Role
                  </label>
                  <RoleDropdown
                    value={newRole}
                    onChange={(value) => setNewRole(value)}
                    roles={hasOrgManagePermission ? roles.filter(r => r.name !== 'owner') : roles.filter(r => r.name !== 'owner' && r.display_order >= userRank)}
                    variant="modal"
                    className="w-full"
                    showBadges={true}
                    memberCounts={memberCounts}
                  />
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="px-6 py-5 flex items-center justify-end gap-3 flex-shrink-0">
              <Button
                variant="outline"
                onClick={() => {
                  setShowRoleChangeModal(false);
                  setMemberToChangeRole(null);
                }}
              >
                Cancel
              </Button>
              <Button
                onClick={handleUpdateRole}
                disabled={updatingRole}
                className="bg-primary text-primary-foreground hover:bg-primary/90"
              >
                {updatingRole ? (
                  <>
                    <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                    Updating
                  </>
                ) : (
                  'Update Role'
                )}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Leave/Remove Confirmation Modal */}
      {showLeaveConfirmModal && memberToRemove && (
        <div className="fixed inset-0 z-50">
          {/* Backdrop */}
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
            onClick={() => {
              setShowLeaveConfirmModal(false);
              setMemberToRemove(null);
            }}
          />

          {/* Modal - centered */}
          <div className="fixed inset-0 flex items-center justify-center p-4">
            <div
              className="bg-background border border-border rounded-lg shadow-2xl w-full max-w-md"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="px-6 py-5 border-b border-border">
                <h2 className="text-xl font-semibold text-foreground">
                  {user?.id === memberToRemove ? 'Leave Team' : 'Remove Member'}
                </h2>
              </div>

              {/* Content */}
              <div className="px-6 py-6">
                <p className="text-foreground-secondary">
                  {user?.id === memberToRemove
                    ? 'Are you sure you want to leave this team? You will need to be re-added by a team admin to rejoin.'
                    : 'Are you sure you want to remove this member from the team?'}
                </p>
              </div>

              {/* Footer */}
              <div className="px-6 py-5 border-t border-border flex items-center justify-end gap-3">
                <Button
                  variant="outline"
                  onClick={() => {
                    setShowLeaveConfirmModal(false);
                    setMemberToRemove(null);
                  }}
                  disabled={removingMember}
                >
                  Cancel
                </Button>
                <Button
                  onClick={confirmRemoveMember}
                  disabled={removingMember}
                  className="bg-red-600 text-white hover:bg-red-700"
                >
                  {removingMember ? (
                    <>
                      <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                      {user?.id === memberToRemove ? 'Leaving' : 'Removing'}
                    </>
                  ) : (
                    user?.id === memberToRemove ? 'Leave Team' : 'Remove'
                  )}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

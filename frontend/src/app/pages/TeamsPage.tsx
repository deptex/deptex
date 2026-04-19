import { useState, useEffect, useMemo, useRef } from 'react';
import { useParams, useOutletContext, useNavigate } from 'react-router-dom';
import { Plus, Users, Search, Grid3x3, List, ChevronRight, Folder, Loader2, Pencil } from 'lucide-react';
import { api, Team, TeamWithRole, OrganizationMember, Organization, RolePermissions } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { RoleBadge } from '../../components/RoleBadge';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from '../../components/ui/dialog';

interface OrganizationContextType {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

export default function TeamsPage() {
  const { id } = useParams<{ id: string }>();
  const { organization } = useOutletContext<OrganizationContextType>();
  const [teams, setTeams] = useState<TeamWithRole[]>([]);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingTeam, setEditingTeam] = useState<Team | null>(null);
  const [teamName, setTeamName] = useState('');
  const [teamDescription, setTeamDescription] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [userPermissions, setUserPermissions] = useState<RolePermissions | null>(null);
  const { toast } = useToast();
  const navigate = useNavigate();
  const searchInputRef = useRef<HTMLInputElement>(null);

  const handleTeamClick = (teamId: string) => {
    navigate(`/organizations/${id}/teams/${teamId}`);
  };

  // Prefetch team data on hover
  const prefetchTimeouts = useRef<Map<string, NodeJS.Timeout>>(new Map());

  const handleTeamHover = (teamId: string) => {
    if (!id) return;

    // Clear any existing timeout for this team
    const existingTimeout = prefetchTimeouts.current.get(teamId);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    // NOTE: We intentionally do NOT cache permissions from the teams list here.
    // The teams list permissions can be stale (fetched at page load time).
    // Permissions should only be cached by TeamLayout after fetching from the database.
    // This ensures users always see accurate, up-to-date permissions.

    // Small delay to avoid prefetching on accidental hovers
    const timeout = setTimeout(() => {
      api.prefetchTeam(id, teamId).catch(() => {
        // Silently fail - prefetch errors shouldn't interrupt the user
      });
      prefetchTimeouts.current.delete(teamId);
    }, 100); // 100ms delay before prefetching

    prefetchTimeouts.current.set(teamId, timeout);
  };

  const handleTeamHoverEnd = (teamId: string) => {
    // Clear timeout if user moves mouse away before prefetch starts
    const timeout = prefetchTimeouts.current.get(teamId);
    if (timeout) {
      clearTimeout(timeout);
      prefetchTimeouts.current.delete(teamId);
    }
  };

  // Filter teams based on search query
  const filteredTeams = useMemo(() => {
    if (!searchQuery.trim()) {
      return teams;
    }
    const query = searchQuery.toLowerCase();
    return teams.filter(team =>
      team.name.toLowerCase().includes(query)
    );
  }, [teams, searchQuery]);

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

  useEffect(() => {
    if (id) {
      loadData();
    }
  }, [id]);

  // Get cached permissions
  const getCachedPermissions = (): RolePermissions | null => {
    if (organization?.permissions) {
      const perms = { ...organization.permissions } as any;
      // Handle legacy key
      if (perms.create_teams_and_projects && !perms.manage_teams_and_projects) {
        perms.manage_teams_and_projects = true;
      }
      // Force owner full permissions
      if (organization.role === 'owner') {
        perms.view_all_teams_and_projects = true;
        perms.manage_teams_and_projects = true;
      }
      return perms;
    }
    if (id) {
      const cachedStr = localStorage.getItem(`org_permissions_${id}`);
      if (cachedStr) {
        try {
          const perms = JSON.parse(cachedStr);
          // Handle legacy key
          if (perms.create_teams_and_projects && !perms.manage_teams_and_projects) {
            perms.manage_teams_and_projects = true;
          }
          // Force owner full permissions
          if (organization?.role === 'owner') {

            perms.manage_teams_and_projects = true;
          }
          return perms;
        } catch { return null; }
      }
    }
    return null;
  };

  // Load user permissions from database
  useEffect(() => {
    const loadPermissions = async () => {
      if (!id || !organization?.role) return;

      // Try cached permissions first for instant display
      const cachedPerms = getCachedPermissions();
      if (cachedPerms) {
        setUserPermissions(cachedPerms);
      }

      try {
        const roles = await api.getOrganizationRoles(id);
        const userRole = roles.find(r => r.name === organization.role);

        if (userRole?.permissions) {
          const perms = { ...userRole.permissions } as any;

          // Handle legacy key
          if (perms.create_teams_and_projects && !perms.manage_teams_and_projects) {
            perms.manage_teams_and_projects = true;
          }

          // Force owner full permissions
          if (organization.role === 'owner') {

            perms.manage_teams_and_projects = true;
          }

          setUserPermissions(perms);
          // Update cache
          localStorage.setItem(`org_permissions_${id}`, JSON.stringify(perms));
        }
      } catch (error) {
        console.error('Failed to load permissions:', error);
        // Keep using cached permissions on error
      }
    };

    loadPermissions();
  }, [id, organization?.role]);

  const loadData = async () => {
    if (!id) return;

    try {
      setLoading(true);
      const [teamsData, membersData] = await Promise.all([
        api.getTeams(id),
        api.getOrganizationMembers(id),
      ]);
      setTeams(teamsData);
      setMembers(membersData);

      // Cache roles and permissions for instant access when navigating to team
      teamsData.forEach((team: TeamWithRole) => {
        if (team.role) {
          localStorage.setItem(`team_role_${team.id}`, team.role);
        }
        if (team.permissions) {
          localStorage.setItem(`team_permissions_${team.id}`, JSON.stringify(team.permissions));
        }
        // Also cache role display info for instant badge display
        if (team.role_display_name) {
          localStorage.setItem(`team_role_display_name_${team.id}`, team.role_display_name);
        }
        if (team.role_color) {
          localStorage.setItem(`team_role_color_${team.id}`, team.role_color);
        }
      });
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

  const handleCreateTeam = async () => {
    if (!id || !teamName.trim()) {
      toast({
        title: 'Error',
        description: 'Team name is required',
        variant: 'destructive',
      });
      return;
    }

    const trimmedName = teamName.trim();

    setCreating(true);
    try {
      await api.createTeam(id, trimmedName, teamDescription.trim());

      // Close modal and reset form
      setShowCreateModal(false);
      setTeamName('');
      setTeamDescription('');

      // Reload data to get the new team
      await loadData();

      toast({
        title: 'Success',
        description: 'Team created successfully',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to create team',
        variant: 'destructive',
      });
    } finally {
      setCreating(false);
    }
  };

  const handleUpdateTeam = async () => {
    if (!id || !editingTeam || !teamName.trim()) {
      return;
    }

    try {
      // Use the correct API method that accepts description
      // Note: api.updateTeam signature in api.ts accepts { name, avatar_url, description }
      const updatedTeam = await api.updateTeam(id, editingTeam.id, {
        name: teamName.trim(),
        description: teamDescription.trim()
      });
      setTeams(teams.map(t => t.id === updatedTeam.id ? { ...t, role: t.role, role_display_name: t.role_display_name, ...updatedTeam } : t));
      setEditingTeam(null);
      setTeamName('');
      setTeamDescription('');
      toast({
        title: 'Success',
        description: 'Team updated successfully',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to update team',
        variant: 'destructive',
      });
    }
  };

  const handleDeleteTeam = async (teamId: string) => {
    if (!id) return;

    if (!confirm('Are you sure you want to delete this team? This action cannot be undone.')) {
      return;
    }

    try {
      await api.deleteTeam(id, teamId);
      setTeams(teams.filter(t => t.id !== teamId));
      toast({
        title: 'Success',
        description: 'Team deleted successfully',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to delete team',
        variant: 'destructive',
      });
    }
  };

  const openEditModal = (team: Team) => {
    setEditingTeam(team);
    setTeamName(team.name);
    setTeamDescription(team.description || '');
    setShowCreateModal(true);
  };

  const closeModal = () => {
    setShowCreateModal(false);
    setEditingTeam(null);
    setTeamName('');
    setTeamDescription('');
  };

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Search, View Toggle, and Create Team */}
      <div className="flex items-center justify-between gap-4 mb-4">
        <div className="relative w-80">
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
        <div className="flex items-center gap-2">
          {/* View Toggle */}
          <div className="flex items-center border border-border rounded-md overflow-hidden">
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={() => setViewMode('grid')}
                  className={`px-3 py-1.5 text-sm transition-colors ${viewMode === 'grid'
                    ? 'bg-background-card text-foreground'
                    : 'text-foreground-secondary hover:text-foreground hover:bg-background-card/50'
                    }`}
                  aria-label="Grid view"
                >
                  <Grid3x3 className="h-4 w-4" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom">Grid view</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={() => setViewMode('list')}
                  className={`px-3 py-1.5 text-sm transition-colors border-l border-border ${viewMode === 'list'
                    ? 'bg-background-card text-foreground'
                    : 'text-foreground-secondary hover:text-foreground hover:bg-background-card/50'
                    }`}
                  aria-label="List view"
                >
                  <List className="h-4 w-4" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom">List view</TooltipContent>
            </Tooltip>
          </div>
          {userPermissions?.manage_teams_and_projects && (
            <Button
              onClick={() => {
                setEditingTeam(null);
                setTeamName('');
                setTeamDescription('');
                setShowCreateModal(true);
              }}
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
            >
              <Plus className="h-4 w-4 mr-2" />
              Create Team
            </Button>
          )}
        </div>
      </div>

      {loading ? (
        viewMode === 'grid' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <div
                key={i}
                className="bg-background-card border border-border rounded-lg p-5 animate-pulse relative flex flex-col h-[200px]"
              >
                <div className="flex-1 flex flex-col min-h-0">
                  <div className="h-5 bg-muted rounded w-3/4 mb-2" />
                  <div className="h-4 bg-muted rounded w-full mb-1" />
                  <div className="h-4 bg-muted rounded w-2/3 mb-3" />
                  <div className="h-5 w-20 bg-muted rounded" />
                </div>
                <div className="pt-4 border-t border-border flex items-center gap-6 mt-auto">
                  <div className="h-4 w-16 bg-muted rounded" />
                  <div className="h-4 w-16 bg-muted rounded" />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <table className="w-full">
              <thead className="bg-[#141618] border-b border-border">
                <tr>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Team
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Status
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Projects
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                    Members
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[1, 2, 3].map((i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="px-4 py-3">
                      <div className="h-4 bg-muted rounded w-32" />
                    </td>
                    <td className="px-4 py-3">
                      <div className="h-5 bg-muted rounded w-20" />
                    </td>
                    <td className="px-4 py-3">
                      <div className="h-4 bg-muted rounded w-8" />
                    </td>
                    <td className="px-4 py-3">
                      <div className="h-4 bg-muted rounded w-8" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      ) : filteredTeams.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 px-4">
          <div className="text-center">
            <Users className="mx-auto h-12 w-12 text-foreground-secondary mb-4" />
            <h3 className="text-lg font-semibold text-foreground mb-2">No teams found</h3>
            <p className="text-foreground-secondary mb-4">
              {searchQuery
                ? 'No teams match your search criteria.'
                : userPermissions?.manage_teams_and_projects
                  ? 'Get started by creating your first team.'
                  : 'No teams found.'}
            </p>
            {!searchQuery && userPermissions?.manage_teams_and_projects && (
              <Button
                onClick={() => {
                  setEditingTeam(null);
                  setTeamName('');
                  setTeamDescription('');
                  setShowCreateModal(true);
                }}
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              >
                <Plus className="h-4 w-4 mr-2" />
                Create Team
              </Button>
            )}
          </div>
        </div>
      ) : viewMode === 'grid' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredTeams.map((team) => (
            <div
              key={team.id}
              onClick={() => handleTeamClick(team.id)}
              onMouseEnter={() => handleTeamHover(team.id)}
              onMouseLeave={() => handleTeamHoverEnd(team.id)}
              className="bg-background-card border border-border rounded-lg p-5 hover:bg-background-card/80 transition-all cursor-pointer group relative flex flex-col min-h-[180px]"
            >
              <ChevronRight className="absolute top-5 right-5 h-5 w-5 text-foreground-secondary group-hover:text-foreground transition-colors flex-shrink-0" />
              <div className="flex-1 flex flex-col min-h-0 pr-6">
                <h3 className="text-lg font-bold text-foreground mb-1 truncate">{team.name}</h3>
                <p className="text-sm text-foreground-secondary line-clamp-2 mb-4 flex-1">
                  {team.description || "No description provided."}
                </p>
                {team.role && !team.role_display_name?.startsWith('Org ') && (
                  <div className="mb-2">
                    <RoleBadge
                      role={team.role}
                      roleDisplayName={team.role_display_name}
                      roleColor={team.role_color}
                    />
                  </div>
                )}
              </div>
              <div className="pt-4 border-t border-border flex items-center gap-6 mt-auto">
                <div className="flex items-center gap-2 text-foreground-secondary" title={`${team.member_count || 0} Members`}>
                  <Users className="h-4 w-4" />
                  <span className="text-sm font-medium">{team.member_count || 0}</span>
                </div>
                <div className="flex items-center gap-2 text-foreground-secondary" title={`${team.project_count || 0} Projects`}>
                  <Folder className="h-4 w-4" />
                  <span className="text-sm font-medium">{team.project_count || 0}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Team
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Status
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Projects
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Members
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredTeams.map((team) => (
                <tr
                  key={team.id}
                  onClick={() => handleTeamClick(team.id)}
                  onMouseEnter={() => handleTeamHover(team.id)}
                  onMouseLeave={() => handleTeamHoverEnd(team.id)}
                  className="hover:bg-table-hover transition-colors cursor-pointer group"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="text-sm font-semibold text-foreground">{team.name}</div>
                      {team.role && !team.role_display_name?.startsWith('Org ') && (
                        <RoleBadge
                          role={team.role}
                          roleDisplayName={team.role_display_name}
                          roleColor={team.role_color}
                        />
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded text-xs font-medium border bg-success/20 text-success border-success/40">
                      COMPLIANT
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-sm text-foreground-secondary flex items-center gap-2">
                      <Folder className="h-4 w-4" />
                      {team.project_count || 0}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-sm text-foreground-secondary flex items-center gap-2">
                      <Users className="h-4 w-4" />
                      {team.member_count || 0}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create/Edit Team Dialog */}
      <Dialog open={showCreateModal} onOpenChange={(open) => { if (!open) closeModal(); }}>
        <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden max-h-[90vh] flex flex-col">
          <div className="px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
            <DialogTitle>{editingTeam ? 'Edit Team' : 'Create Team'}</DialogTitle>
            <DialogDescription className="mt-1">
              Teams are part of the same organization and allow you to group projects and members together.
              They add another level of access control, enabling members to only see and interact with resources
              within their assigned teams.
            </DialogDescription>
          </div>

          <div className="px-6 py-4 grid gap-4 bg-background overflow-y-auto max-h-[60vh] min-h-0">
            <div>
              <label htmlFor="team-name" className="block text-sm font-medium text-foreground mb-2">
                Team Name
              </label>
              <input
                id="team-name"
                type="text"
                value={teamName}
                onChange={(e) => setTeamName(e.target.value)}
                placeholder="Engineering Team"
                className="w-full px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent mb-4"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    editingTeam ? handleUpdateTeam() : handleCreateTeam();
                  }
                }}
              />
            </div>

            <div>
              <label htmlFor="team-description" className="block text-sm font-medium text-foreground mb-2">
                Description
              </label>
              <textarea
                id="team-description"
                value={teamDescription}
                onChange={(e) => setTeamDescription(e.target.value)}
                placeholder="Describe the team's purpose..."
                rows={4}
                className="w-full px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
              />
            </div>
          </div>

          <DialogFooter className="px-6 py-4 bg-background">
            <Button variant="outline" onClick={closeModal}>
              Cancel
            </Button>
            <Button
              onClick={editingTeam ? handleUpdateTeam : handleCreateTeam}
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              disabled={creating}
            >
              {creating ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin mr-2 flex-shrink-0" />
                  Create
                </>
              ) : editingTeam ? (
                <>
                  <Pencil className="h-4 w-4 mr-2 flex-shrink-0" />
                  Update
                </>
              ) : (
                <>
                  <Plus className="h-4 w-4 mr-2 flex-shrink-0" />
                  Create
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  );
}


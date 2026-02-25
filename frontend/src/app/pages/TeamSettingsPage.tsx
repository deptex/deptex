import { useState, useEffect, useRef } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import { Save, Trash2, Upload, Settings, Plus, X, Edit2, MoreVertical, UserCircle, Users, Bell, Tag } from 'lucide-react';
import { api, TeamWithRole, TeamPermissions, TeamMember, TeamRole, Organization } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { useAuth } from '../../contexts/AuthContext';
import { Button } from '../../components/ui/button';
import { supabase } from '../../lib/supabase';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../components/ui/dropdown-menu';
import TeamMembersPage from './TeamMembersPage';
import { TeamPermissionEditor } from '../../components/TeamPermissionEditor';
import { RoleBadge } from '../../components/RoleBadge';
import { Palette, GripVertical } from 'lucide-react';


interface TeamContextType {
  team: TeamWithRole | null;
  reloadTeam: () => Promise<void>;
  updateTeamData: (updates: Partial<TeamWithRole>) => void;
  organizationId: string;
  userPermissions: TeamPermissions | null;
  organization: Organization | null;
}

export default function TeamSettingsPage() {
  const { team, organizationId, reloadTeam, updateTeamData, userPermissions, organization } = useOutletContext<TeamContextType>();
  const { user } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [activeSection, setActiveSection] = useState('general');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [avatarUrl, setAvatarUrl] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);



  // Delete state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [isDeletingTeam, setIsDeletingTeam] = useState(false);

  // Roles state
  const [allRoles, setAllRoles] = useState<TeamRole[]>([]);
  const [loadingRoles, setLoadingRoles] = useState(false);
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [loadingMembers, setLoadingMembers] = useState(false);
  const [editingRoleNameId, setEditingRoleNameId] = useState<string | null>(null);
  const [editingRoleName, setEditingRoleName] = useState('');
  const [isSavingRole, setIsSavingRole] = useState(false);
  const [showAddRoleSidepanel, setShowAddRoleSidepanel] = useState(false);
  const [newRoleNameInput, setNewRoleNameInput] = useState('');
  const [newRolePermissions, setNewRolePermissions] = useState<TeamPermissions>({
    view_overview: false,
    resolve_alerts: false,
    manage_projects: false,
    manage_members: false,
    view_settings: false,
    view_members: false,
    add_members: false,
    kick_members: false,
    view_roles: false,
    edit_roles: false,
    manage_notification_settings: false,
  });
  const [isCreatingRole, setIsCreatingRole] = useState(false);
  const [showRoleSettingsModal, setShowRoleSettingsModal] = useState(false);
  const [selectedRoleForSettings, setSelectedRoleForSettings] = useState<TeamRole | null>(null);
  const [editingRolePermissions, setEditingRolePermissions] = useState<TeamPermissions | null>(null);
  const [deletingRoleId, setDeletingRoleId] = useState<string | null>(null);
  const [isRoleEditable, setIsRoleEditable] = useState(false); // Whether the selected role can be edited

  // Drag and drop state
  const [draggedRoleId, setDraggedRoleId] = useState<string | null>(null);
  const [dragPreviewRoles, setDragPreviewRoles] = useState<TeamRole[] | null>(null);

  // Color state
  const [newRoleColor, setNewRoleColor] = useState('');
  const [editingRoleColor, setEditingRoleColor] = useState('');

  // Track the team id to only reset state when switching teams, not on every reload
  const [loadedTeamId, setLoadedTeamId] = useState<string | null>(null);

  const canManageSettings = userPermissions?.view_settings || false;
  // Only users with org-level manage_teams_and_projects permission can delete teams
  const canDeleteTeam = organization?.permissions?.manage_teams_and_projects || false;

  useEffect(() => {
    if (userPermissions && !userPermissions.view_settings) {
      navigate(`/organizations/${organizationId}/teams/${team?.id}/projects`, { replace: true });
    }
  }, [userPermissions, navigate, organizationId, team?.id]);

  // Only sync team data to local state when switching to a different team (not on reload)
  useEffect(() => {
    if (team && team.id !== loadedTeamId) {
      setName(team.name);
      setDescription(team.description || '');
      setAvatarUrl(team.avatar_url || null);
      setLoadedTeamId(team.id);
    }
  }, [team, loadedTeamId]);



  useEffect(() => {
    if (team && activeSection === 'roles') {
      loadRoles();
      loadMembers();
    }
  }, [team, activeSection]);

  const loadMembers = async () => {
    if (!organizationId || !team?.id) return;
    try {
      setLoadingMembers(true);
      const fetchedMembers = await api.getTeamMembers(organizationId, team.id);
      setMembers(fetchedMembers);
    } catch (error: any) {
      console.error('Failed to load members:', error);
    } finally {
      setLoadingMembers(false);
    }
  };





  const loadRoles = async () => {
    if (!organizationId || !team?.id) return;
    try {
      setLoadingRoles(true);
      const roles = await api.getTeamRoles(organizationId, team.id);
      const sortedRoles = roles.sort((a, b) => a.display_order - b.display_order);
      setAllRoles(sortedRoles);
    } catch (error: any) {
      console.error('Failed to load roles:', error);
    } finally {
      setLoadingRoles(false);
    }
  };

  const handleSave = async () => {
    if (!organizationId || !team?.id || !name.trim()) {
      toast({
        title: 'Error',
        description: 'Team name is required',
        variant: 'destructive',
      });
      return;
    }

    setSaving(true);
    try {
      const updatedTeam = await api.updateTeam(organizationId, team.id, {
        name: name.trim(),
        description: description.trim(),
        avatar_url: avatarUrl || undefined,
      });
      // Update the team data directly in the parent to avoid refetch race conditions
      updateTeamData({
        name: updatedTeam.name,
        description: updatedTeam.description,
        avatar_url: updatedTeam.avatar_url,
      });
      toast({
        title: 'Success',
        description: 'Team settings updated',
      });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to update team',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleAvatarUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !team?.id || !organizationId) return;

    if (!file.type.startsWith('image/')) {
      toast({
        title: 'Error',
        description: 'Please select an image file',
        variant: 'destructive',
      });
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      toast({
        title: 'Error',
        description: 'Image must be less than 5MB',
        variant: 'destructive',
      });
      return;
    }

    setUploading(true);
    try {
      const fileExt = file.name.split('.').pop();
      const fileName = `${team.id}-${Date.now()}.${fileExt}`;
      // Path must start with organization ID for RLS policies to work
      const filePath = `${organizationId}/team-avatars/${fileName}`;

      const { error: uploadError } = await supabase.storage
        .from('organization-avatars')
        .upload(filePath, file, { upsert: true });

      if (uploadError) throw uploadError;

      const { data: urlData } = supabase.storage
        .from('organization-avatars')
        .getPublicUrl(filePath);

      const publicUrl = urlData.publicUrl;

      // Auto-save the avatar immediately (like personal settings)
      const updatedTeam = await api.updateTeam(organizationId, team.id, {
        avatar_url: publicUrl,
      });

      // Preload the new image before updating state (prevents flash)
      await new Promise<void>((resolve) => {
        const img = new Image();
        img.onload = () => resolve();
        img.onerror = () => resolve();
        img.src = publicUrl;
      });

      // Update local state and parent team data to update header
      setAvatarUrl(publicUrl);
      updateTeamData({ avatar_url: updatedTeam.avatar_url });

      toast({
        title: 'Avatar updated',
        description: 'Team avatar has been updated successfully.',
      });
    } catch (error: any) {
      console.error('Upload error:', error);
      toast({
        title: 'Error',
        description: error.message || 'Failed to upload avatar',
        variant: 'destructive',
      });
    } finally {
      setUploading(false);
    }

    // Reset input
    e.target.value = '';
  };



  const handleDeleteTeam = async () => {
    if (!organizationId || !team?.id || deleteConfirmText !== team.name || isDeletingTeam) return;

    try {
      setIsDeletingTeam(true);
      await api.deleteTeam(organizationId, team.id);
      toast({
        title: 'Team deleted',
        description: 'The team has been deleted successfully.',
      });
      navigate(`/organizations/${organizationId}/teams`);
    } catch (error: any) {
      toast({
        title: 'Delete failed',
        description: error.message || 'Failed to delete team. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setIsDeletingTeam(false);
    }
  };

  const getRoleDisplayName = (roleName: string): string => {
    const role = allRoles.find(r => r.name === roleName);
    if (role?.display_name) {
      return role.display_name;
    }
    if (roleName === 'owner') return 'Owner';
    if (roleName === 'member') return 'Member';
    return roleName.charAt(0).toUpperCase() + roleName.slice(1);
  };

  const handleCreateRole = async (permissions: TeamPermissions) => {
    if (!organizationId || !team?.id || !newRoleNameInput.trim()) return;

    const roleName = newRoleNameInput.trim().toLowerCase();

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
      await api.createTeamRole(organizationId, team.id, {
        name: roleName,
        display_name: newRoleNameInput.trim(),
        permissions,
        color: newRoleColor || null,
      });
      await loadRoles();
      setNewRoleNameInput('');
      setNewRoleColor('');
      setNewRolePermissions({
        view_overview: false,
        resolve_alerts: false,
        manage_projects: false,
        manage_members: false,
        view_settings: false,
        view_roles: false,
        edit_roles: false,
        manage_notification_settings: false,
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

  const handleDeleteRole = async (role: TeamRole) => {
    // Only top ranked role (display_order 0) cannot be deleted - it's always required
    // Member role CAN be deleted - it's just a default role, not special
    if (!organizationId || !team?.id || role.display_order === 0 || !role.id) return;

    try {
      setDeletingRoleId(role.id);
      await api.deleteTeamRole(organizationId, team.id, role.id);
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

    // Prevent moving any role above the top ranked role (position 0)
    // The top ranked role should always be at the top
    const topRoleIndex = sourceRoles.findIndex(r => r.display_order === 0);
    if (topRoleIndex === 0 && targetIndex === 0) {
      // Cannot drop above top role
      return;
    }

    // Create new array with the dragged item moved to target position
    const newRoles = [...sourceRoles];
    const [draggedRole] = newRoles.splice(draggedIndex, 1);
    newRoles.splice(targetIndex, 0, draggedRole);

    setDragPreviewRoles(newRoles);
  };

  // Commit the reorder on drop
  const handleDragReorder = async () => {
    if (!organizationId || !team?.id || !dragPreviewRoles) return;

    const userRank = team?.user_rank;

    // Calculate which roles changed position
    // Compare original ARRAY INDEX to new array index (not display_order to index)
    const updates: Array<{ id: string; newOrder: number; originalIndex: number }> = [];
    dragPreviewRoles.forEach((role, newIndex) => {
      const originalIndex = allRoles.findIndex(r => r.id === role.id);
      if (originalIndex !== -1 && originalIndex !== newIndex) {
        updates.push({ id: role.id, newOrder: newIndex, originalIndex });
      }
    });

    if (updates.length === 0) {
      setDragPreviewRoles(null);
      return;
    }

    // Check if any role that was ORIGINALLY below user's position would be moved ABOVE user's NEW position
    // Only perform this check if we have a valid userRank
    if (!hasOrgManagePermission && userRank !== null && userRank !== undefined) {
      // Find user's role index in ORIGINAL array
      const originalUserIndex = allRoles.findIndex(r => r.name === team?.role);
      // Find user's role index in the NEW (preview) array
      const userNewPosition = dragPreviewRoles.findIndex(r => r.name === team?.role);


      const invalidUpdate = updates.find(update => {
        // Was this role originally BELOW the user? (higher index = lower rank)
        const wasBelow = update.originalIndex > originalUserIndex;
        // Is this role now ABOVE the user in the new ordering? (lower index = higher rank)
        const isNowAbove = update.newOrder < userNewPosition;
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
        api.updateTeamRole(organizationId, team.id, roleId, { display_order: newOrder })
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

  const handleEditRoleName = (role: TeamRole) => {
    if (!role.id) return;
    setEditingRoleNameId(role.id);
    setEditingRoleName(role.display_name || role.name);
  };

  const handleEditRolePermissions = (role: TeamRole, editable: boolean = true) => {
    if (!role.id) return;
    setSelectedRoleForSettings(role);
    setIsRoleEditable(editable);
    setEditingRoleName(role.display_name || role.name);
    setEditingRolePermissions(role.permissions || {
      view_overview: false,
      resolve_alerts: false,
      manage_projects: false,
      manage_members: false,
      view_settings: false,
      view_roles: false,
      edit_roles: false,
      manage_notification_settings: false,
    });
    setEditingRoleColor(role.color || '');
    setShowRoleSettingsModal(true);
  };

  const handleSaveRoleName = async (role: TeamRole) => {
    if (!organizationId || !team?.id || !role.id || !editingRoleName.trim()) return;

    try {
      setIsSavingRole(true);
      const updatedRole = await api.updateTeamRole(organizationId, team.id, role.id, {
        display_name: editingRoleName.trim(),
      });

      setAllRoles(prevRoles =>
        prevRoles.map(r =>
          r.id === role.id
            ? { ...r, display_name: updatedRole.display_name }
            : r
        )
      );

      setEditingRoleNameId(null);
      setEditingRoleName('');

      toast({
        title: 'Role name updated',
        description: 'The role name has been updated successfully.',
      });

      loadRoles().catch(error => {
        console.error('Background role refresh failed:', error);
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

  const handleSaveRolePermissions = async (role: TeamRole, permissions: TeamPermissions) => {
    if (!organizationId || !team?.id || !role.id) return;

    try {
      setIsSavingRole(true);

      // For admin role, only save name and color, not permissions
      const updateData: any = {
        color: editingRoleColor || null,
        display_name: editingRoleName.trim() || undefined,
      };

      // Only include permissions for non-top-ranked roles
      if (role.display_order !== 0) {
        updateData.permissions = permissions;
      }

      const updatedRole = await api.updateTeamRole(organizationId, team.id, role.id, updateData);

      setAllRoles(prevRoles =>
        prevRoles.map(r =>
          r.id === role.id
            ? {
              ...r,
              ...(role.display_order !== 0 && { permissions: updatedRole.permissions }),
              color: updatedRole.color,
              display_name: updatedRole.display_name
            }
            : r
        )
      );

      setShowRoleSettingsModal(false);
      setSelectedRoleForSettings(null);
      setEditingRolePermissions(null);

      toast({
        title: 'Role updated',
        description: 'The role has been updated successfully.',
      });

      // If the user updated their own role, reload team data to update header
      if (role.name === team?.role) {
        await reloadTeam();
      }

      loadRoles().catch(error => {
        console.error('Background role refresh failed:', error);
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

  // Check if user has org-level manage_teams_and_projects permission
  const hasOrgManagePermission = organization?.permissions?.manage_teams_and_projects || false;

  const teamSettingsSections = [
    {
      id: 'general',
      label: 'General',
      icon: <Settings className="h-4 w-4 tab-icon-shake" />,
    },
    // Show Notifications section if user can manage notification settings OR has org-level permission
    ...((userPermissions?.manage_notification_settings || hasOrgManagePermission) ? [{
      id: 'notifications',
      label: 'Notifications',
      icon: <Bell className="h-4 w-4 tab-icon-shake" />,
    }] : []),
    // Show Roles section if user can view/edit roles OR has org-level manage permission
    ...((userPermissions?.view_roles || userPermissions?.edit_roles || hasOrgManagePermission) ? [{
      id: 'roles',
      label: 'Roles',
      icon: <Users className="h-4 w-4 tab-icon-shake" />,
    }] : []),
  ];

  if (!team) {
    return (
      <div className="bg-background">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-background">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex gap-8 items-start">
          {/* Sidebar */}
          <aside className="w-64 flex-shrink-0">
            <div className="sticky top-24 pt-8 bg-background z-10">
              <nav className="space-y-1">
                {teamSettingsSections.map((section) => (
                  <button
                    key={section.id}
                    onClick={() => setActiveSection(section.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors group ${activeSection === section.id
                      ? 'text-foreground'
                      : 'text-foreground-secondary hover:text-foreground'
                      }`}
                  >
                    {section.icon}
                    {section.label}
                  </button>
                ))}
              </nav>
            </div>
          </aside>

          {/* Content */}
          <div className="flex-1 no-scrollbar">
            {activeSection === 'general' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-2xl font-bold text-foreground">General Settings</h2>
                  <p className="text-foreground-secondary mt-1">
                    Manage your team's profile and settings.
                  </p>
                </div>

                {/* Team Name & Description Card */}
                <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                  <div className="p-6">
                    <h3 className="text-base font-semibold text-foreground mb-1">Team Name</h3>
                    <p className="text-sm text-foreground-secondary mb-4">
                      This is your team's visible name. It will be displayed throughout the dashboard.
                    </p>
                    <div className="max-w-md mb-6">
                      <input
                        type="text"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="Enter team name"
                        className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                      />
                    </div>

                    <h3 className="text-base font-semibold text-foreground mb-1">Team Description</h3>
                    <p className="text-sm text-foreground-secondary mb-4">
                      Describe your team's purpose and responsibilities.
                    </p>
                    <textarea
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="Describe the team's purpose..."
                      rows={3}
                      className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all resize-none"
                    />
                  </div>
                  <div className="px-6 py-3 bg-black/20 border-t border-border flex items-center justify-between">
                    <p className="text-xs text-foreground-secondary">
                      Changes will be visible to all team members.
                    </p>
                    <Button
                      onClick={handleSave}
                      disabled={saving || (name === team?.name && description === (team?.description || ''))}
                      size="sm"
                      className="h-8"
                    >
                      {saving ? (
                        <>
                          <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full mr-2" />
                          Saving
                        </>
                      ) : (
                        'Save'
                      )}
                    </Button>
                  </div>
                </div>

                {/* Danger Zone - Only visible to those with permission */}
                {canDeleteTeam && (
                  <div className="border border-destructive/30 rounded-lg overflow-hidden bg-destructive/5">
                    <div className="px-6 py-3 border-b border-destructive/30 bg-destructive/10">
                      <h3 className="text-sm font-semibold text-destructive uppercase tracking-wide">Danger Zone</h3>
                    </div>
                    <div className="p-6">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <h4 className="text-base font-semibold text-foreground mb-1">Delete Team</h4>
                          <p className="text-sm text-foreground-secondary">
                            Permanently delete this team and all of its data. This action cannot be undone.
                          </p>
                        </div>
                        {!showDeleteConfirm && team && (
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

                      {showDeleteConfirm && team && (
                        <div className="mt-4 p-4 bg-background/50 rounded-lg border border-destructive/30 space-y-4">
                          <p className="text-sm text-foreground">
                            To confirm deletion, type <strong className="text-destructive font-mono bg-destructive/10 px-1.5 py-0.5 rounded">{team.name}</strong> below:
                          </p>
                          <input
                            type="text"
                            value={deleteConfirmText}
                            onChange={(e) => setDeleteConfirmText(e.target.value)}
                            placeholder={team.name}
                            className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-destructive/50 focus:border-destructive transition-all"
                          />
                          <div className="flex gap-2">
                            <Button
                              onClick={handleDeleteTeam}
                              variant="destructive"
                              size="sm"
                              disabled={deleteConfirmText !== team.name || isDeletingTeam}
                              className="h-8"
                            >
                              {isDeletingTeam ? (
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

            {activeSection === 'notifications' && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-2xl font-bold text-foreground">Notifications</h2>
                  <p className="text-foreground-secondary mt-1">
                    Manage notification settings for your team.
                  </p>
                </div>

                {/* Placeholder Card */}
                <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                  <div className="p-12 flex flex-col items-center justify-center text-center">
                    <div className="h-16 w-16 rounded-full bg-background-subtle flex items-center justify-center mb-4">
                      <Bell className="h-8 w-8 text-foreground-secondary" />
                    </div>
                    <h3 className="text-lg font-semibold text-foreground mb-2">Team level notifications coming soon</h3>
                    <p className="text-sm text-foreground-secondary max-w-md">
                      Configure where team notifications are sent and manage notification preferences for your team members.
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
                    <p className="text-foreground-secondary mt-2">
                      Manage roles and permissions for your team.
                    </p>
                  </div>
                  {canManageSettings && (
                    <Button
                      onClick={() => setShowAddRoleSidepanel(true)}
                      className="bg-primary text-primary-foreground hover:bg-primary/90 h-8 text-sm"
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
                        const isUserRole = team?.role === role.name;
                        // Use current array (preview or actual) for permission calculations
                        const currentRoles = dragPreviewRoles || allRoles;
                        // Find user's role index by NAME (not display_order which can have duplicates/gaps)
                        const userRoleIndex = currentRoles.findIndex(r => r.name === team?.role);
                        const roleIndex = currentRoles.findIndex(r => r.id === role.id);
                        // Role is below user if its array index is GREATER than user's array index (strictly below, not same)
                        const isRoleBelowUserRank = userRoleIndex !== -1 && roleIndex !== -1 && roleIndex > userRoleIndex;
                        const isTopRankedRole = role.display_order === 0; // Top ranked role (display_order 0)
                        const isUserTopRanked = userRoleIndex === 0; // User is top ranked
                        // Can edit role settings (name, color): org manage permission OR role is below user rank
                        // Top role CAN be edited (name/color) but not its permissions
                        // Special case: If user IS the top ranked role, they can edit their OWN role's name/color
                        const canEditRole = canManageSettings && (hasOrgManagePermission || isRoleBelowUserRank || (isUserRole && isUserTopRanked));
                        // Can delete if: has permission, NOT top ranked role (top role is never deletable)
                        // Member role CAN be deleted (it's just another role, not special like top role)
                        const canDeleteRole = canManageSettings && (hasOrgManagePermission || isRoleBelowUserRank) && !isTopRankedRole;
                        // Can drag/reorder if: has permission, NOT top ranked role (top role always stays at top)
                        // If has org-level permission, can drag any role (including own role)
                        // If only team-level permission, can only drag roles below user's rank (not own role)
                        const canDrag = canManageSettings && !isTopRankedRole && currentRoles.length > 1 &&
                          (hasOrgManagePermission || (isRoleBelowUserRank && !isUserRole));
                        const isDragging = draggedRoleId === role.id;
                        const memberCount = members.filter(m => m.role === role.name).length;

                        return (
                          <div
                            key={role.id || role.name}
                            className={`px-4 py-3 flex items-center justify-between transition-all duration-150 group ${
                              isDragging ? 'opacity-50 bg-primary/10 scale-[0.98]' : 'hover:bg-table-hover'
                            }`}
                            draggable={canDrag}
                            onDragStart={(e) => {
                              if (!canDrag || !role.id) {
                                e.preventDefault();
                                return;
                              }
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
                              if (draggedRoleId && draggedRoleId !== role.id && role.id) {
                                handleDragPreview(draggedRoleId, role.id);
                              }
                            }}
                            onDrop={(e) => {
                              e.preventDefault();
                              handleDragReorder();
                              setDraggedRoleId(null);
                            }}
                          >
                            {/* Left: Role Name + Member count subtext + Your Role badge */}
                            <div className="flex items-center gap-2 min-w-0 flex-1">
                              <div className="flex flex-col min-w-0">
                                <div className="flex items-center gap-2">
                                  {editingRoleNameId === role.id ? (
                                    <input
                                      type="text"
                                      value={editingRoleName}
                                      onChange={(e) => setEditingRoleName(e.target.value)}
                                      onClick={(e) => e.stopPropagation()}
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
                                  </span>
                                </div>
                              </div>
                            </div>

                            {/* Right side - Badge transforms to actions on hover */}
                            <div className="flex items-center justify-end flex-shrink-0 w-36 relative">
                              {/* Badge - visible by default, hidden on hover when there are actions */}
                              <div className={`flex justify-end transition-opacity ${canManageSettings ? 'group-hover:opacity-0' : ''}`}>
                                <RoleBadge
                                  role={role.name}
                                  roleDisplayName={role.display_name}
                                  roleColor={role.color}
                                />
                              </div>

                              {/* Actions - hidden by default, visible on hover */}
                              {canManageSettings && (
                                <div className="absolute inset-0 flex items-center justify-end gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    onClick={() => handleEditRolePermissions(role, canEditRole)}
                                    className="h-7 w-7 text-foreground-secondary hover:text-foreground"
                                    title={canEditRole ? "Settings" : "View Settings (read-only)"}
                                  >
                                    <Settings className="h-4 w-4" />
                                  </Button>

                                  {canDeleteRole && (
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
                      Create roles to define permissions and access levels for your team members.
                    </p>
                  </div>
                )}
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
                    setNewRolePermissions({
                      view_overview: false,
                      resolve_alerts: false,
                      manage_projects: false,
                      manage_members: false,
                      view_settings: false,
                      view_members: false,
                      add_members: false,
                      kick_members: false,
                      view_roles: false,
                      edit_roles: false,
                      manage_notification_settings: false,
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
                      Define a custom role with specific permissions for your team.
                    </p>
                  </div>

                  {/* Content */}
                  <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
                    <div className="space-y-6">
                      {/* Role Name Input */}
                      <div className="space-y-2">
                        <label className="block text-sm font-medium text-foreground">
                          Role Name
                        </label>
                        <input
                          type="text"
                          placeholder="e.g. Developer, Manager"
                          value={newRoleNameInput}
                          onChange={(e) => setNewRoleNameInput(e.target.value)}
                          maxLength={24}
                          className="w-full px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
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
                            <button
                              key={color}
                              type="button"
                              onClick={() => setNewRoleColor(color)}
                              disabled={isCreatingRole}
                              title={name}
                              className={`h-8 w-8 rounded-lg border-2 transition-all flex items-center justify-center ${newRoleColor === color
                                ? 'border-white scale-110 shadow-lg'
                                : 'border-transparent hover:scale-105'
                                }`}
                              style={{ backgroundColor: color }}
                            >
                              {newRoleColor === color && (
                                <div className="h-4 w-4 text-white drop-shadow-md" />
                              )}
                            </button>
                          ))}

                          {/* Custom Color Picker */}
                          <div className="relative" title="Custom color">
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
                            </div>
                          </div>

                          {/* Clear color button */}
                          {newRoleColor && (
                            <button
                              type="button"
                              onClick={() => setNewRoleColor('')}
                              disabled={isCreatingRole}
                              className="h-8 w-8 rounded-lg border border-border text-foreground-secondary hover:text-foreground hover:border-foreground-secondary/50 transition-all flex items-center justify-center"
                              title="Clear color"
                            >
                              <X className="h-4 w-4" />
                            </button>
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
                          <h3 className="text-lg font-semibold text-foreground mb-1">Permissions</h3>
                          <p className="text-sm text-foreground-secondary">
                            Configure what this role can do in your team.
                          </p>
                        </div>

                        <TeamPermissionEditor
                          permissions={newRolePermissions}
                          onSave={async () => { }}
                          onChange={setNewRolePermissions}
                          hideActions={true}
                          currentUserPermissions={userPermissions}
                          isOwner={hasOrgManagePermission}
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
                        setNewRolePermissions({
                          view_overview: false,
                          resolve_alerts: false,
                          manage_projects: false,
                          manage_members: false,
                          view_settings: false,
                          view_members: false,
                          add_members: false,
                          kick_members: false,
                          view_roles: false,
                          edit_roles: false,
                          manage_notification_settings: false,
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
                          Creating
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
            {showRoleSettingsModal && selectedRoleForSettings && editingRolePermissions && (
              <div className="fixed inset-0 z-50">
                {/* Backdrop */}
                <div
                  className="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"
                  onClick={() => {
                    setShowRoleSettingsModal(false);
                    setSelectedRoleForSettings(null);
                    setEditingRolePermissions(null);
                  }}
                />

                {/* Side Panel */}
                <div
                  className="fixed right-0 top-0 h-full w-full max-w-lg bg-background border-l border-border shadow-2xl transform transition-transform duration-300 translate-x-0 flex flex-col"
                  onClick={(e) => e.stopPropagation()}
                >
                  {/* Header */}
                  <div className="px-6 py-5 border-b border-border flex-shrink-0 bg-[#141618]">
                    <div className="flex items-center gap-2">
                      <h2 className="text-xl font-semibold text-foreground">
                        {selectedRoleForSettings.display_name || selectedRoleForSettings.name.charAt(0).toUpperCase() + selectedRoleForSettings.name.slice(1)} Settings
                      </h2>
                      {!isRoleEditable && (
                        <span className="px-2 py-0.5 text-xs font-medium bg-amber-500/15 text-amber-400 rounded-full">
                          Read-only
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Content */}
                  <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-6">
                    <div className="space-y-6">
                      {/* Read-only notice */}
                      {!isRoleEditable && (
                        <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
                          <p className="text-sm text-amber-400">
                            You cannot edit this role because it is at or above your rank.
                          </p>
                        </div>
                      )}

                      <div className="mb-4">
                        <h3 className="text-lg font-semibold text-foreground mb-1">
                          Role Settings
                        </h3>
                        <p className="text-sm text-foreground-secondary">
                          {selectedRoleForSettings.display_order === 0
                            ? 'Customize the appearance of this role.'
                            : 'Configure the name, color, and permissions for this role.'}
                        </p>
                      </div>

                      {/* Role Name */}
                      <div className={`space-y-3 ${!isRoleEditable ? 'opacity-60 pointer-events-none' : ''}`}>
                        <label className="flex items-center gap-2 text-base font-semibold text-foreground">
                          <Tag className="h-5 w-5 text-foreground-secondary" />
                          Role Name
                        </label>
                        <input
                          type="text"
                          value={editingRoleName}
                          onChange={(e) => setEditingRoleName(e.target.value)}
                          placeholder="e.g. Developer, Manager"
                          maxLength={24}
                          disabled={!isRoleEditable || isSavingRole}
                          className={`w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all ${!isRoleEditable ? 'opacity-60 cursor-not-allowed' : ''}`}
                        />
                      </div>

                      {/* Role Color */}
                      <div className={`space-y-3 ${!isRoleEditable ? 'opacity-60 pointer-events-none' : ''}`}>
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
                            <button
                              key={color}
                              type="button"
                              onClick={() => setEditingRoleColor(color)}
                              disabled={isSavingRole || !isRoleEditable}
                              title={name}
                              className={`h-8 w-8 rounded-lg border-2 transition-all flex items-center justify-center ${editingRoleColor === color
                                ? 'border-white scale-110 shadow-lg'
                                : 'border-transparent hover:scale-105'
                                }`}
                              style={{ backgroundColor: color }}
                            >
                              {editingRoleColor === color && (
                                <div className="h-4 w-4 text-white drop-shadow-md" />
                              )}
                            </button>
                          ))}

                          {/* Custom Color Picker */}
                          <div className="relative" title="Custom color">
                            <input
                              type="color"
                              value={editingRoleColor || '#6b7280'}
                              onChange={(e) => setEditingRoleColor(e.target.value)}
                              className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
                              disabled={isSavingRole || !isRoleEditable}
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
                            </div>
                          </div>

                          {/* Clear color button */}
                          {editingRoleColor && isRoleEditable && (
                            <button
                              type="button"
                              onClick={() => setEditingRoleColor('')}
                              disabled={isSavingRole}
                              className="h-8 w-8 rounded-lg border border-border text-foreground-secondary hover:text-foreground hover:border-foreground-secondary/50 transition-all flex items-center justify-center"
                              title="Clear color"
                            >
                              <X className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Only show permissions editor for non-top-ranked roles */}
                      {selectedRoleForSettings.display_order !== 0 && (
                        <div className={`pt-4 border-t border-border ${!isRoleEditable ? 'opacity-60 pointer-events-none' : ''}`}>
                          <TeamPermissionEditor
                            permissions={editingRolePermissions}
                            onSave={(perms) => handleSaveRolePermissions(selectedRoleForSettings, perms)}
                            onChange={(perms) => isRoleEditable && setEditingRolePermissions(perms)}
                            hideActions={true}
                            currentUserPermissions={userPermissions}
                            isOwner={hasOrgManagePermission && isRoleEditable}
                          />
                        </div>
                      )}

                      <div className="flex items-center justify-end gap-3 pt-6">
                        <Button
                          onClick={() => {
                            setShowRoleSettingsModal(false);
                            setSelectedRoleForSettings(null);
                            setEditingRolePermissions(null);
                          }}
                          variant="ghost"
                          disabled={isSavingRole}
                          className="px-4"
                        >
                          {isRoleEditable ? 'Cancel' : 'Close'}
                        </Button>
                        {isRoleEditable && (
                          <Button
                            onClick={() => handleSaveRolePermissions(selectedRoleForSettings, editingRolePermissions)}
                            disabled={isSavingRole}
                            className="px-6 bg-primary text-primary-foreground hover:bg-primary/90"
                          >
                            {isSavingRole ? (
                              <>
                                <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                                Saving
                              </>
                            ) : (
                              <>
                                <Save className="h-4 w-4 mr-2" />
                                {selectedRoleForSettings.display_order === 0 ? 'Save Changes' : 'Save Permissions'}
                              </>
                            )}
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

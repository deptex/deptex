import { useState, useEffect, useRef } from 'react';
import { useOutletContext, useNavigate, useParams, Link } from 'react-router-dom';
import { Save, Trash2, Upload, Settings, Plus, X, Edit2, MoreVertical, UserCircle, Users, Bell, Tag, FileCheck, Check, Mail, Webhook, ChevronDown, Loader2, BookOpen } from 'lucide-react';
import { api, TeamWithRole, TeamPermissions, TeamMember, TeamRole, Organization, type CiCdConnection } from '../../lib/api';
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
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '../../components/ui/dialog';
import { Label } from '../../components/ui/label';
import { Input } from '../../components/ui/input';
import TeamMembersPage from './TeamMembersPage';
import NotificationRulesSection from './NotificationRulesSection';
import { TeamPermissionEditor } from '../../components/TeamPermissionEditor';
import { RoleBadge } from '../../components/RoleBadge';
import { Palette, GripVertical } from 'lucide-react';
import { cn } from '../../lib/utils';


interface TeamContextType {
  team: TeamWithRole | null;
  reloadTeam: () => Promise<void>;
  updateTeamData: (updates: Partial<TeamWithRole>) => void;
  organizationId: string;
  userPermissions: TeamPermissions | null;
  organization: Organization | null;
}

const VALID_TEAM_SETTINGS_SECTIONS = new Set(['general', 'notifications', 'roles']);

export default function TeamSettingsPage() {
  const { orgId, teamId, section: sectionParam } = useParams<{ orgId: string; teamId: string; section?: string }>();
  const { team, organizationId, reloadTeam, updateTeamData, userPermissions, organization } = useOutletContext<TeamContextType>();
  const { user } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();

  const activeSection = (sectionParam && VALID_TEAM_SETTINGS_SECTIONS.has(sectionParam) ? sectionParam : 'general');
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
  const [addRolePanelVisible, setAddRolePanelVisible] = useState(false);
  const addRoleCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
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
  const [roleSettingsPanelVisible, setRoleSettingsPanelVisible] = useState(false);
  const [roleSettingsClosing, setRoleSettingsClosing] = useState(false);
  const roleSettingsCloseTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
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

  // Notification state
  const [notificationActiveTab, setNotificationActiveTab] = useState<'notifications' | 'destinations'>('notifications');
  const [teamConnections, setTeamConnections] = useState<{ inherited: CiCdConnection[]; team: CiCdConnection[] }>({ inherited: [], team: [] });
  const [teamConnectionsLoading, setTeamConnectionsLoading] = useState(false);
  const notificationCreateRef = useRef<(() => void) | null>(null);
  const [showTeamEmailDialog, setShowTeamEmailDialog] = useState(false);
  const [teamEmailToAdd, setTeamEmailToAdd] = useState('');
  const [teamEmailSaving, setTeamEmailSaving] = useState(false);
  const [showTeamCustomDialog, setShowTeamCustomDialog] = useState(false);
  const [teamCustomName, setTeamCustomName] = useState('');
  const [teamCustomWebhookUrl, setTeamCustomWebhookUrl] = useState('');
  const [teamCustomSaving, setTeamCustomSaving] = useState(false);

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

  // Redirect to settings/general when section param is invalid
  useEffect(() => {
    if (orgId && teamId && sectionParam && !VALID_TEAM_SETTINGS_SECTIONS.has(sectionParam)) {
      navigate(`/organizations/${orgId}/teams/${teamId}/settings/general`, { replace: true });
    }
  }, [orgId, teamId, sectionParam, navigate]);

  // Add role sidebar: animate in on open, animate out before unmount
  useEffect(() => {
    if (showAddRoleSidepanel) {
      setAddRolePanelVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setAddRolePanelVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setAddRolePanelVisible(false);
    }
  }, [showAddRoleSidepanel]);

  // Role Settings sidebar: animate in on open, animate out before unmount
  useEffect(() => {
    if (showRoleSettingsModal) {
      setRoleSettingsPanelVisible(false);
      const raf = requestAnimationFrame(() => {
        requestAnimationFrame(() => setRoleSettingsPanelVisible(true));
      });
      return () => cancelAnimationFrame(raf);
    } else {
      setRoleSettingsPanelVisible(false);
      setRoleSettingsClosing(false);
    }
  }, [showRoleSettingsModal]);

  // Cleanup timeouts on unmount
  useEffect(() => () => {
    if (addRoleCloseTimeoutRef.current) clearTimeout(addRoleCloseTimeoutRef.current);
    if (roleSettingsCloseTimeoutRef.current) clearTimeout(roleSettingsCloseTimeoutRef.current);
  }, []);

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

  useEffect(() => {
    if (team && activeSection === 'notifications') {
      loadTeamConnections();
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





  const loadTeamConnections = async () => {
    if (!organizationId || !team?.id) return;
    setTeamConnectionsLoading(true);
    try {
      const conns = await api.getTeamConnections(organizationId, team.id);
      setTeamConnections(conns);
    } catch {
      setTeamConnections({ inherited: [], team: [] });
    } finally {
      setTeamConnectionsLoading(false);
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
      closeAddRolePanel();
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

  const closeAddRolePanel = () => {
    setAddRolePanelVisible(false);
    if (addRoleCloseTimeoutRef.current) clearTimeout(addRoleCloseTimeoutRef.current);
    addRoleCloseTimeoutRef.current = setTimeout(() => {
      addRoleCloseTimeoutRef.current = null;
      setShowAddRoleSidepanel(false);
      setNewRoleNameInput('');
      setNewRoleColor('#3b82f6');
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
    }, 150);
  };

  const closeRoleSettingsPanel = () => {
    setRoleSettingsPanelVisible(false);
    setRoleSettingsClosing(true);
    if (roleSettingsCloseTimeoutRef.current) clearTimeout(roleSettingsCloseTimeoutRef.current);
    roleSettingsCloseTimeoutRef.current = setTimeout(() => {
      roleSettingsCloseTimeoutRef.current = null;
      setShowRoleSettingsModal(false);
      setSelectedRoleForSettings(null);
      setEditingRolePermissions(null);
      setEditingRoleName('');
      setRoleSettingsClosing(false);
    }, 150);
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

      closeRoleSettingsPanel();

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
                    onClick={() => orgId && teamId && navigate(`/organizations/${orgId}/teams/${teamId}/settings/${section.id}`)}
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
                  <h2 className="text-2xl font-bold text-foreground">General</h2>
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
                      className="h-8 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                    >
                      {saving && (
                        <span className="animate-spin h-3.5 w-3.5 border-2 border-current border-t-transparent rounded-full mr-2" />
                      )}
                      Save
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
              <div>
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-2xl font-bold text-foreground">Notifications</h2>
                  {notificationActiveTab === 'notifications' && organizationId && team?.id && (
                    <Button
                      onClick={() => notificationCreateRef.current?.()}
                      className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 h-8 text-sm"
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Create Rule
                    </Button>
                  )}
                </div>

                <div className="flex items-center justify-between border-b border-border pb-px">
                  <div className="flex items-center gap-6">
                    <button
                      type="button"
                      onClick={() => setNotificationActiveTab('notifications')}
                      className={`pb-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                        notificationActiveTab === 'notifications' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
                      }`}
                    >
                      Notifications
                    </button>
                    <button
                      type="button"
                      onClick={() => setNotificationActiveTab('destinations')}
                      className={`pb-3 text-sm font-medium transition-colors border-b-2 -mb-px ${
                        notificationActiveTab === 'destinations' ? 'text-foreground border-foreground' : 'text-foreground-secondary hover:text-foreground border-transparent'
                      }`}
                    >
                      Destinations
                    </button>
                  </div>
                </div>

                {notificationActiveTab === 'notifications' && organizationId && team?.id && (
                  <div className="pt-6">
                    <NotificationRulesSection
                      organizationId={organizationId}
                      teamId={team.id}
                      hideTitle
                      createHandlerRef={notificationCreateRef}
                      connections={[...(teamConnections.inherited || []), ...(teamConnections.team || [])]}
                    />
                  </div>
                )}

                {notificationActiveTab === 'destinations' && (
                  <div className="pt-6 space-y-8">
                    {/* Inherited from organization */}
                    <div>
                      <h3 className="text-lg font-semibold text-foreground mb-3">Inherited from organization</h3>
                      <p className="text-sm text-foreground-secondary mb-4">
                        Integrations connected at the organization level are available for this team.
                      </p>
                      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                        <table className="w-full table-fixed">
                          <colgroup>
                            <col className="w-[200px]" />
                            <col />
                            <col className="w-[120px]" />
                          </colgroup>
                          <thead className="bg-background-card-header border-b border-border">
                            <tr>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                              <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {teamConnectionsLoading ? (
                              [1, 2, 3].map((i) => (
                                <tr key={i}>
                                  <td className="px-4 py-3"><div className="h-4 w-20 bg-muted animate-pulse rounded" /></td>
                                  <td className="px-4 py-3"><div className="h-4 w-28 bg-muted animate-pulse rounded" /></td>
                                  <td className="px-4 py-3" />
                                </tr>
                              ))
                            ) : teamConnections.inherited.length === 0 ? (
                              <tr>
                                <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                  No inherited integrations. Connect integrations in Organization Settings.
                                </td>
                              </tr>
                            ) : (
                              teamConnections.inherited.map((conn: CiCdConnection) => (
                                <tr key={conn.id} className="group hover:bg-table-hover transition-colors">
                                  <td className="px-4 py-3">
                                    <div className="flex items-center gap-2.5">
                                      {(conn.provider === 'slack' || conn.provider === 'discord') && (
                                        <img src={`/images/integrations/${conn.provider}.png`} alt="" className="h-5 w-5 rounded-sm" />
                                      )}
                                      {conn.provider === 'email' && <Mail className="h-5 w-5 text-foreground-secondary" />}
                                      {(conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing') && (
                                        conn.metadata?.icon_url ? <img src={conn.metadata.icon_url} alt="" className="h-5 w-5 rounded-sm" /> : <Webhook className="h-5 w-5 text-foreground-secondary" />
                                      )}
                                      {!['slack', 'discord', 'email', 'custom_notification', 'custom_ticketing'].includes(conn.provider) && (
                                        conn.provider === 'jira' ? <img src="/images/integrations/jira.png" alt="" className="h-5 w-5 rounded-sm" /> :
                                        conn.provider === 'linear' ? <img src="/images/integrations/linear.png" alt="" className="h-5 w-5 rounded-sm" /> :
                                        <Webhook className="h-5 w-5 text-foreground-secondary" />
                                      )}
                                      <span className="text-sm font-medium text-foreground">
                                        {conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing' ? 'Custom' :
                                          conn.provider === 'email' ? 'Email' :
                                          conn.provider === 'jira' ? (conn.metadata?.type === 'data_center' ? 'Jira DC' : 'Jira') :
                                          conn.provider === 'slack' ? 'Slack' : conn.provider === 'discord' ? 'Discord' : conn.provider === 'linear' ? 'Linear' : conn.provider}
                                      </span>
                                    </div>
                                  </td>
                                  <td className="px-4 py-3">
                                    <span className="text-sm text-foreground truncate block">{conn.display_name || '-'}</span>
                                  </td>
                                  <td className="px-4 py-3 text-right">
                                    <span className="text-xs text-foreground-secondary px-2 py-1 rounded border border-border bg-transparent">Inherited</span>
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {/* Team-specific */}
                    <div>
                      <h3 className="text-lg font-semibold text-foreground mb-3">Team-specific</h3>
                      <p className="text-sm text-foreground-secondary mb-4">
                        Add integrations that are specific to this team.
                      </p>
                      {canManageSettings && (
                        <div className="flex items-center gap-2 mb-4 flex-wrap">
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs"
                            onClick={() => { setTeamEmailToAdd(''); setShowTeamEmailDialog(true); }}
                          >
                            <Mail className="h-3.5 w-3.5 mr-1.5" />
                            Add Email
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs"
                            onClick={() => { setTeamCustomName(''); setTeamCustomWebhookUrl(''); setShowTeamCustomDialog(true); }}
                          >
                            <Webhook className="h-3.5 w-3.5 mr-1.5" />
                            Add Custom
                          </Button>
                        </div>
                      )}
                      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                        <table className="w-full table-fixed">
                          <colgroup>
                            <col className="w-[200px]" />
                            <col />
                            <col className="w-[140px]" />
                          </colgroup>
                          <thead className="bg-background-card-header border-b border-border">
                            <tr>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Provider</th>
                              <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Connection</th>
                              <th className="text-right px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider"></th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {teamConnectionsLoading ? (
                              [1, 2].map((i) => (
                                <tr key={i}>
                                  <td className="px-4 py-3"><div className="h-4 w-20 bg-muted animate-pulse rounded" /></td>
                                  <td className="px-4 py-3"><div className="h-4 w-28 bg-muted animate-pulse rounded" /></td>
                                  <td className="px-4 py-3" />
                                </tr>
                              ))
                            ) : teamConnections.team.length === 0 ? (
                              <tr>
                                <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                                  No team-specific integrations. Add one above.
                                </td>
                              </tr>
                            ) : (
                              teamConnections.team.map((conn: CiCdConnection) => (
                                <tr key={conn.id} className="group hover:bg-table-hover transition-colors">
                                  <td className="px-4 py-3">
                                    <div className="flex items-center gap-2.5">
                                      {(conn.provider === 'slack' || conn.provider === 'discord') && (
                                        <img src={`/images/integrations/${conn.provider}.png`} alt="" className="h-5 w-5 rounded-sm" />
                                      )}
                                      {conn.provider === 'email' && <Mail className="h-5 w-5 text-foreground-secondary" />}
                                      {(conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing') && (
                                        conn.metadata?.icon_url ? <img src={conn.metadata.icon_url} alt="" className="h-5 w-5 rounded-sm" /> : <Webhook className="h-5 w-5 text-foreground-secondary" />
                                      )}
                                      {!['slack', 'discord', 'email', 'custom_notification', 'custom_ticketing'].includes(conn.provider) && (
                                        conn.provider === 'jira' ? <img src="/images/integrations/jira.png" alt="" className="h-5 w-5 rounded-sm" /> :
                                        conn.provider === 'linear' ? <img src="/images/integrations/linear.png" alt="" className="h-5 w-5 rounded-sm" /> :
                                        <Webhook className="h-5 w-5 text-foreground-secondary" />
                                      )}
                                      <span className="text-sm font-medium text-foreground">
                                        {conn.provider === 'custom_notification' || conn.provider === 'custom_ticketing' ? 'Custom' :
                                          conn.provider === 'email' ? 'Email' :
                                          conn.provider === 'jira' ? (conn.metadata?.type === 'data_center' ? 'Jira DC' : 'Jira') :
                                          conn.provider === 'slack' ? 'Slack' : conn.provider === 'discord' ? 'Discord' : conn.provider === 'linear' ? 'Linear' : conn.provider}
                                      </span>
                                    </div>
                                  </td>
                                  <td className="px-4 py-3">
                                    <span className="text-sm text-foreground truncate block">
                                      {conn.provider === 'email' ? conn.metadata?.email || conn.display_name : conn.display_name || '-'}
                                    </span>
                                  </td>
                                  <td className="px-4 py-3 text-right">
                                    {canManageSettings && (
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        className="text-xs hover:bg-destructive/10 hover:border-destructive/30 opacity-0 group-hover:opacity-100 transition-opacity"
                                        onClick={async () => {
                                          if (!confirm('Remove this integration?')) return;
                                          try {
                                            await api.deleteTeamConnection(organizationId, team!.id, conn.id);
                                            toast({ title: 'Removed', description: 'Integration removed.' });
                                            loadTeamConnections();
                                          } catch (err: any) {
                                            toast({ title: 'Failed to remove', description: err.message, variant: 'destructive' });
                                          }
                                        }}
                                      >
                                        Remove
                                      </Button>
                                    )}
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                )}
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
                  className={cn(
                    'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
                    addRolePanelVisible ? 'opacity-100' : 'opacity-0'
                  )}
                  onClick={closeAddRolePanel}
                />

                {/* Right-side popup panel – Vercel style: rounded corners, floating feel */}
                <div
                  className={cn(
                    'fixed right-4 top-4 bottom-4 w-full max-w-[680px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
                    addRolePanelVisible ? 'translate-x-0' : 'translate-x-full'
                  )}
                  onClick={(e) => e.stopPropagation()}
                >
                  {/* Header – no X, no border */}
                  <div className="px-6 pt-5 pb-3 flex-shrink-0">
                    <h2 className="text-xl font-semibold text-foreground">Create New Role</h2>
                    <p className="text-sm text-foreground-secondary mt-0.5">
                      Define a custom role with specific permissions for your team.
                    </p>
                  </div>

                  {/* Content */}
                  <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">
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
                          className="w-full px-3 py-2.5 bg-background-card border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
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
                                <Check className="h-4 w-4 text-white drop-shadow-md" />
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
                  <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
                    <Button
                      variant="outline"
                      onClick={closeAddRolePanel}
                      disabled={isCreatingRole}
                    >
                      Cancel
                    </Button>
                    <Button
                      onClick={async () => {
                        await handleCreateRole(newRolePermissions);
                      }}
                      disabled={isCreatingRole || !newRoleNameInput.trim()}
                      className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
                    >
                      {isCreatingRole ? (
                        <>
                          <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                          Create Role
                        </>
                      ) : (
                        <>
                          <FileCheck className="h-4 w-4 mr-2" />
                          Create Role
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {/* Role Settings Side Panel */}
            {(showRoleSettingsModal || roleSettingsClosing) && selectedRoleForSettings && editingRolePermissions && (
              <div className="fixed inset-0 z-50">
                {/* Backdrop */}
                <div
                  className={cn(
                    'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
                    roleSettingsPanelVisible ? 'opacity-100' : 'opacity-0'
                  )}
                  onClick={closeRoleSettingsPanel}
                />

                {/* Side Panel – matches Create New Role style */}
                <div
                  className={cn(
                    'fixed right-4 top-4 bottom-4 w-full max-w-[680px] bg-background border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
                    roleSettingsPanelVisible ? 'translate-x-0' : 'translate-x-full'
                  )}
                  onClick={(e) => e.stopPropagation()}
                >
                  {/* Header */}
                  <div className="px-6 pt-5 pb-3 flex-shrink-0">
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
                  <div className="flex-1 overflow-y-auto no-scrollbar px-6 py-4">
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
                                <Check className="h-4 w-4 text-white drop-shadow-md" />
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
                    </div>
                  </div>

                  {/* Footer */}
                  <div className="px-6 py-4 flex items-center justify-end gap-3 flex-shrink-0 border-t border-border bg-background-card-header">
                    {isRoleEditable ? (
                      <>
                        <Button
                          variant="outline"
                          onClick={closeRoleSettingsPanel}
                          disabled={isSavingRole}
                        >
                          Cancel
                        </Button>
                        <Button
                          onClick={() => handleSaveRolePermissions(selectedRoleForSettings, editingRolePermissions)}
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
                              <FileCheck className="h-4 w-4 mr-2" />
                              {selectedRoleForSettings.display_order === 0 ? 'Save Changes' : 'Save Permissions'}
                            </>
                          )}
                        </Button>
                      </>
                    ) : (
                      <Button
                        variant="outline"
                        onClick={closeRoleSettingsPanel}
                      >
                        Close
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Team Email Notification Dialog */}
      <Dialog open={showTeamEmailDialog} onOpenChange={setShowTeamEmailDialog}>
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
              <Label htmlFor="team-email-to-add">Email address</Label>
              <Input
                id="team-email-to-add"
                type="email"
                value={teamEmailToAdd}
                onChange={(e) => setTeamEmailToAdd(e.target.value)}
                placeholder=""
              />
            </div>
          </div>
          <DialogFooter className="px-6 py-4 bg-background">
            <Button variant="outline" onClick={() => setShowTeamEmailDialog(false)}>Cancel</Button>
            <Button
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              disabled={!teamEmailToAdd.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(teamEmailToAdd.trim()) || teamEmailSaving}
              onClick={async () => {
                if (!organizationId || !team?.id) return;
                setTeamEmailSaving(true);
                try {
                  await api.createTeamEmailNotification(organizationId, team.id, teamEmailToAdd.trim());
                  toast({ title: 'Added', description: 'Email notification added successfully.' });
                  setShowTeamEmailDialog(false);
                  setTeamEmailToAdd('');
                  loadTeamConnections();
                } catch (err: any) {
                  toast({ title: 'Error', description: err.message || 'Failed to add email.', variant: 'destructive' });
                } finally {
                  setTeamEmailSaving(false);
                }
              }}
            >
              {teamEmailSaving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Team Custom Integration Dialog */}
      <Dialog open={showTeamCustomDialog} onOpenChange={setShowTeamCustomDialog}>
        <DialogContent hideClose className="sm:max-w-[520px] bg-background p-0 gap-0 overflow-hidden">
          <div className="px-6 pt-6 pb-4 border-b border-border">
            <div className="flex items-start justify-between gap-4">
              <div>
                <DialogTitle>Add custom integration</DialogTitle>
                <DialogDescription className="mt-1">Set up a custom webhook endpoint for notifications.</DialogDescription>
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
              <Label htmlFor="team-custom-name">Name</Label>
              <Input
                id="team-custom-name"
                value={teamCustomName}
                onChange={(e) => setTeamCustomName(e.target.value)}
                placeholder=""
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="team-custom-webhook">Webhook URL</Label>
              <Input
                id="team-custom-webhook"
                type="url"
                value={teamCustomWebhookUrl}
                onChange={(e) => setTeamCustomWebhookUrl(e.target.value)}
                placeholder=""
                className={teamCustomWebhookUrl.trim() && !teamCustomWebhookUrl.trim().toLowerCase().startsWith('https://') ? 'border-destructive focus-visible:ring-destructive/50' : undefined}
              />
            </div>
          </div>
          <DialogFooter className="px-6 py-4 bg-background">
            <Button variant="outline" onClick={() => setShowTeamCustomDialog(false)}>Cancel</Button>
            <Button
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
              disabled={!teamCustomName.trim() || !teamCustomWebhookUrl.trim() || teamCustomSaving || !/^https:\/\/[^\s]+$/i.test(teamCustomWebhookUrl.trim())}
              onClick={async () => {
                if (!organizationId || !team?.id) return;
                setTeamCustomSaving(true);
                try {
                  await api.createTeamCustomIntegration(organizationId, team.id, {
                    name: teamCustomName.trim(),
                    type: 'notification',
                    webhook_url: teamCustomWebhookUrl.trim(),
                  });
                  toast({ title: 'Created', description: 'Custom integration created.' });
                  setShowTeamCustomDialog(false);
                  setTeamCustomName('');
                  setTeamCustomWebhookUrl('');
                  loadTeamConnections();
                } catch (err: any) {
                  toast({ title: 'Error', description: err.message || 'Failed to save.', variant: 'destructive' });
                } finally {
                  setTeamCustomSaving(false);
                }
              }}
            >
              {teamCustomSaving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
              Create connection
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

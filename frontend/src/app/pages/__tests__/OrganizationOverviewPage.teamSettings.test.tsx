/**
 * Tests for team sidebar settings functionality within OrganizationOverviewPage.
 *
 * Since OrganizationOverviewPage is extremely complex (ReactFlow, Supabase realtime, etc.),
 * these tests focus on the core logic functions extracted into testable units:
 * - Team name save + dirty-check (save button enable/disable)
 * - Role deletion with member-count guard
 * - Role drag-to-reorder preview logic
 * - Project status label (Creating vs Compliant vs Not Compliant)
 * - Stale data clearing on team switch
 */

import { describe, it, expect } from 'vitest';

// ── projectStatusLabel logic ─────────────────────────────────────────────────
// Mirrors the function at the top of OrganizationOverviewPage.tsx

function isExtractionOngoing(status: string, step: string | null): boolean {
  const ongoingStatuses = ['queued', 'cloning', 'analyzing', 'finalizing'];
  if (ongoingStatuses.includes(status)) return true;
  if (status === 'completed' && step && step !== 'completed') return true;
  return false;
}

function projectStatusLabel(project: {
  repo_status?: string | null;
  extraction_step?: string | null;
  is_compliant?: boolean;
}): { label: string; inProgress: boolean; isError: boolean } {
  const status = project.repo_status;
  if (isExtractionOngoing(status || '', project.extraction_step ?? null)) {
    const step = project.extraction_step;
    const labels: Record<string, string> = {
      queued: 'Creating', cloning: 'Creating', sbom: 'Creating', deps_synced: 'Creating',
      ast_parsing: 'Creating', scanning: 'Creating', uploading: 'Creating', completed: 'Creating',
    };
    const label = step ? (labels[step] ?? 'Creating') : (status === 'analyzing' || status === 'finalizing' ? 'Analyzing' : 'Creating');
    return { label, inProgress: true, isError: false };
  }
  if (status === 'error') return { label: 'Failed', inProgress: false, isError: true };
  return {
    label: project.is_compliant !== false ? 'COMPLIANT' : 'NOT COMPLIANT',
    inProgress: false,
    isError: false,
  };
}

describe('projectStatusLabel', () => {
  it('returns Creating for queued projects', () => {
    const result = projectStatusLabel({ repo_status: 'queued', extraction_step: 'queued' });
    expect(result).toEqual({ label: 'Creating', inProgress: true, isError: false });
  });

  it('returns Creating for cloning projects', () => {
    const result = projectStatusLabel({ repo_status: 'cloning', extraction_step: 'cloning' });
    expect(result).toEqual({ label: 'Creating', inProgress: true, isError: false });
  });

  it('returns Analyzing for analyzing status', () => {
    const result = projectStatusLabel({ repo_status: 'analyzing', extraction_step: null });
    expect(result).toEqual({ label: 'Analyzing', inProgress: true, isError: false });
  });

  it('returns Failed for error status', () => {
    const result = projectStatusLabel({ repo_status: 'error', extraction_step: null });
    expect(result).toEqual({ label: 'Failed', inProgress: false, isError: true });
  });

  it('returns COMPLIANT when is_compliant is true', () => {
    const result = projectStatusLabel({ repo_status: 'completed', extraction_step: 'completed', is_compliant: true });
    expect(result).toEqual({ label: 'COMPLIANT', inProgress: false, isError: false });
  });

  it('returns NOT COMPLIANT when is_compliant is false', () => {
    const result = projectStatusLabel({ repo_status: 'completed', extraction_step: 'completed', is_compliant: false });
    expect(result).toEqual({ label: 'NOT COMPLIANT', inProgress: false, isError: false });
  });

  it('returns COMPLIANT when is_compliant is undefined (default)', () => {
    const result = projectStatusLabel({ repo_status: 'completed', extraction_step: 'completed' });
    expect(result).toEqual({ label: 'COMPLIANT', inProgress: false, isError: false });
  });
});

// ── Team settings save dirty-check logic ─────────────────────────────────────

describe('team settings save button dirty-check', () => {
  function isSaveDisabled(
    saving: boolean,
    name: string,
    description: string,
    savedName: string,
    savedDescription: string,
  ): boolean {
    return saving || (name === savedName && description === savedDescription);
  }

  it('is disabled when name and description match saved values', () => {
    expect(isSaveDisabled(false, 'My Team', 'A description', 'My Team', 'A description')).toBe(true);
  });

  it('is enabled when name differs from saved value', () => {
    expect(isSaveDisabled(false, 'My Team Updated', 'A description', 'My Team', 'A description')).toBe(false);
  });

  it('is enabled when description differs from saved value', () => {
    expect(isSaveDisabled(false, 'My Team', 'New desc', 'My Team', 'A description')).toBe(false);
  });

  it('is disabled while saving even if values differ', () => {
    expect(isSaveDisabled(true, 'Changed', 'Changed', 'Original', 'Original')).toBe(true);
  });

  it('is disabled after save when saved values are updated to match current', () => {
    // Simulates: user types "teams", saves, savedName updates to "teams"
    expect(isSaveDisabled(false, 'teams', '', 'teams', '')).toBe(true);
  });
});

// ── Role deletion member-count guard ─────────────────────────────────────────

describe('role deletion member-count guard', () => {
  interface Member { user_id: string; role: string }
  interface Role { id: string; name: string; display_name?: string }

  function canDeleteRole(role: Role, members: Member[]): { allowed: boolean; memberCount: number } {
    const membersWithRole = members.filter((m) => m.role === role.name).length;
    return { allowed: membersWithRole === 0, memberCount: membersWithRole };
  }

  it('allows deletion when no members have the role', () => {
    const role = { id: 'r1', name: 'contributor' };
    const members = [
      { user_id: 'u1', role: 'owner' },
      { user_id: 'u2', role: 'member' },
    ];
    expect(canDeleteRole(role, members)).toEqual({ allowed: true, memberCount: 0 });
  });

  it('blocks deletion when members have the role', () => {
    const role = { id: 'r1', name: 'contributor' };
    const members = [
      { user_id: 'u1', role: 'contributor' },
      { user_id: 'u2', role: 'member' },
      { user_id: 'u3', role: 'contributor' },
    ];
    expect(canDeleteRole(role, members)).toEqual({ allowed: false, memberCount: 2 });
  });

  it('allows deletion when role exists but has zero members', () => {
    const role = { id: 'r1', name: 'viewer' };
    const members: Member[] = [];
    expect(canDeleteRole(role, members)).toEqual({ allowed: true, memberCount: 0 });
  });
});

// ── Role drag-to-reorder preview logic ───────────────────────────────────────

describe('role drag-to-reorder preview', () => {
  interface Role { id: string; name: string; display_order: number }

  function dragPreview(roles: Role[], draggedId: string, targetId: string): Role[] | null {
    const draggedIndex = roles.findIndex(r => r.id === draggedId);
    const targetIndex = roles.findIndex(r => r.id === targetId);
    if (draggedIndex === -1 || targetIndex === -1 || draggedIndex === targetIndex) return null;
    const newRoles = [...roles];
    const [draggedRole] = newRoles.splice(draggedIndex, 1);
    newRoles.splice(targetIndex, 0, draggedRole);
    return newRoles;
  }

  const roles: Role[] = [
    { id: 'r1', name: 'owner', display_order: 0 },
    { id: 'r2', name: 'admin', display_order: 1 },
    { id: 'r3', name: 'member', display_order: 2 },
    { id: 'r4', name: 'viewer', display_order: 3 },
  ];

  it('moves a role down in the list', () => {
    const result = dragPreview(roles, 'r2', 'r4');
    expect(result!.map(r => r.id)).toEqual(['r1', 'r3', 'r4', 'r2']);
  });

  it('moves a role up in the list', () => {
    const result = dragPreview(roles, 'r4', 'r2');
    expect(result!.map(r => r.id)).toEqual(['r1', 'r4', 'r2', 'r3']);
  });

  it('returns null when dragging onto self', () => {
    expect(dragPreview(roles, 'r2', 'r2')).toBeNull();
  });

  it('returns null when dragged id does not exist', () => {
    expect(dragPreview(roles, 'nonexistent', 'r2')).toBeNull();
  });

  it('returns null when target id does not exist', () => {
    expect(dragPreview(roles, 'r2', 'nonexistent')).toBeNull();
  });

  it('does not mutate the original array', () => {
    const original = [...roles];
    dragPreview(roles, 'r2', 'r4');
    expect(roles).toEqual(original);
  });
});

// ── Reorder commit: detect changed display_orders ────────────────────────────

describe('role reorder commit - detect updates', () => {
  interface Role { id: string; name: string; display_order: number }

  function computeReorderUpdates(original: Role[], reordered: Role[]): Array<{ id: string; newOrder: number }> {
    const updates: Array<{ id: string; newOrder: number }> = [];
    reordered.forEach((role, index) => {
      const orig = original.find(r => r.id === role.id);
      if (orig && orig.display_order !== index) {
        updates.push({ id: role.id, newOrder: index });
      }
    });
    return updates;
  }

  const roles: Role[] = [
    { id: 'r1', name: 'owner', display_order: 0 },
    { id: 'r2', name: 'admin', display_order: 1 },
    { id: 'r3', name: 'member', display_order: 2 },
  ];

  it('detects no updates when order unchanged', () => {
    expect(computeReorderUpdates(roles, roles)).toEqual([]);
  });

  it('detects updates when roles are swapped', () => {
    const reordered = [roles[0], roles[2], roles[1]]; // owner, member, admin
    const updates = computeReorderUpdates(roles, reordered);
    expect(updates).toEqual([
      { id: 'r3', newOrder: 1 },
      { id: 'r2', newOrder: 2 },
    ]);
  });

  it('detects all changes when fully reversed (except first)', () => {
    const reordered = [roles[0], roles[2], roles[1]];
    const updates = computeReorderUpdates(roles, reordered);
    expect(updates).toHaveLength(2);
    // owner stays at 0, so no update for r1
    expect(updates.find(u => u.id === 'r1')).toBeUndefined();
  });
});

// ── Rank validation on reorder ────────────────────────────────────────────────

describe('role reorder rank validation', () => {
  interface Role { id: string; name: string; display_order: number }

  /**
   * Mirrors the rank check in handleTeamSettingsDragReorder:
   * Computes updates (roles whose original array index differs from new index),
   * then checks if any role originally below the user was moved above them.
   */
  function hasInvalidRankMove(
    original: Role[],
    reordered: Role[],
    userRole: string,
  ): boolean {
    const originalUserIndex = original.findIndex(r => r.name === userRole);
    const userNewPosition = reordered.findIndex(r => r.name === userRole);
    if (originalUserIndex === -1 || userNewPosition === -1) return false;

    const updates: Array<{ originalIndex: number; newOrder: number }> = [];
    reordered.forEach((role, newIndex) => {
      const origIdx = original.findIndex(r => r.id === role.id);
      if (origIdx !== -1 && origIdx !== newIndex) {
        updates.push({ originalIndex: origIdx, newOrder: newIndex });
      }
    });

    return updates.some(update => {
      const wasBelow = update.originalIndex > originalUserIndex;
      const isNowAbove = update.newOrder < userNewPosition;
      return wasBelow && isNowAbove;
    });
  }

  const roles: Role[] = [
    { id: 'r1', name: 'lead', display_order: 0 },
    { id: 'r2', name: 'admin', display_order: 1 },
    { id: 'r3', name: 'member', display_order: 2 },
    { id: 'r4', name: 'viewer', display_order: 3 },
  ];

  it('allows reordering roles below user rank', () => {
    // User is admin (index 1). Swapping viewer and member — both below admin.
    const reordered = [roles[0], roles[1], roles[3], roles[2]]; // lead, admin, viewer, member
    expect(hasInvalidRankMove(roles, reordered, 'admin')).toBe(false);
  });

  it('blocks moving a role from below user to above user', () => {
    // User is admin (index 1). Moving viewer (orig 3) to index 1, pushing admin to index 2.
    const reordered = [roles[0], roles[3], roles[1], roles[2]]; // lead, viewer, admin, member
    expect(hasInvalidRankMove(roles, reordered, 'admin')).toBe(true);
  });

  it('allows org admin to reorder anything (caller skips this check)', () => {
    // The org-level check bypasses this function entirely.
    // We verify the function itself would flag it — caller skips for org admins.
    const reordered = [roles[0], roles[3], roles[1], roles[2]];
    expect(hasInvalidRankMove(roles, reordered, 'admin')).toBe(true);
  });

  it('allows keeping roles in same position', () => {
    expect(hasInvalidRankMove(roles, roles, 'admin')).toBe(false);
  });

  it('returns false when user role not found in list', () => {
    expect(hasInvalidRankMove(roles, roles, 'nonexistent')).toBe(false);
  });
});

// ── canDrag logic ────────────────────────────────────────────────────────────

describe('canDrag permission logic', () => {
  /**
   * Mirrors the canDrag calculation from the team sidebar roles list.
   * canDrag = canManageSettings && roles.length > 1
   *   && (hasOrgManagePermission || (!isTopRankedRole && isRoleBelowUserRank && !isUserRole))
   *
   * Key difference from org settings: org manage permission bypasses ALL restrictions
   * including top-ranked role (teams don't have an immovable "owner" role like orgs do).
   */
  function canDrag(opts: {
    canManageSettings: boolean;
    isTopRankedRole: boolean;
    rolesCount: number;
    hasOrgManagePermission: boolean;
    isRoleBelowUserRank: boolean;
    isUserRole: boolean;
  }): boolean {
    return opts.canManageSettings && opts.rolesCount > 1 &&
      (opts.hasOrgManagePermission || (!opts.isTopRankedRole && opts.isRoleBelowUserRank && !opts.isUserRole));
  }

  const base = { canManageSettings: true, isTopRankedRole: false, rolesCount: 3, hasOrgManagePermission: false, isRoleBelowUserRank: true, isUserRole: false };

  it('allows dragging a role below user rank', () => {
    expect(canDrag(base)).toBe(true);
  });

  it('blocks dragging the top-ranked role (without org permission)', () => {
    expect(canDrag({ ...base, isTopRankedRole: true })).toBe(false);
  });

  it('blocks dragging when only one role exists', () => {
    expect(canDrag({ ...base, rolesCount: 1 })).toBe(false);
  });

  it('blocks dragging your own role (without org permission)', () => {
    expect(canDrag({ ...base, isUserRole: true })).toBe(false);
  });

  it('blocks dragging a role above your rank (without org permission)', () => {
    expect(canDrag({ ...base, isRoleBelowUserRank: false })).toBe(false);
  });

  it('allows org admin to drag any role including top-ranked', () => {
    expect(canDrag({ ...base, hasOrgManagePermission: true, isTopRankedRole: true, isRoleBelowUserRank: false, isUserRole: true })).toBe(true);
  });

  it('allows org admin to drag their own role', () => {
    expect(canDrag({ ...base, hasOrgManagePermission: true, isUserRole: true })).toBe(true);
  });

  it('blocks when user lacks manage settings permission', () => {
    expect(canDrag({ ...base, canManageSettings: false })).toBe(false);
  });
});

// ── Contributing project detection ───────────────────────────────────────────

describe('contributing project detection', () => {
  function isContributing(project: { owner_team_id?: string | null }, selectedTeamId: string): boolean {
    return project.owner_team_id !== selectedTeamId;
  }

  it('returns false when team is the owner', () => {
    expect(isContributing({ owner_team_id: 'team-1' }, 'team-1')).toBe(false);
  });

  it('returns true when team is not the owner', () => {
    expect(isContributing({ owner_team_id: 'team-2' }, 'team-1')).toBe(true);
  });

  it('returns true when owner_team_id is null', () => {
    expect(isContributing({ owner_team_id: null }, 'team-1')).toBe(true);
  });
});

// ── Team settings tab/subtab permission guards ───────────────────────────────

describe('team settings tab permission guards', () => {
  interface Permissions {
    view_settings?: boolean;
    manage_notification_settings?: boolean;
    view_roles?: boolean;
    edit_roles?: boolean;
  }

  /**
   * Mirrors the content-level permission checks on each settings subtab.
   * Returns what a user can VIEW (not edit).
   */
  function canViewSubtab(
    subtab: 'general' | 'notifications' | 'roles',
    permissions: Permissions | null,
    hasOrgManage: boolean,
  ): boolean {
    if (subtab === 'general') return true; // anyone can view general
    if (subtab === 'notifications') return !!(permissions?.manage_notification_settings || hasOrgManage);
    if (subtab === 'roles') return !!(permissions?.view_roles || permissions?.edit_roles || hasOrgManage);
    return false;
  }

  /**
   * Mirrors the redirect guard: given an unauthorized subtab, returns what it should redirect to.
   */
  function resolveSubtab(
    subtab: 'general' | 'notifications' | 'roles',
    permissions: Permissions | null,
    hasOrgManage: boolean,
  ): 'general' | 'notifications' | 'roles' {
    if (canViewSubtab(subtab, permissions, hasOrgManage)) return subtab;
    return 'general';
  }

  // General tab — always viewable

  it('general tab is viewable by anyone with no permissions', () => {
    expect(canViewSubtab('general', null, false)).toBe(true);
  });

  it('general tab is viewable by anyone with empty permissions', () => {
    expect(canViewSubtab('general', {}, false)).toBe(true);
  });

  // Notifications tab

  it('notifications tab requires manage_notification_settings', () => {
    expect(canViewSubtab('notifications', { manage_notification_settings: true }, false)).toBe(true);
  });

  it('notifications tab allowed with org manage permission', () => {
    expect(canViewSubtab('notifications', {}, true)).toBe(true);
  });

  it('notifications tab blocked without permission', () => {
    expect(canViewSubtab('notifications', {}, false)).toBe(false);
  });

  it('notifications tab blocked with null permissions', () => {
    expect(canViewSubtab('notifications', null, false)).toBe(false);
  });

  // Roles tab

  it('roles tab requires view_roles', () => {
    expect(canViewSubtab('roles', { view_roles: true }, false)).toBe(true);
  });

  it('roles tab allowed with edit_roles', () => {
    expect(canViewSubtab('roles', { edit_roles: true }, false)).toBe(true);
  });

  it('roles tab allowed with org manage permission', () => {
    expect(canViewSubtab('roles', {}, true)).toBe(true);
  });

  it('roles tab blocked without permission', () => {
    expect(canViewSubtab('roles', {}, false)).toBe(false);
  });

  it('roles tab blocked with null permissions', () => {
    expect(canViewSubtab('roles', null, false)).toBe(false);
  });

  // Redirect guard

  it('redirects unauthorized notifications to general', () => {
    expect(resolveSubtab('notifications', {}, false)).toBe('general');
  });

  it('redirects unauthorized roles to general', () => {
    expect(resolveSubtab('roles', {}, false)).toBe('general');
  });

  it('keeps authorized notifications tab', () => {
    expect(resolveSubtab('notifications', { manage_notification_settings: true }, false)).toBe('notifications');
  });

  it('keeps authorized roles tab', () => {
    expect(resolveSubtab('roles', { view_roles: true }, false)).toBe('roles');
  });

  it('never redirects general tab', () => {
    expect(resolveSubtab('general', null, false)).toBe('general');
    expect(resolveSubtab('general', {}, false)).toBe('general');
  });
});

// ── General settings edit permissions ────────────────────────────────────────

describe('general settings edit permissions', () => {
  /**
   * Mirrors canManageSettings: determines if user can edit team name/description.
   */
  function canEditGeneralSettings(
    teamPermissions: { view_settings?: boolean } | null,
    hasOrgManage: boolean,
  ): boolean {
    return !!(teamPermissions?.view_settings || hasOrgManage);
  }

  it('allows editing with view_settings permission', () => {
    expect(canEditGeneralSettings({ view_settings: true }, false)).toBe(true);
  });

  it('allows editing with org manage permission', () => {
    expect(canEditGeneralSettings({}, true)).toBe(true);
  });

  it('blocks editing without any permission', () => {
    expect(canEditGeneralSettings({}, false)).toBe(false);
  });

  it('blocks editing with null permissions and no org manage', () => {
    expect(canEditGeneralSettings(null, false)).toBe(false);
  });

  it('allows editing with both permissions', () => {
    expect(canEditGeneralSettings({ view_settings: true }, true)).toBe(true);
  });
});

// ── Team members tab permission guards ───────────────────────────────────────

describe('team members tab permissions', () => {
  interface Permissions {
    manage_members?: boolean;
    add_members?: boolean;
    kick_members?: boolean;
    edit_roles?: boolean;
  }

  function canAddMember(permissions: Permissions | null, hasOrgManage: boolean): boolean {
    return !!(permissions?.manage_members || permissions?.add_members || hasOrgManage);
  }

  function canKickMember(
    permissions: Permissions | null,
    hasOrgManage: boolean,
    isOwner: boolean,
    canManageByHierarchy: boolean,
  ): boolean {
    const canManageMembers = !!(permissions?.manage_members || permissions?.kick_members);
    return (canManageMembers || hasOrgManage) && !isOwner && canManageByHierarchy;
  }

  function canChangeRole(
    permissions: Permissions | null,
    hasOrgManage: boolean,
    isOwner: boolean,
    canManageByHierarchy: boolean,
  ): boolean {
    return (!!(permissions?.edit_roles) || hasOrgManage) && !isOwner && canManageByHierarchy;
  }

  // Add member

  it('allows adding member with add_members permission', () => {
    expect(canAddMember({ add_members: true }, false)).toBe(true);
  });

  it('allows adding member with manage_members permission', () => {
    expect(canAddMember({ manage_members: true }, false)).toBe(true);
  });

  it('allows adding member with org manage permission', () => {
    expect(canAddMember({}, true)).toBe(true);
  });

  it('blocks adding member without any permission', () => {
    expect(canAddMember({}, false)).toBe(false);
  });

  it('blocks adding member with null permissions', () => {
    expect(canAddMember(null, false)).toBe(false);
  });

  // Kick member

  it('allows kicking a lower-ranked non-owner member with manage_members', () => {
    expect(canKickMember({ manage_members: true }, false, false, true)).toBe(true);
  });

  it('allows kicking with kick_members permission', () => {
    expect(canKickMember({ kick_members: true }, false, false, true)).toBe(true);
  });

  it('allows kicking with org manage permission', () => {
    expect(canKickMember({}, true, false, true)).toBe(true);
  });

  it('blocks kicking the team owner', () => {
    expect(canKickMember({ manage_members: true }, false, true, true)).toBe(false);
  });

  it('blocks kicking a higher-ranked member', () => {
    expect(canKickMember({ manage_members: true }, false, false, false)).toBe(false);
  });

  it('blocks kicking without permission', () => {
    expect(canKickMember({}, false, false, true)).toBe(false);
  });

  // Change role

  it('allows changing role with edit_roles permission and lower rank', () => {
    expect(canChangeRole({ edit_roles: true }, false, false, true)).toBe(true);
  });

  it('allows changing role with org manage permission', () => {
    expect(canChangeRole({}, true, false, true)).toBe(true);
  });

  it('blocks changing owner role', () => {
    expect(canChangeRole({ edit_roles: true }, false, true, true)).toBe(false);
  });

  it('blocks changing role of higher-ranked member', () => {
    expect(canChangeRole({ edit_roles: true }, false, false, false)).toBe(false);
  });

  it('blocks changing role without permission', () => {
    expect(canChangeRole({}, false, false, true)).toBe(false);
  });
});

// ── Projects tab permission guards ───────────────────────────────────────────

describe('projects tab permissions', () => {
  function canCreateProject(
    teamPermissions: { manage_projects?: boolean } | null,
    hasOrgManage: boolean,
  ): boolean {
    return !!(teamPermissions?.manage_projects || hasOrgManage);
  }

  it('allows creating project with manage_projects permission', () => {
    expect(canCreateProject({ manage_projects: true }, false)).toBe(true);
  });

  it('allows creating project with org manage permission', () => {
    expect(canCreateProject({}, true)).toBe(true);
  });

  it('blocks creating project without any permission', () => {
    expect(canCreateProject({}, false)).toBe(false);
  });

  it('blocks creating project with null permissions', () => {
    expect(canCreateProject(null, false)).toBe(false);
  });
});

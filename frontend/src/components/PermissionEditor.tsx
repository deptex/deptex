import { useState, useEffect } from 'react';
import { Button } from './ui/button';
import { RolePermissions } from '../lib/api';
import { Save, Check } from 'lucide-react';

interface PermissionEditorProps {
  permissions: RolePermissions;
  onSave: (permissions: RolePermissions) => Promise<void>;
  onCancel?: () => void;
  isLoading?: boolean;
  onChange?: (permissions: RolePermissions) => void;
  hideActions?: boolean;
  currentUserPermissions?: RolePermissions | null;
  isOrgOwner?: boolean;
}

// Animated permission row component
function AnimatedPermissionRow({
  isVisible,
  isLast,
  children,
}: {
  isVisible: boolean;
  isLast: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      className={`grid transition-all duration-200 ease-out ${isVisible ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
        }`}
    >
      <div className="overflow-hidden">
        <div>{children}</div>
      </div>
    </div>
  );
}

export function PermissionEditor({
  permissions,
  onSave,
  onCancel,
  isLoading = false,
  onChange,
  hideActions = false,
  currentUserPermissions,
  isOrgOwner = false
}: PermissionEditorProps) {
  const [localPermissions, setLocalPermissions] = useState<RolePermissions>(permissions);

  useEffect(() => {
    setLocalPermissions(permissions);
  }, [permissions]);

  const handlePermissionChange = (key: keyof RolePermissions, value: boolean) => {
    // strict check: cannot grant permission you don't have
    if (!isOrgOwner && value) {
      if (key === 'manage_compliance') {
        const hasEither =
          currentUserPermissions?.manage_compliance || currentUserPermissions?.manage_statuses;
        if (!currentUserPermissions || !hasEither) return;
      } else if (!currentUserPermissions || !currentUserPermissions[key]) {
        return;
      }
    }

    const updated = { ...localPermissions, [key]: value };

    // Combined permission: view_members and add_members are synced together
    if (key === 'view_members') {
      updated.add_members = value;
      if (!value) {
        updated.kick_members = false;
        updated.edit_roles = false;
      }
    }

    // Use Aegis AI is one capability in the UI: sync chat, fixes, and incidents together
    if (key === 'interact_with_aegis') {
      updated.trigger_fix = value;
      updated.manage_incidents = value;
      if (!value) {
        updated.manage_aegis = false;
        updated.view_ai_spending = false;
      }
    }

    // Manage Aegis Configuration bundles view_ai_spending (same capability in the UI)
    if (key === 'manage_aegis') {
      updated.view_ai_spending = value;
    }

    // Manage Policies bundles manage_compliance + manage_statuses (same tabs/settings access)
    if (key === 'manage_compliance') {
      updated.manage_statuses = value;
    }

    setLocalPermissions(updated);
    if (onChange) {
      onChange(updated);
    }
  };

  const handleSave = async () => {
    // Persist AI block consistently: one "Use Aegis AI" concept = all three flags aligned
    const toSave: RolePermissions = { ...localPermissions };
    if (toSave.interact_with_aegis) {
      toSave.trigger_fix = true;
      toSave.manage_incidents = true;
    } else {
      toSave.trigger_fix = false;
      toSave.manage_incidents = false;
    }
    // manage_aegis and view_ai_spending are one toggle in the UI
    if (toSave.manage_aegis) {
      toSave.view_ai_spending = true;
    } else {
      toSave.view_ai_spending = false;
    }
    // Manage Policies: keep both flags aligned; manage_watchtower removed — clear if present
    if (toSave.manage_compliance) {
      toSave.manage_statuses = true;
    } else {
      toSave.manage_statuses = false;
    }
    (toSave as Record<string, boolean>).manage_watchtower = false;
    // Org settings entry no longer gated by view_settings — keep true so team/project code still works
    toSave.view_settings = true;
    await onSave(toSave);
  };

  const permissionGroups = [
    {
      title: 'Admin',
      // No view_settings — any org member can open Settings; sidebar shows only sections they have permission for
      permissions: [
        { key: 'manage_billing' as const, label: 'Manage Plan & Billing' },
        {
          key: 'manage_security' as const,
          label: 'Manage SSO, MFA & network access',
        },
        { key: 'view_members' as const, label: 'View/Add Members' },
        { key: 'kick_members' as const, label: 'Kick Members', dependsOn: 'view_members' as const },
        { key: 'edit_roles' as const, label: 'View/Edit Roles', dependsOn: 'view_members' as const },
        { key: 'view_activity' as const, label: 'View Audit Logs' },
        { key: 'manage_integrations' as const, label: 'Manage Integrations' },
        { key: 'manage_notifications' as const, label: 'Manage Notifications' },
      ],
    },
    {
      title: 'Security & Policies',
      permissions: [
        // Single toggle syncs manage_compliance + manage_statuses (policies, statuses, tiers tabs)
        { key: 'manage_compliance' as const, label: 'Manage Policies' },
      ],
    },
    {
      title: 'AI & Automation',
      permissions: [
        // Single "Use Aegis AI" toggle syncs interact_with_aegis + trigger_fix + manage_incidents in handlePermissionChange
        { key: 'interact_with_aegis' as const, label: 'Use Aegis AI' },
        {
          key: 'manage_aegis' as const,
          label: 'Manage Aegis Configuration',
          dependsOn: 'interact_with_aegis' as const,
        },
      ],
    },
    {
      title: 'Teams & Projects',
      permissions: [
        { key: 'manage_teams_and_projects' as const, label: 'Manage Teams & Projects' },
      ],
    },
  ];

  // Helper to check if a permission should be visible
  const isPermissionVisible = (perm: { key: string; dependsOn?: string }) => {
    if (!perm.dependsOn) return true;
    return localPermissions[perm.dependsOn as keyof RolePermissions] === true;
  };

  // Get visible permissions for calculating "isLast"
  const getVisiblePermissions = (perms: Array<{ key: string; dependsOn?: string }>) => {
    return perms.filter(p => isPermissionVisible(p));
  };

  return (
    <div className="space-y-2">
      {permissionGroups.filter((g) => g.permissions.length > 0).map((group) => {
        const visiblePerms = getVisiblePermissions(group.permissions);

        return (
          <div key={group.title} className="space-y-2">
            <div className="flex items-center gap-1.5 px-1">
              <h4 className="text-xs font-semibold text-foreground-secondary tracking-wide uppercase">
                {group.title}
              </h4>
            </div>
            <div className="flex flex-col">
              {group.permissions.map((perm) => {
                const dependsOn = 'dependsOn' in perm ? perm.dependsOn : undefined;
                const isVisible = isPermissionVisible(perm);
                let isDisabled = dependsOn ? !localPermissions[dependsOn] : false;

                const userHasPermission =
                  isOrgOwner ||
                  (currentUserPermissions &&
                    (perm.key === 'manage_compliance'
                      ? !!(currentUserPermissions.manage_compliance || currentUserPermissions.manage_statuses)
                      : !!currentUserPermissions[perm.key]));

                if (!userHasPermission) {
                  isDisabled = true;
                }

                // Use Aegis AI row reflects combined capability (legacy roles may have mismatched flags)
                // Manage Aegis Configuration bundles view_ai_spending — one toggle, no separate row
                const isChecked =
                  perm.key === 'interact_with_aegis'
                    ? !!(
                        localPermissions.interact_with_aegis ||
                        localPermissions.trigger_fix ||
                        localPermissions.manage_incidents
                      )
                    : perm.key === 'manage_aegis'
                      ? !!(localPermissions.manage_aegis || localPermissions.view_ai_spending)
                      : perm.key === 'manage_compliance'
                        ? !!(
                            localPermissions.manage_compliance ||
                            localPermissions.manage_statuses
                          )
                        : localPermissions[perm.key];

                // Calculate if this is the last visible permission (spacing only between visible rows)
                const visibleIndex = visiblePerms.findIndex(p => p.key === perm.key);
                const isLastVisible = visibleIndex === visiblePerms.length - 1;
                const spacerBelow = isVisible
                  ? isLastVisible
                    ? 'mb-4' /* extra space after last item in section */
                    : 'mb-2'
                  : '';

                const rowContent = (
                  <button
                    type="button"
                    onClick={() => {
                      if (isDisabled) return;
                      if (perm.key === 'interact_with_aegis') {
                        const next = !isChecked;
                        handlePermissionChange('interact_with_aegis', next);
                        return;
                      }
                      if (perm.key === 'manage_aegis') {
                        const next = !isChecked;
                        handlePermissionChange('manage_aegis', next);
                        return;
                      }
                      if (perm.key === 'manage_compliance') {
                        const next = !isChecked;
                        handlePermissionChange('manage_compliance', next);
                        return;
                      }
                      handlePermissionChange(perm.key, !isChecked);
                    }}
                    disabled={isDisabled}
                    className={`w-full rounded-lg border px-4 py-3 flex items-center gap-3 text-left transition-all outline-none focus:outline-none focus-visible:ring-2 focus-visible:ring-border focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 ${
                      isDisabled ? 'opacity-60' : ''
                    } ${
                      isChecked
                        ? 'bg-background-card border-foreground/50 ring-1 ring-foreground/20'
                        : 'bg-background-card border-border hover:border-foreground-secondary/30'
                    }`}
                  >
                    <div
                      className={`h-4 w-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center transition-colors ${
                        isChecked ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary/50 bg-transparent'
                      }`}
                      aria-hidden
                    >
                      {isChecked && <Check className="h-2.5 w-2.5" />}
                    </div>
                    <span className={`text-sm font-medium flex-1 ${isDisabled ? 'text-foreground-secondary' : 'text-foreground'}`}>
                      {perm.label}
                    </span>
                  </button>
                );

                const content =
                  dependsOn ? (
                    <AnimatedPermissionRow
                      isVisible={isVisible}
                      isLast={isLastVisible}
                    >
                      {rowContent}
                    </AnimatedPermissionRow>
                  ) : (
                    rowContent
                  );

                return (
                  <div key={perm.key} className={`min-h-0 ${spacerBelow}`}>
                    {content}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {!hideActions && (
        <div className="sticky bottom-0 -mx-6 px-6 py-4 mt-6 bg-background border-t border-border flex items-center justify-end gap-3 flex-shrink-0">
          {onCancel && (
            <Button
              onClick={onCancel}
              variant="outline"
              disabled={isLoading}
              className="px-4"
            >
              Cancel
            </Button>
          )}
          <Button
            onClick={handleSave}
            disabled={isLoading}
            className="px-6 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
          >
            {isLoading ? (
              <>
                <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                Save Permissions
              </>
            ) : (
              <>
                <Save className="h-4 w-4 mr-2" />
                Save Permissions
              </>
            )}
          </Button>
        </div>
      )}
    </div>
  );
}

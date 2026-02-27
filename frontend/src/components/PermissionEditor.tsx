import { useState, useEffect } from 'react';
import { Button } from './ui/button';
import { RolePermissions } from '../lib/api';
import { Save, Settings, Shield, Users } from 'lucide-react';

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
        <div className={`${!isLast ? 'border-b border-border' : ''}`}>
          {children}
        </div>
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
    if (!isOrgOwner && (!currentUserPermissions || !currentUserPermissions[key]) && value) {
      return;
    }

    const updated = { ...localPermissions, [key]: value };

    // If view_settings is disabled, disable dependent permissions
    if (key === 'view_settings' && !value) {
      updated.manage_billing = false;
      updated.manage_security = false;
      updated.view_members = false;
      updated.add_members = false;
      updated.edit_roles = false;
      updated.kick_members = false;
      updated.view_activity = false;
      updated.manage_integrations = false;
      updated.manage_notifications = false;
    }

    // Combined permission: view_members and add_members are synced together
    if (key === 'view_members') {
      updated.add_members = value;
      if (!value) {
        updated.kick_members = false;
        updated.edit_roles = false;
      }
    }

    setLocalPermissions(updated);
    if (onChange) {
      onChange(updated);
    }
  };

  const handleSave = async () => {
    await onSave(localPermissions);
  };

  const permissionGroups = [
    {
      title: 'Admin',
      icon: <Settings className="h-3.5 w-3.5" />,
      permissions: [
        { key: 'view_settings' as const, label: 'View Settings' },
        { key: 'manage_billing' as const, label: 'Manage Plan & Billing', dependsOn: 'view_settings' as const },
        { key: 'manage_security' as const, label: 'Manage Security', dependsOn: 'view_settings' as const },
        { key: 'view_members' as const, label: 'View/Add Members', dependsOn: 'view_settings' as const },
        { key: 'kick_members' as const, label: 'Kick Members', dependsOn: 'view_members' as const },
        { key: 'edit_roles' as const, label: 'View/Edit Roles', dependsOn: 'view_members' as const },
        { key: 'view_activity' as const, label: 'View Audit Logs', dependsOn: 'view_settings' as const },
        { key: 'manage_integrations' as const, label: 'Manage Integrations', dependsOn: 'view_settings' as const },
        { key: 'manage_notifications' as const, label: 'Manage Notifications', dependsOn: 'view_settings' as const },
      ],
    },
    {
      title: 'Security & Policies',
      icon: <Shield className="h-3.5 w-3.5" />,
      permissions: [
        { key: 'manage_compliance' as const, label: 'Manage Compliance' },
      ],
    },
    {
      title: 'Teams & Projects',
      icon: <Users className="h-3.5 w-3.5" />,
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
    <div className="space-y-4">
      {permissionGroups.filter((g) => g.permissions.length > 0).map((group) => {
        const visiblePerms = getVisiblePermissions(group.permissions);

        return (
          <div key={group.title} className="space-y-2">
            <div className="flex items-center gap-1.5 px-1">
              <span className="text-foreground-secondary">{group.icon}</span>
              <h4 className="text-xs font-semibold text-foreground-secondary tracking-wide uppercase">
                {group.title}
              </h4>
            </div>
            <div className="rounded-lg border border-border bg-background overflow-hidden">
              {group.permissions.map((perm) => {
                const dependsOn = 'dependsOn' in perm ? perm.dependsOn : undefined;
                const isVisible = isPermissionVisible(perm);
                let isDisabled = dependsOn ? !localPermissions[dependsOn] : false;

                const userHasPermission = isOrgOwner || (currentUserPermissions ? !!currentUserPermissions[perm.key] : false);

                if (!userHasPermission) {
                  isDisabled = true;
                }

                const isChecked = localPermissions[perm.key];

                // Calculate if this is the last visible permission
                const visibleIndex = visiblePerms.findIndex(p => p.key === perm.key);
                const isLastVisible = visibleIndex === visiblePerms.length - 1;

                // If this permission has no dependency, render it normally
                if (!dependsOn) {
                  return (
                    <div
                      key={perm.key}
                      className={`w-full px-4 py-3 flex items-center justify-between ${!isLastVisible ? 'border-b border-border' : ''
                        } ${isDisabled ? 'opacity-40' : ''}`}
                    >
                      <span className={`text-sm font-medium ${isDisabled ? 'text-foreground-secondary' : 'text-foreground'}`}>
                        {perm.label}
                      </span>
                      <button
                        onClick={() => !isDisabled && handlePermissionChange(perm.key, !isChecked)}
                        disabled={isDisabled}
                        className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-border focus:ring-offset-2 focus:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 ${isChecked ? 'bg-primary' : 'bg-background-subtle'
                          }`}
                      >
                        <span
                          className={`inline-block h-3.5 w-3.5 transform rounded-full bg-background transition-transform ${isChecked ? 'translate-x-4' : 'translate-x-0.5'
                            }`}
                        />
                      </button>
                    </div>
                  );
                }

                // For dependent permissions, wrap in animated container
                return (
                  <AnimatedPermissionRow
                    key={perm.key}
                    isVisible={isVisible}
                    isLast={isLastVisible}
                  >
                    <div
                      className={`w-full px-4 py-3 flex items-center justify-between ${isDisabled ? 'opacity-40' : ''
                        }`}
                    >
                      <span className={`text-sm font-medium ${isDisabled ? 'text-foreground-secondary' : 'text-foreground'}`}>
                        {perm.label}
                      </span>
                      <button
                        onClick={() => !isDisabled && handlePermissionChange(perm.key, !isChecked)}
                        disabled={isDisabled}
                        className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-border focus:ring-offset-2 focus:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 ${isChecked ? 'bg-primary' : 'bg-background-subtle'
                          }`}
                      >
                        <span
                          className={`inline-block h-3.5 w-3.5 transform rounded-full bg-background transition-transform ${isChecked ? 'translate-x-4' : 'translate-x-0.5'
                            }`}
                        />
                      </button>
                    </div>
                  </AnimatedPermissionRow>
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

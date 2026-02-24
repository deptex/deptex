import { useState, useEffect } from 'react';
import { Button } from './ui/button';
import { TeamPermissions } from '../lib/api';
import { Save, Settings, Users, FolderKanban, ShieldAlert } from 'lucide-react';

interface TeamPermissionEditorProps {
    permissions: TeamPermissions;
    onSave: (permissions: TeamPermissions) => Promise<void>;
    onCancel?: () => void;
    isLoading?: boolean;
    onChange?: (permissions: TeamPermissions) => void;
    hideActions?: boolean;
    currentUserPermissions?: TeamPermissions | null;
    isOwner?: boolean;
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

export function TeamPermissionEditor({
    permissions,
    onSave,
    onCancel,
    isLoading = false,
    onChange,
    hideActions = false,
    currentUserPermissions,
    isOwner = false
}: TeamPermissionEditorProps) {
    const [localPermissions, setLocalPermissions] = useState<TeamPermissions>(permissions);

    useEffect(() => {
        setLocalPermissions(permissions);
    }, [permissions]);

    const handlePermissionChange = (key: keyof TeamPermissions, value: boolean) => {
        // strict check: cannot grant permission you don't have
        if (!isOwner && (!currentUserPermissions || !currentUserPermissions[key]) && value) {
            return;
        }

        const updated = { ...localPermissions, [key]: value };

        // Dependency Logic

        // View Settings dependencies
        if (key === 'view_settings' && !value) {
            updated.view_members = false;
            updated.add_members = false; // implied by view/add members
            updated.edit_roles = false;
            updated.view_roles = false;
            // kick_members is usually under view_members/manage members
            updated.kick_members = false;
            updated.manage_notification_settings = false;
        }

        // View/Add Members
        // User structure: Admin -> View Settings -> View/Add Members -> ...
        if ((key === 'view_members' || key === 'add_members') && !value) {
            // If unchecking, ensure sub-tasks are off
            updated.kick_members = false;
            updated.edit_roles = false;
            updated.view_roles = false;
        }

        // Sync view_members and add_members if they are grouped as "View/Add Members"
        // The user said "view/add members" is a single item/section?
        // "subtask of this is view/add members"
        // I will treat 'view_members' as the toggle for this group, and enabling it enables 'add_members' too?
        // Or I'll just keep them separate but grouped.
        // Let's assume 'view_members' is the parent key for the UI group "View/Add Members".
        if (key === 'view_members') {
            updated.add_members = value; // Sync add with view for this specific grouping request?
            if (!value) {
                updated.kick_members = false;
                updated.edit_roles = false;
                updated.view_roles = false;
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

    // User Requested Structure:
    // Admin: 
    //   - Resolve Alerts (resolve_alerts)
    //   - View Settings (view_settings)
    //       - View/Add Members (view_members + add_members)
    //           - Manage Members (kick_members)
    //           - Manage Roles (view_roles + edit_roles - usually edit_roles implies view)
    // Projects:
    //   - Manage Projects (manage_projects)

    const permissionGroups = [
        {
            title: 'Admin',
            icon: <Settings className="h-3.5 w-3.5" />,
            permissions: [
                { key: 'resolve_alerts' as const, label: 'Resolve Alerts' },
                { key: 'view_settings' as const, label: 'View Settings' },
                { key: 'manage_notification_settings' as const, label: 'Manage Notification Settings', dependsOn: 'view_settings' as const },
                { key: 'view_members' as const, label: 'View/Add Members', dependsOn: 'view_settings' as const },
                { key: 'kick_members' as const, label: 'Remove Members', dependsOn: 'view_members' as const },
                { key: 'edit_roles' as const, label: 'Manage Roles', dependsOn: 'view_members' as const },
            ],
        },
        {
            title: 'Projects',
            icon: <FolderKanban className="h-3.5 w-3.5" />,
            permissions: [
                { key: 'manage_projects' as const, label: 'Manage Projects' },
            ],
        },
    ];

    // Helper to check if a permission should be visible
    const isPermissionVisible = (perm: { key: string; dependsOn?: string }) => {
        if (!perm.dependsOn) return true;
        return localPermissions[perm.dependsOn as keyof TeamPermissions] === true;
    };

    // Get visible permissions for calculating "isLast"
    const getVisiblePermissions = (perms: Array<{ key: string; dependsOn?: string }>) => {
        return perms.filter(p => isPermissionVisible(p));
    };

    return (
        <div className="space-y-4">
            {permissionGroups.map((group) => {
                const visiblePerms = getVisiblePermissions(group.permissions);

                return (
                    <div key={group.title} className="space-y-2">
                        <div className="flex items-center gap-1.5 px-1">
                            <span className="text-foreground-secondary">{group.icon}</span>
                            <h4 className="text-xs font-semibold text-foreground-secondary tracking-wide uppercase">
                                {group.title}
                            </h4>
                        </div>
                        <div className="rounded-lg border border-border bg-background overflow-hidden men-box-shadow">
                            {group.permissions.map((perm) => {
                                const dependsOn = 'dependsOn' in perm ? perm.dependsOn : undefined;
                                const isVisible = isPermissionVisible(perm);
                                let isDisabled = dependsOn ? !localPermissions[dependsOn as keyof TeamPermissions] : false;

                                const userHasPermission = isOwner || (currentUserPermissions ? !!currentUserPermissions[perm.key as keyof TeamPermissions] : false);

                                if (!userHasPermission) {
                                    isDisabled = true;
                                }

                                const isChecked = localPermissions[perm.key as keyof TeamPermissions];

                                // Calculate if this is the last visible permission
                                const visibleIndex = visiblePerms.findIndex(p => p.key === perm.key);
                                const isLastVisible = visibleIndex === visiblePerms.length - 1;

                                // No indentation - all permissions use same padding
                                const paddingLeft = 'px-4';
                                const translation = 'translate-x-0.5';
                                const checkedTranslation = 'translate-x-4';

                                const renderRow = (
                                    <div
                                        key={perm.key}
                                        className={`w-full ${paddingLeft} py-3 flex items-center justify-between ${isDisabled ? 'opacity-40' : ''}`}
                                    >
                                        <div className="flex flex-col">
                                            <span className={`text-sm font-medium ${isDisabled ? 'text-foreground-secondary' : 'text-foreground'}`}>
                                                {perm.label}
                                            </span>
                                        </div>
                                        <button
                                            onClick={() => !isDisabled && handlePermissionChange(perm.key as keyof TeamPermissions, !isChecked)}
                                            disabled={isDisabled}
                                            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-border focus:ring-offset-2 focus:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 ${isChecked ? 'bg-primary' : 'bg-background-subtle'
                                                }`}
                                        >
                                            <span
                                                className={`inline-block h-3.5 w-3.5 transform rounded-full bg-background transition-transform ${isChecked ? checkedTranslation : translation
                                                    }`}
                                            />
                                        </button>
                                    </div>
                                );

                                if (!dependsOn) {
                                    return (
                                        <div key={perm.key} className={`${!isLastVisible ? 'border-b border-border' : ''}`}>
                                            {renderRow}
                                        </div>
                                    );
                                }

                                return (
                                    <AnimatedPermissionRow
                                        key={perm.key}
                                        isVisible={isVisible}
                                        isLast={isLastVisible}
                                    >
                                        {renderRow}
                                    </AnimatedPermissionRow>
                                );
                            })}
                        </div>
                    </div>
                );
            })}

            {!hideActions && (
                <div className="flex items-center justify-end gap-3 pt-6 border-t border-border">
                    {onCancel && (
                        <Button
                            onClick={onCancel}
                            variant="ghost"
                            disabled={isLoading}
                            className="px-4"
                        >
                            Cancel
                        </Button>
                    )}
                    <Button
                        onClick={handleSave}
                        disabled={isLoading}
                        className="px-6 bg-primary text-primary-foreground hover:bg-primary/90"
                    >
                        {isLoading ? (
                            <>
                                <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full mr-2" />
                                Saving
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

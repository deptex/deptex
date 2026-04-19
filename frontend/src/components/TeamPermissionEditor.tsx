import { useState, useEffect } from 'react';
import { Button } from './ui/button';
import { TeamPermissions } from '../lib/api';
import { Save, Check } from 'lucide-react';

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
                <div>{children}</div>
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
        // Normalize legacy roles: derive manage_members from add_members/kick_members if not set
        const normalized = { ...permissions };
        if (!normalized.manage_members && (normalized.add_members || normalized.kick_members)) {
            normalized.manage_members = true;
        }
        setLocalPermissions(normalized);
    }, [permissions]);

    const handlePermissionChange = (key: keyof TeamPermissions, value: boolean) => {
        // strict check: cannot grant permission you don't have
        if (!isOwner && (!currentUserPermissions || !currentUserPermissions[key]) && value) {
            return;
        }

        const updated = { ...localPermissions, [key]: value };

        // Dependency Logic

        // View Settings: when disabled, disable dependents
        if (key === 'view_settings' && !value) {
            updated.manage_notification_settings = false;
            updated.edit_roles = false;
        }

        // Manage Members: when disabled, disable edit_roles (Manage Roles depends on both)
        // Sync add_members and kick_members for backend compatibility
        if (key === 'manage_members') {
            updated.add_members = value;
            updated.kick_members = value;
            if (!value) {
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

    // Structure: View Settings, Manage Members (top-level). Manage Roles depends on BOTH.
    const permissionGroups = [
        {
            title: 'Admin',
            permissions: [
                { key: 'view_settings' as const, label: 'View Settings' },
                { key: 'manage_notification_settings' as const, label: 'Manage Notification Settings', dependsOn: 'view_settings' as const },
                { key: 'manage_members' as const, label: 'Manage Members' },
                { key: 'edit_roles' as const, label: 'Manage Roles', dependsOnAll: ['view_settings', 'manage_members'] as const },
            ],
        },
        {
            title: 'Projects',
            permissions: [
                { key: 'manage_projects' as const, label: 'Manage Projects' },
            ],
        },
    ];

    type PermDef = { key: string; dependsOn?: string; dependsOnAll?: readonly string[] };

    // Helper to check if a permission should be visible
    const isPermissionVisible = (perm: PermDef) => {
        if (perm.dependsOnAll) {
            return perm.dependsOnAll.every(k => localPermissions[k as keyof TeamPermissions] === true);
        }
        if (!perm.dependsOn) return true;
        return localPermissions[perm.dependsOn as keyof TeamPermissions] === true;
    };

    // Get visible permissions for calculating "isLast"
    const getVisiblePermissions = (perms: PermDef[]) => {
        return perms.filter(p => isPermissionVisible(p));
    };

    return (
        <div className="space-y-2">
            {permissionGroups.map((group) => {
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
                                const dependsOnAll = 'dependsOnAll' in perm ? perm.dependsOnAll : undefined;
                                const isVisible = isPermissionVisible(perm);
                                let isDisabled = false;
                                if (dependsOnAll) {
                                    isDisabled = !dependsOnAll.every(k => localPermissions[k as keyof TeamPermissions] === true);
                                } else if (dependsOn) {
                                    isDisabled = !localPermissions[dependsOn as keyof TeamPermissions];
                                }

                                const userHasPermission = isOwner || (currentUserPermissions ? !!currentUserPermissions[perm.key as keyof TeamPermissions] : false);

                                if (!userHasPermission) {
                                    isDisabled = true;
                                }

                                const isChecked = localPermissions[perm.key as keyof TeamPermissions];

                                // Calculate if this is the last visible permission
                                const visibleIndex = visiblePerms.findIndex(p => p.key === perm.key);
                                const isLastVisible = visibleIndex === visiblePerms.length - 1;
                                const spacerBelow = isVisible
                                    ? isLastVisible ? 'mb-4' : 'mb-2'
                                    : '';

                                const rowContent = (
                                    <button
                                        type="button"
                                        onClick={() => {
                                            if (isDisabled) return;
                                            handlePermissionChange(perm.key as keyof TeamPermissions, !isChecked);
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

                                const hasDependency = dependsOn || dependsOnAll;
                                if (!hasDependency) {
                                    return (
                                        <div key={perm.key} className={`min-h-0 ${spacerBelow}`}>
                                            {rowContent}
                                        </div>
                                    );
                                }

                                return (
                                    <div key={perm.key} className={`min-h-0 ${spacerBelow}`}>
                                        <AnimatedPermissionRow
                                            isVisible={isVisible}
                                            isLast={isLastVisible}
                                        >
                                            {rowContent}
                                        </AnimatedPermissionRow>
                                    </div>
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

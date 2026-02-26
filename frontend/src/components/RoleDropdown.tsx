import { useState, useRef, useEffect, useLayoutEffect } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown, Users } from 'lucide-react';
import { RoleBadge } from './RoleBadge';

interface RoleDropdownProps {
  value: string;
  onChange: (value: string) => void;
  roles: Array<{ name: string; display_name?: string | null; is_default?: boolean; color?: string | null; id?: string }>;
  excludeRoles?: string[];
  className?: string;
  getRoleDisplayName?: (roleName: string) => string;
  getRoleColor?: (roleName: string) => string | undefined;
  variant?: 'default' | 'modal';
  memberCounts?: Record<string, number>;
  showBadges?: boolean;
}

export function RoleDropdown({
  value,
  onChange,
  roles,
  excludeRoles = [],
  className = '',
  getRoleDisplayName: externalGetRoleDisplayName,
  variant = 'default',
  memberCounts,
  showBadges = false
}: RoleDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [portalPosition, setPortalPosition] = useState<{ top: number; left: number; width: number; placement: 'bottom' | 'top' } | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Measure trigger position for portal (modal variant)
  useLayoutEffect(() => {
    if (variant === 'modal' && isOpen && triggerRef.current) {
      const updatePosition = () => {
        if (!triggerRef.current) return;
        const rect = triggerRef.current.getBoundingClientRect();
        const spaceBelow = window.innerHeight - rect.bottom;
        const spaceAbove = rect.top;
        const dropdownHeight = 256; // max-h-60 ≈ 240px + padding
        const placement: 'bottom' | 'top' = spaceBelow >= dropdownHeight || spaceBelow >= spaceAbove ? 'bottom' : 'top';
        setPortalPosition({
          left: rect.left,
          width: Math.max(rect.width, 240),
          top: placement === 'bottom' ? rect.bottom + 6 : rect.top - 6,
          placement
        });
      };
      updatePosition();
      window.addEventListener('scroll', updatePosition, true);
      window.addEventListener('resize', updatePosition);
      return () => {
        window.removeEventListener('scroll', updatePosition, true);
        window.removeEventListener('resize', updatePosition);
      };
    } else if (variant === 'modal' && !isOpen) {
      setPortalPosition(null);
    }
  }, [variant, isOpen]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      const inTrigger = dropdownRef.current?.contains(target);
      const inMenu = variant === 'modal' ? menuRef.current?.contains(target) : inTrigger;
      if (!inTrigger && !inMenu) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen, variant]);

  // Filter out excluded roles and deduplicate by name
  const availableRoles = roles
    .filter(role => !excludeRoles.includes(role.name))
    .filter((role, index, self) =>
      index === self.findIndex(r => r.name === role.name)
    );

  const getRoleDisplayName = (roleName: string): string => {
    // Use external function if provided
    if (externalGetRoleDisplayName) {
      return externalGetRoleDisplayName(roleName);
    }

    // Otherwise use internal logic
    const role = roles.find(r => r.name === roleName);
    if (role && role.display_name) {
      return role.display_name;
    }
    if (roleName === 'owner') return 'Owner';
    if (roleName === 'member') return 'Member';
    if (roleName === 'all') return 'All Roles';
    return roleName.charAt(0).toUpperCase() + roleName.slice(1);
  };

  const selectedRole = availableRoles.find(r => r.name === value);

  const dropdownContent = (
    <div
      ref={variant === 'modal' ? menuRef : undefined}
      className={`w-full min-w-[240px] bg-background-card border border-border rounded-lg shadow-xl overflow-hidden animate-in fade-in-0 zoom-in-95 duration-100 ${variant === 'modal' ? 'z-[9999]' : 'z-50'} ${variant === 'modal' && portalPosition ? 'fixed' : 'absolute mt-1.5'}`}
      style={variant === 'modal' && portalPosition ? {
        top: portalPosition.placement === 'bottom' ? portalPosition.top : 'auto',
        bottom: portalPosition.placement === 'top' ? window.innerHeight - portalPosition.top : 'auto',
        left: portalPosition.left,
        width: portalPosition.width,
        pointerEvents: 'auto' // Radix Dialog sets pointer-events:none outside content; override so portaled dropdown receives clicks
      } : undefined}
    >
      <div className="py-1 max-h-60 overflow-auto overscroll-contain">
        {availableRoles.map((role) => {
          const memberCount = memberCounts?.[role.name] ?? 0;
          const hasDetails = showBadges && role.name !== 'all';

          return (
            <button
              key={role.name}
              type="button"
              onClick={() => {
                onChange(role.name);
                setIsOpen(false);
              }}
              className="w-full px-3 py-2.5 flex items-center justify-between hover:bg-table-hover transition-colors text-left"
            >
              {hasDetails ? (
                <>
                  <div className="flex flex-col gap-0.5 min-w-0 flex-1 mr-3">
                    <span className="text-sm font-medium text-foreground truncate">
                      {getRoleDisplayName(role.name)}
                    </span>
                    <div className="flex items-center gap-1 text-foreground-secondary">
                      <Users className="h-3 w-3" />
                      <span className="text-xs">
                        {memberCount} {memberCount === 1 ? 'member' : 'members'}
                      </span>
                    </div>
                  </div>
                  <RoleBadge
                    role={role.name}
                    roleDisplayName={role.display_name}
                    roleColor={role.color}
                  />
                </>
              ) : (
                <span className="text-sm text-foreground">{getRoleDisplayName(role.name)}</span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );

  return (
    <div className={`relative ${className}`} ref={dropdownRef}>
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={`w-full min-w-[240px] px-3 py-2.5 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary flex items-center justify-between transition-all ${variant === 'modal'
          ? 'bg-background-card hover:border-foreground-secondary/30'
          : 'bg-background-card hover:border-foreground-secondary/30'
          } ${isOpen ? 'ring-2 ring-primary/50 border-primary' : ''}`}
      >
        <span className="text-left">
          {selectedRole ? getRoleDisplayName(selectedRole.name) : 'Select a role...'}
        </span>
        <ChevronDown className={`h-4 w-4 text-foreground-secondary flex-shrink-0 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        variant === 'modal' && portalPosition
          ? createPortal(dropdownContent, document.body)
          : dropdownContent
      )}
    </div>
  );
}

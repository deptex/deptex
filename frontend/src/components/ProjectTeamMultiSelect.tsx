import { useState, useRef, useEffect, useLayoutEffect } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown, Check } from 'lucide-react';
import { Team } from '../lib/api';

interface ProjectTeamMultiSelectProps {
  value: string[];
  onChange: (value: string[]) => void;
  teams: Team[];
  className?: string;
  variant?: 'default' | 'modal';
}

export function ProjectTeamMultiSelect({
  value,
  onChange,
  teams,
  className = '',
  variant = 'default'
}: ProjectTeamMultiSelectProps) {
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
        const dropdownHeight = 256;
        const placement: 'bottom' | 'top' = spaceBelow >= dropdownHeight || spaceBelow >= spaceAbove ? 'bottom' : 'top';
        setPortalPosition({
          left: rect.left,
          width: rect.width,
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

  const toggleTeam = (teamId: string) => {
    if (value.includes(teamId)) {
      onChange(value.filter(id => id !== teamId));
    } else {
      onChange([...value, teamId]);
    }
  };

  const selectedTeams = teams.filter(team => value.includes(team.id));

  const dropdownContent = (
    <div
      ref={variant === 'modal' ? menuRef : undefined}
      className={`w-full bg-background-card border border-border rounded-lg shadow-xl overflow-hidden animate-in fade-in-0 zoom-in-95 duration-100 ${variant === 'modal' ? 'z-[9999]' : 'z-50'} ${variant === 'modal' && portalPosition ? 'fixed' : 'absolute mt-1.5'}`}
      style={variant === 'modal' && portalPosition ? {
        top: portalPosition.placement === 'bottom' ? portalPosition.top : 'auto',
        bottom: portalPosition.placement === 'top' ? window.innerHeight - portalPosition.top : 'auto',
        left: portalPosition.left,
        width: portalPosition.width,
        pointerEvents: 'auto' // Radix Dialog sets pointer-events:none outside content; override so portaled dropdown receives clicks
      } : undefined}
    >
      <div className="py-1 max-h-60 overflow-auto overscroll-contain">
        {teams.length === 0 ? (
          <div className="px-3 py-4 text-sm text-foreground-secondary text-center">
            No teams available
          </div>
        ) : (
          teams.map((team) => {
            const isSelected = value.includes(team.id);
            return (
              <button
                key={team.id}
                type="button"
                onClick={() => toggleTeam(team.id)}
                className="w-full px-3 py-2.5 flex items-center justify-between hover:bg-table-hover transition-colors text-left"
              >
                <div className="flex flex-col gap-0.5 min-w-0">
                  <span className="text-sm font-medium text-foreground">{team.name}</span>
                  {team.description && (
                    <span className="text-xs text-foreground-secondary line-clamp-1">{team.description}</span>
                  )}
                </div>
                <div
                  className={`h-4 w-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center ${
                    isSelected ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary/50 bg-transparent'
                  }`}
                  aria-hidden
                >
                  {isSelected && <Check className="h-2.5 w-2.5" />}
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );

  return (
    <div className={`relative ${className}`} ref={dropdownRef}>
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={`w-full px-3 py-2.5 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary flex items-center justify-between transition-all min-h-[42px] ${variant === 'modal'
          ? 'bg-background-card hover:border-foreground-secondary/30'
          : 'bg-background-card hover:border-foreground-secondary/30'
          } ${isOpen ? 'ring-2 ring-primary/50 border-primary' : ''}`}
      >
        <div className="flex items-center gap-2 flex-1 min-w-0">
          {selectedTeams.length === 0 ? (
            <span className="text-foreground-secondary">Select teams...</span>
          ) : (
            <div className="flex items-center gap-1.5 flex-wrap">
              {selectedTeams.map((team, index) => (
                <span key={team.id} className="text-foreground text-sm">
                  {team.name}
                  {index < selectedTeams.length - 1 && ','}
                </span>
              ))}
            </div>
          )}
        </div>
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

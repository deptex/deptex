import { useState, useRef, useEffect } from 'react';
import { ChevronDown, Users } from 'lucide-react';

interface Team {
  id: string;
  name: string;
  avatar_url?: string | null;
  description?: string | null;
}

interface TeamDropdownProps {
  value: string;
  onChange: (value: string) => void;
  teams: Team[];
  className?: string;
  allOptionLabel?: string;
  showNoTeamOption?: boolean;
  noTeamLabel?: string;
  variant?: 'default' | 'modal';
  memberCounts?: Record<string, number>;
  showMemberCounts?: boolean;
}

export function TeamDropdown({ value, onChange, teams, className = '', allOptionLabel = 'All Teams', showNoTeamOption = false, noTeamLabel = 'No Team', variant = 'default', memberCounts, showMemberCounts = false }: TeamDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const baseOptions = showNoTeamOption
    ? [{ id: '', name: noTeamLabel }, ...teams]
    : [{ id: 'all', name: allOptionLabel }, ...teams];

  const getDisplayName = (teamId: string): string => {
    if (teamId === 'all') return allOptionLabel;
    if (teamId === '') return noTeamLabel;
    const team = teams.find(t => t.id === teamId);
    return team ? team.name : (showNoTeamOption ? noTeamLabel : 'Select a team...');
  };

  const selectedOption = baseOptions.find(opt => opt.id === value);

  return (
    <div className={`relative ${className}`} ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={`w-full px-3 py-2.5 border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary flex items-center justify-between transition-all ${variant === 'modal'
          ? 'bg-background-card hover:border-foreground-secondary/30'
          : 'bg-background-card hover:border-foreground-secondary/30'
          } ${isOpen ? 'ring-2 ring-primary/50 border-primary' : ''}`}
      >
        <span className="text-left">
          {selectedOption ? getDisplayName(selectedOption.id) : (showNoTeamOption ? noTeamLabel : allOptionLabel)}
        </span>
        <ChevronDown className={`h-4 w-4 text-foreground-secondary flex-shrink-0 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className={`absolute left-0 right-0 mt-1.5 bg-background-card border border-border rounded-lg shadow-xl overflow-auto max-h-60 animate-in fade-in-0 zoom-in-95 duration-100 overscroll-contain ${variant === 'modal' ? 'z-[100]' : 'z-50'}`}>
          <div className="py-1">
            {baseOptions.map((option) => {
              const isSpecialOption = option.id === 'all' || option.id === '';
              const team = teams.find(t => t.id === option.id);
              const count = memberCounts?.[option.id] ?? 0;
              const hasDetails = showMemberCounts && (isSpecialOption || !!team);

              return (
                <button
                  key={option.id}
                  type="button"
                  onClick={() => {
                    onChange(option.id);
                    setIsOpen(false);
                  }}
                  className="w-full px-3 py-2.5 flex items-center justify-between hover:bg-table-hover transition-colors text-left"
                >
                  {hasDetails ? (
                    <div className="flex flex-col gap-0.5 min-w-0 flex-1">
                      <span className="text-sm font-medium text-foreground truncate">{option.name}</span>
                      <div className="flex items-center gap-1 text-foreground-secondary">
                        <Users className="h-3 w-3" />
                        <span className="text-xs">
                          {count} {count === 1 ? 'member' : 'members'}
                        </span>
                      </div>
                    </div>
                  ) : (
                    <span className="text-sm text-foreground">{option.name}</span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

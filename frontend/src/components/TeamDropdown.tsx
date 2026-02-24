import { useState, useRef, useEffect } from 'react';
import { ChevronDown, Check } from 'lucide-react';

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
}

export function TeamDropdown({ value, onChange, teams, className = '', allOptionLabel = 'All Teams', showNoTeamOption = false, noTeamLabel = 'No Team', variant = 'default' }: TeamDropdownProps) {
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
        <div className="absolute z-50 w-full min-w-[280px] mt-2 bg-background-card border border-border rounded-md shadow-lg max-h-60 overflow-auto">
          <div className="py-1">
            {baseOptions.map((option) => {
              const isSelected = option.id === value;
              const isSpecialOption = option.id === 'all' || option.id === '';
              const team = teams.find(t => t.id === option.id);

              return (
                <button
                  key={option.id}
                  type="button"
                  onClick={() => {
                    onChange(option.id);
                    setIsOpen(false);
                  }}
                  className="w-full px-3 py-2.5 flex items-center justify-between hover:bg-background-subtle/20 transition-colors text-left"
                >
                  {isSpecialOption ? (
                    <>
                      <span className="text-sm text-foreground">{option.name}</span>
                      {isSelected && <Check className="h-4 w-4 text-foreground flex-shrink-0" />}
                    </>
                  ) : (
                    <>
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <img
                          src={team?.avatar_url || '/images/team_profile.png'}
                          alt={option.name}
                          className="h-9 w-9 rounded-full object-cover border border-border flex-shrink-0"
                        />
                        <div className="flex flex-col min-w-0 flex-1">
                          <span className="text-sm font-medium text-foreground truncate">{option.name}</span>
                          {team?.description && (
                            <span className="text-xs text-foreground-secondary truncate block overflow-hidden text-ellipsis whitespace-nowrap max-w-[200px]">{team.description}</span>
                          )}
                        </div>
                      </div>
                      {isSelected && <Check className="h-4 w-4 text-foreground flex-shrink-0 ml-2" />}
                    </>
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

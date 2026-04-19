import { useState, useRef, useEffect } from 'react';
import { ChevronDown, Check } from 'lucide-react';

interface Team {
  id: string;
  name: string;
}

interface ProjectTeamDropdownProps {
  value: string;
  onChange: (value: string) => void;
  teams: Team[];
  className?: string;
}

export function ProjectTeamDropdown({ value, onChange, teams, className = '' }: ProjectTeamDropdownProps) {
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

  const getDisplayName = (teamId: string): string => {
    if (teamId === '') return 'No Team';
    const team = teams.find(t => t.id === teamId);
    return team ? team.name : 'No Team';
  };

  const selectedOption = value ? teams.find(t => t.id === value) : null;

  return (
    <div className={`relative ${className}`} ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-3 py-2 bg-background-card border border-border rounded-md text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent flex items-center justify-between transition-colors hover:bg-background-card/80"
      >
        <span className="text-left">
          {selectedOption ? selectedOption.name : 'No Team'}
        </span>
        <ChevronDown className={`h-4 w-4 text-foreground-secondary flex-shrink-0 transition-transform ${isOpen ? 'transform rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute z-50 w-full mt-2 bg-background-card border border-border rounded-md shadow-lg max-h-60 overflow-auto">
          <div className="py-1">
            {/* No Team option */}
            <button
              type="button"
              onClick={() => {
                onChange('');
                setIsOpen(false);
              }}
              className={`w-full px-3 py-2 flex items-center justify-between hover:bg-background-subtle/20 transition-colors text-left ${value === '' ? 'bg-background-subtle/30' : ''
                }`}
            >
              <span className="text-sm text-foreground">No Team</span>
              {value === '' && <Check className="h-4 w-4 text-primary flex-shrink-0" />}
            </button>

            {/* Team options */}
            {teams.map((team) => {
              const isSelected = team.id === value;
              return (
                <button
                  key={team.id}
                  type="button"
                  onClick={() => {
                    onChange(team.id);
                    setIsOpen(false);
                  }}
                  className={`w-full px-3 py-2 flex items-center justify-between hover:bg-background-subtle/20 transition-colors text-left ${isSelected ? 'bg-background-subtle/30' : ''
                    }`}
                >
                  <span className="text-sm text-foreground">{team.name}</span>
                  {isSelected && <Check className="h-4 w-4 text-primary flex-shrink-0" />}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}


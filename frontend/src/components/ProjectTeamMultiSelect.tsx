import { useState, useRef, useEffect } from 'react';
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
  const dropdownRef = useRef<HTMLDivElement>(null);

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

  const toggleTeam = (teamId: string) => {
    if (value.includes(teamId)) {
      onChange(value.filter(id => id !== teamId));
    } else {
      onChange([...value, teamId]);
    }
  };

  const selectedTeams = teams.filter(team => value.includes(team.id));

  return (
    <div className={`relative ${className}`} ref={dropdownRef}>
      <button
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
                <div key={team.id} className="flex items-center gap-1.5">
                  <div className="flex items-center gap-1.5">
                    <img
                      src={team.avatar_url || '/images/team_profile.png'}
                      alt={team.name}
                      className="h-4 w-4 rounded-full object-cover border border-border flex-shrink-0"
                    />
                    <span className="text-foreground text-sm">{team.name}</span>
                  </div>
                  {index < selectedTeams.length - 1 && (
                    <span className="text-foreground-secondary">,</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
        <ChevronDown className={`h-4 w-4 text-foreground-secondary flex-shrink-0 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute z-50 w-full mt-1.5 bg-background-card border border-border rounded-lg shadow-xl overflow-hidden animate-in fade-in-0 zoom-in-95 duration-100">
          <div className="py-1 max-h-60 overflow-auto">
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
                    className="w-full px-3 py-2.5 flex items-center justify-between hover:bg-background-subtle/20 transition-colors text-left"
                  >
                    <div className="flex items-center gap-2.5">
                      <img
                        src={team.avatar_url || '/images/team_profile.png'}
                        alt={team.name}
                        className="h-7 w-7 rounded-full object-cover border border-border flex-shrink-0"
                      />
                      <div className="flex flex-col">
                        <span className="text-sm font-medium text-foreground">{team.name}</span>
                        {team.description && (
                          <span className="text-xs text-foreground-secondary line-clamp-1">{team.description}</span>
                        )}
                      </div>
                    </div>
                    {isSelected && (
                      <Check className="h-4 w-4 text-foreground flex-shrink-0" />
                    )}
                  </button>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}

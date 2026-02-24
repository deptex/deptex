import { Check, ChevronDown, Lock } from 'lucide-react';
import { Team } from '../lib/api';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import { cn } from '../lib/utils';

interface ProjectTeamSelectProps {
  value: string | null;
  onChange: (value: string | null) => void;
  teams: Team[];
  className?: string;
  variant?: 'default' | 'modal';
  locked?: boolean;
  placeholder?: string;
}

export function ProjectTeamSelect({
  value,
  onChange,
  teams,
  className = '',
  variant = 'default',
  locked = false,
  placeholder = 'Select a team...'
}: ProjectTeamSelectProps) {
  const selectedTeam = teams.find(team => team.id === value);

  const handleSelect = (next: string | null) => {
    if (locked) return;
    onChange(next);
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          disabled={locked}
          className={cn(
            'w-full min-h-[42px] px-3 py-2.5 rounded-lg text-sm text-left',
            'border border-border bg-background-card',
            'focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary',
            'flex items-center justify-between gap-2 transition-all',
            variant === 'modal' && 'bg-background-card hover:border-foreground-secondary/30',
            !variant && 'hover:border-foreground-secondary/30',
            'data-[state=open]:ring-2 data-[state=open]:ring-primary/50 data-[state=open]:border-primary',
            locked && 'cursor-not-allowed opacity-80',
            className
          )}
        >
          <span className={cn(
            'flex-1 min-w-0 truncate',
            !selectedTeam && 'text-foreground-secondary'
          )}>
            {selectedTeam ? selectedTeam.name : placeholder}
          </span>
          {locked ? (
            <Lock className="h-4 w-4 text-foreground-secondary flex-shrink-0" />
          ) : (
            <ChevronDown className="h-4 w-4 text-foreground-secondary flex-shrink-0 transition-transform duration-200 [[data-state=open]_&]:rotate-180" />
          )}
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="start"
        sideOffset={6}
        className="min-w-[var(--radix-dropdown-menu-trigger-width)] max-h-[min(16rem,60vh)] overflow-auto rounded-lg border border-border bg-background-card p-1 shadow-xl"
      >
        {teams.length === 0 ? (
          <div className="px-3 py-4 text-sm text-foreground-secondary text-center">
            No teams available
          </div>
        ) : (
          <>
            <DropdownMenuItem
              onSelect={() => handleSelect(null)}
              className="rounded-md px-3 py-2.5 text-sm cursor-pointer focus:bg-table-hover flex items-center justify-between gap-2"
            >
              <span className="text-foreground-secondary">No team (optional)</span>
              <div
                className={cn(
                  'h-4 w-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center transition-colors',
                  value === null ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary/50 bg-transparent'
                )}
                aria-hidden
              >
                {value === null && <Check className="h-2.5 w-2.5" />}
              </div>
            </DropdownMenuItem>
            <DropdownMenuSeparator className="my-1" />
            {teams.map((team) => {
              const isSelected = value === team.id;
              return (
                <DropdownMenuItem
                  key={team.id}
                  onSelect={() => handleSelect(team.id)}
                  className="rounded-md px-3 py-2.5 text-sm cursor-pointer focus:bg-table-hover flex items-center justify-between gap-2"
                >
                  <div className="flex flex-col gap-0.5 min-w-0">
                    <span className="font-medium text-foreground">
                      {team.name}
                    </span>
                    {team.description && (
                      <span className="text-xs text-foreground-secondary line-clamp-1">
                        {team.description}
                      </span>
                    )}
                  </div>
                  <div
                    className={cn(
                      'h-4 w-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center transition-colors',
                      isSelected ? 'border-foreground bg-foreground text-background' : 'border-foreground-secondary/50 bg-transparent'
                    )}
                    aria-hidden
                  >
                    {isSelected && <Check className="h-2.5 w-2.5" />}
                  </div>
                </DropdownMenuItem>
              );
            })}
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

import { useState } from 'react';
import { ChevronDown, Lock, Search } from 'lucide-react';
import { Team } from '../lib/api';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
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
  /** Called when the dropdown opens — lets the caller lazy-load `teams` on first open. */
  onOpen?: () => void;
  /** Show a loading state inside the dropdown while `teams` is being fetched. */
  loading?: boolean;
}

export function ProjectTeamSelect({
  value,
  onChange,
  teams,
  className = '',
  variant = 'default',
  locked = false,
  placeholder = 'Select a team...',
  onOpen,
  loading = false,
}: ProjectTeamSelectProps) {
  const [search, setSearch] = useState('');
  const selectedTeam = teams.find(team => team.id === value);

  const handleToggle = (id: string) => {
    if (locked) return;
    onChange(value === id ? null : id);
  };

  const q = search.trim().toLowerCase();
  const filteredTeams = q
    ? teams.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          (t.description ?? '').toLowerCase().includes(q),
      )
    : teams;

  return (
    <DropdownMenu onOpenChange={(open) => { if (open) onOpen?.(); else setSearch(''); }}>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          disabled={locked}
          style={{ WebkitTapHighlightColor: 'transparent' }}
          className={cn(
            'w-full min-h-[42px] px-3 py-2.5 rounded-lg text-sm text-left',
            'border border-border bg-background-card',
            'focus:outline-none focus:ring-2 focus:ring-ring focus:border-input',
            'flex items-center justify-between gap-2 transition-colors',
            variant === 'modal' && 'bg-background-card hover:border-foreground-secondary/30',
            !variant && 'hover:border-foreground-secondary/30',
            'data-[state=open]:ring-2 data-[state=open]:ring-ring data-[state=open]:border-input',
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
        className="min-w-[var(--radix-dropdown-menu-trigger-width)] rounded-lg border border-border bg-background-card p-0 shadow-xl"
      >
        {loading ? (
          <div className="p-1" aria-busy="true" aria-label="Loading teams">
            {[0, 1, 2].map((i) => (
              <div key={i} className="rounded-md px-3 py-2.5 flex flex-col gap-1.5">
                <div className={cn('h-4 rounded bg-muted animate-pulse', i === 1 ? 'w-24' : 'w-32')} />
                <div className={cn('h-3 rounded bg-muted/60 animate-pulse', i === 1 ? 'w-36' : 'w-44')} />
              </div>
            ))}
          </div>
        ) : teams.length === 0 ? (
          <div className="px-3 py-4 text-sm text-foreground-secondary text-center">
            No teams available
          </div>
        ) : (
          <>
            <div className="p-2 border-b border-border">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-foreground-secondary pointer-events-none" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  onKeyDown={(e) => e.stopPropagation()}
                  placeholder="Search teams..."
                  autoFocus
                  style={{ WebkitTapHighlightColor: 'transparent' }}
                  className="w-full pl-9 pr-3 py-2 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input transition-colors"
                />
              </div>
            </div>
            <div className="max-h-[min(16rem,60vh)] overflow-auto p-1">
              {filteredTeams.length === 0 ? (
                <div className="px-3 py-4 text-sm text-foreground-secondary text-center">
                  No matching teams
                </div>
              ) : (
                filteredTeams.map((team) => (
                  <DropdownMenuItem
                    key={team.id}
                    onSelect={() => handleToggle(team.id)}
                    className="rounded-md px-3 py-2.5 text-sm cursor-pointer focus:bg-table-hover flex items-center gap-2"
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
                  </DropdownMenuItem>
                ))
              )}
            </div>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

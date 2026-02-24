import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Check, ChevronsUpDown, Users } from 'lucide-react';
import { api, Team } from '../lib/api';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';

interface TeamSwitcherProps {
  organizationId: string;
  currentTeamId: string;
  currentTeamName: string;
}

export default function TeamSwitcher({
  organizationId,
  currentTeamId,
  currentTeamName,
}: TeamSwitcherProps) {
  const [teams, setTeams] = useState<Team[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    if (isOpen) {
      loadTeams();
    }
  }, [isOpen]);

  const loadTeams = async () => {
    try {
      setIsLoading(true);
      const teamsData = await api.getTeams(organizationId);
      setTeams(teamsData);
    } catch (error) {
      console.error('Failed to load teams:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const filteredTeams = teams.filter(team =>
    team.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleSelectTeam = (teamId: string) => {
    navigate(`/organizations/${organizationId}/teams/${teamId}`);
    setIsOpen(false);
  };

  // Find current team to get its avatar
  const currentTeam = teams.find(t => t.id === currentTeamId);

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <button className="flex items-center justify-center p-1 -ml-1.5 rounded hover:bg-background-subtle transition-colors">
          <ChevronsUpDown className="h-4 w-4 text-foreground-secondary hover:text-foreground transition-colors" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-80 p-0">
        <div className="p-2">
          <div className="relative mb-2">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
            <input
              type="text"
              placeholder="Find team..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              autoFocus
            />
          </div>

          <div className="max-h-64 overflow-y-auto">
            {isLoading ? (
              // Loading skeleton
              <div className="space-y-1">
                <div className="flex items-center gap-2 px-3 py-2">
                  <div className="h-7 w-7 rounded-full bg-border animate-pulse" />
                  <div className="h-4 w-32 bg-border rounded animate-pulse" />
                </div>
              </div>
            ) : (
              <>
                {/* Current team */}
                {(() => {
                  const currentT = filteredTeams.find(t => t.id === currentTeamId);
                  return currentT && (
                    <button
                      onClick={() => handleSelectTeam(currentTeamId)}
                      className="w-full flex items-center justify-between px-3 py-2 rounded-md text-left group"
                    >
                      <div className="flex items-center gap-2">
                        <img
                          src={currentT.avatar_url || '/images/team_profile.png'}
                          alt={currentT.name}
                          className="h-7 w-7 rounded-full object-cover border border-border"
                        />
                        <span className="text-sm font-medium text-foreground group-hover:text-foreground transition-colors">
                          {currentTeamName}
                        </span>
                      </div>
                      <Check className="h-4 w-4 text-primary" />
                    </button>
                  );
                })()}

                {/* Other teams */}
                {filteredTeams
                  .filter(team => team.id !== currentTeamId)
                  .map((team) => (
                    <button
                      key={team.id}
                      onClick={() => handleSelectTeam(team.id)}
                      className="w-full flex items-center px-3 py-2 rounded-md text-left group"
                    >
                      <img
                        src={team.avatar_url || '/images/team_profile.png'}
                        alt={team.name}
                        className="h-7 w-7 rounded-full object-cover border border-border mr-2"
                      />
                      <span className="text-sm text-foreground-secondary group-hover:text-foreground transition-colors">
                        {team.name}
                      </span>
                    </button>
                  ))}

                {/* Empty state */}
                {filteredTeams.length === 0 && (
                  <div className="px-3 py-4 text-sm text-foreground-secondary text-center">
                    No teams found
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

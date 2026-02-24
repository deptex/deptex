import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Check, ChevronsUpDown } from 'lucide-react';
import { api, Project } from '../lib/api';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import { FrameworkIcon } from './framework-icon';

interface ProjectSwitcherProps {
  organizationId: string;
  currentProjectId: string;
  currentProjectName: string;
}

export default function ProjectSwitcher({
  organizationId,
  currentProjectId,
  currentProjectName,
}: ProjectSwitcherProps) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    if (isOpen && projects.length === 0) {
      loadProjects();
    }
  }, [isOpen]);

  const loadProjects = async () => {
    try {
      setLoading(true);
      const projectsData = await api.getProjects(organizationId);
      setProjects(projectsData);
    } catch (error) {
      console.error('Failed to load projects:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredProjects = projects.filter(project =>
    project.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleSelectProject = (projectId: string) => {
    navigate(`/organizations/${organizationId}/projects/${projectId}`);
    setIsOpen(false);
  };

  // Find current project to get its framework
  const currentProject = projects.find(p => p.id === currentProjectId);

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
              placeholder="Find project..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-background border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              autoFocus
            />
          </div>

          <div className="max-h-64 overflow-y-auto">
            {loading ? (
              /* Loading skeleton */
              <div className="space-y-1">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="flex items-center gap-2 px-3 py-2">
                    <div className="h-5 w-5 bg-muted rounded animate-pulse"></div>
                    <div className="h-4 w-32 bg-muted rounded animate-pulse"></div>
                  </div>
                ))}
              </div>
            ) : (
              <>
                {/* Current project */}
                {(() => {
                  const currentProj = filteredProjects.find(p => p.id === currentProjectId);
                  return currentProj && (
                    <button
                      onClick={() => handleSelectProject(currentProjectId)}
                      className="w-full flex items-center justify-between px-3 py-2 rounded-md text-left group"
                    >
                      <div className="flex items-center gap-2">
                        <FrameworkIcon frameworkId={currentProj.framework} size={20} />
                        <span className="text-sm font-medium text-foreground group-hover:text-foreground transition-colors">
                          {currentProjectName}
                        </span>
                      </div>
                      <Check className="h-4 w-4 text-primary" />
                    </button>
                  );
                })()}

                {/* Other projects */}
                {filteredProjects
                  .filter(project => project.id !== currentProjectId)
                  .map((project) => (
                    <button
                      key={project.id}
                      onClick={() => handleSelectProject(project.id)}
                      className="w-full flex items-center px-3 py-2 rounded-md text-left group"
                    >
                      <FrameworkIcon frameworkId={project.framework} size={20} className="mr-2" />
                      <span className="text-sm text-foreground-secondary group-hover:text-foreground transition-colors">
                        {project.name}
                      </span>
                    </button>
                  ))}

                {/* Empty state */}
                {filteredProjects.length === 0 && (
                  <div className="px-3 py-4 text-sm text-foreground-secondary text-center">
                    No projects found
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

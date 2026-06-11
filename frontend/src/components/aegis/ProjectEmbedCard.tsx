import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import { api, type ProjectWithRole } from '../../lib/api';
import { cn } from '../../lib/utils';
import { FrameworkIcon } from '../framework-icon';

interface ProjectEmbedCardProps {
  organizationId: string;
  projectId: string;
}

export function ProjectEmbedCard({ organizationId, projectId }: ProjectEmbedCardProps) {
  /** Same destination as opening a project from the team sidebar on org overview (`openProjectInSidebar`). */
  const overviewProjectSidebarTo = useMemo(
    () => ({
      pathname: `/organizations/${organizationId}/overview`,
      search: new URLSearchParams({
        sidebar: 'project',
        projectId,
        tab: 'vulnerabilities',
      }).toString(),
    }),
    [organizationId, projectId],
  );

  const [project, setProject] = useState<ProjectWithRole | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    setProject(null);
    api
      .getProject(organizationId, projectId, true)
      .then((p) => {
        if (!cancelled) setProject(p);
      })
      .catch(() => {
        if (!cancelled) setError('Could not load this project.');
      });
    return () => {
      cancelled = true;
    };
  }, [organizationId, projectId]);

  const linkClassName = cn(
    'my-2 block rounded-lg border border-border bg-background-card text-left transition-all',
    'hover:bg-background-card/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
    'group',
  );

  if (error) {
    return (
      <Link to={overviewProjectSidebarTo} className={cn(linkClassName, 'px-3 py-2 text-xs text-foreground-muted')}>
        {error}
      </Link>
    );
  }

  if (!project) {
    return (
      <Link to={overviewProjectSidebarTo} className={cn(linkClassName, 'p-5')}>
        <div className="animate-pulse flex items-center justify-between">
          <div className="flex min-w-0 flex-1 items-center gap-3">
            <div className="h-6 w-6 rounded bg-muted" />
            <div className="h-4 w-32 rounded bg-muted" />
            <div className="h-5 w-20 rounded bg-muted" />
          </div>
          <div className="ml-2 h-5 w-5 rounded bg-muted" />
        </div>
      </Link>
    );
  }

  const inner = (
    <div className="flex items-center justify-between">
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <FrameworkIcon frameworkId={project.framework ?? undefined} size={24} />
        <h3 className="truncate text-base font-semibold text-foreground">
          {project.name}
        </h3>
      </div>
      <ChevronRight className="ml-2 h-5 w-5 shrink-0 text-foreground-secondary transition-colors group-hover:text-foreground" />
    </div>
  );

  return (
    <Link to={overviewProjectSidebarTo} className={cn(linkClassName, 'p-5')}>
      {inner}
    </Link>
  );
}

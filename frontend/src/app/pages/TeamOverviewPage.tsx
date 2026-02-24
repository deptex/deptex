import { useState, useEffect, useMemo } from 'react';
import { useOutletContext, Link } from 'react-router-dom';
import { Shield, AlertTriangle, ChevronRight, CheckCircle2 } from 'lucide-react';
import { api, Project, TeamWithRole, TeamPermissions } from '../../lib/api';

interface TeamContextType {
  team: TeamWithRole | null;
  reloadTeam: () => Promise<void>;
  organizationId: string;
  userPermissions: TeamPermissions | null;
}

export default function TeamOverviewPage() {
  const { team, organizationId } = useOutletContext<TeamContextType>();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const teamProjects = useMemo(() => {
    if (!team) return [];
    return projects.filter((p) => p.team_ids?.includes(team.id));
  }, [projects, team]);

  const compliantCount = useMemo(
    () => teamProjects.filter((p) => p.is_compliant !== false).length,
    [teamProjects]
  );
  const nonCompliant = useMemo(
    () => teamProjects.filter((p) => p.is_compliant === false),
    [teamProjects]
  );

  useEffect(() => {
    if (!organizationId || !team) return;
    let cancelled = false;
    setError(null);
    setLoading(true);
    api
      .getProjects(organizationId)
      .then((data) => {
        if (!cancelled) setProjects(data);
      })
      .catch((err: any) => {
        if (!cancelled) setError(err.message || 'Failed to load projects');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [organizationId, team?.id]);

  // Note: Overview is always accessible to all team members - no permission check needed

  if (!team) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse">
          <div className="h-8 bg-background-subtle rounded w-48 mb-6"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="bg-background-card border border-border rounded-lg p-6">
                <div className="h-4 bg-background-subtle rounded w-20 mb-2"></div>
                <div className="h-8 bg-background-subtle rounded w-16"></div>
              </div>
            ))}
          </div>
        </div>
      </main>
    );
  }

  const allCompliant = !loading && !error && teamProjects.length > 0 && compliantCount === teamProjects.length;
  const hasIssues = !loading && !error && nonCompliant.length > 0;

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      <div className="space-y-8">
        {/* Team compliance status card */}
        <section>
          <div className="bg-background-card border border-border rounded-xl overflow-hidden shadow-sm">
            {/* Card header: title + status icon */}
            <div className="flex items-center gap-4 px-6 py-4 border-b border-border bg-background-subtle/30">
              <div
                className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${
                  loading || error
                    ? 'bg-background-subtle'
                    : teamProjects.length === 0
                      ? 'bg-foreground-secondary/10'
                      : allCompliant
                        ? 'bg-success/15'
                        : 'bg-destructive/10'
                }`}
              >
                {loading && <div className="h-5 w-5 rounded-full border-2 border-foreground-secondary/30 border-t-foreground-secondary animate-spin" />}
                {!loading && error && <AlertTriangle className="h-6 w-6 text-destructive" />}
                {!loading && !error && teamProjects.length === 0 && (
                  <Shield className="h-6 w-6 text-foreground-secondary" />
                )}
                {!loading && !error && teamProjects.length > 0 && allCompliant && (
                  <CheckCircle2 className="h-6 w-6 text-success" />
                )}
                {!loading && !error && teamProjects.length > 0 && !allCompliant && (
                  <Shield className="h-6 w-6 text-destructive" />
                )}
              </div>
              <div className="min-w-0 flex-1">
                <h2 className="text-base font-semibold text-foreground">Team compliance status</h2>
                <p className="text-sm text-foreground-secondary mt-0.5">
                  {loading
                    ? 'Loading…'
                    : error
                      ? 'Could not load compliance data'
                      : teamProjects.length === 0
                        ? 'No projects in this team'
                        : allCompliant
                          ? `${teamProjects.length} project${teamProjects.length !== 1 ? 's' : ''} compliant`
                          : `${compliantCount} of ${teamProjects.length} projects compliant`}
                </p>
              </div>
            </div>

            {/* Card body */}
            <div className="p-6">
              {loading && (
                <div className="animate-pulse space-y-3">
                  <div className="h-4 bg-background-subtle rounded w-full max-w-sm" />
                  <div className="h-4 bg-background-subtle rounded w-full max-w-xs" />
                </div>
              )}
              {!loading && error && (
                <p className="text-sm text-destructive">{error}</p>
              )}
              {!loading && !error && teamProjects.length === 0 && (
                <p className="text-sm text-foreground-secondary">
                  Add projects to this team to see compliance status.
                </p>
              )}
              {!loading && !error && teamProjects.length > 0 && allCompliant && (
                <p className="text-sm text-foreground-secondary">
                  All projects in this team meet the organization&apos;s license policies.
                </p>
              )}
              {hasIssues && (
                <div className="space-y-3">
                  <p className="text-sm font-medium text-foreground">Non-compliant projects</p>
                  <ul className="rounded-lg border border-border bg-background-subtle/30 overflow-hidden divide-y divide-border">
                    {nonCompliant.map((project) => (
                      <li key={project.id}>
                        <Link
                          to={`/organizations/${organizationId}/projects/${project.id}/compliance`}
                          className="flex items-center gap-3 px-4 py-3 text-sm text-foreground hover:bg-background-subtle/50 transition-colors"
                        >
                          <AlertTriangle className="h-4 w-4 text-destructive shrink-0" />
                          <span className="flex-1 font-medium">{project.name}</span>
                          <span className="text-foreground-secondary text-xs">View compliance</span>
                          <ChevronRight className="h-4 w-4 text-foreground-secondary shrink-0" />
                        </Link>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}

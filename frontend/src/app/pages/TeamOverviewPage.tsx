import { useState, useEffect, useMemo, useCallback } from 'react';
import { useOutletContext, useNavigate, Link } from 'react-router-dom';
import {
  Shield, AlertTriangle, ChevronRight, Package, Users,
  Activity as ActivityIcon, FileCode, UserPlus,
} from 'lucide-react';
import {
  api, Project, TeamWithRole, TeamPermissions, TeamMember,
  TeamStats, ProjectActivityItem,
} from '../../lib/api';
import { Button } from '../../components/ui/button';
import { StatsStrip, type StatCardData } from '../../components/StatsStrip';
import { ActivityFeed } from '../../components/ActivityFeed';
import { OverviewGraph } from '../../components/OverviewGraph';

interface TeamContextType {
  team: TeamWithRole | null;
  reloadTeam: () => Promise<void>;
  organizationId: string;
  userPermissions: TeamPermissions | null;
}

function relativeTime(dateStr: string | null): string {
  if (!dateStr) return 'Never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function SeverityBar({ critical, high, medium, low }: { critical: number; high: number; medium: number; low: number }) {
  const total = critical + high + medium + low;
  if (total === 0) return null;
  return (
    <div className="flex h-2 rounded-full overflow-hidden bg-muted/30 w-full">
      {critical > 0 && <div className="bg-red-500 h-full" style={{ width: `${(critical / total) * 100}%` }} />}
      {high > 0 && <div className="bg-orange-500 h-full" style={{ width: `${(high / total) * 100}%` }} />}
      {medium > 0 && <div className="bg-yellow-500 h-full" style={{ width: `${(medium / total) * 100}%` }} />}
      {low > 0 && <div className="bg-slate-500 h-full" style={{ width: `${(low / total) * 100}%` }} />}
    </div>
  );
}

export default function TeamOverviewPage() {
  const { team, organizationId, userPermissions } = useOutletContext<TeamContextType>();
  const navigate = useNavigate();

  const [stats, setStats] = useState<TeamStats | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [activities, setActivities] = useState<ProjectActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const teamProjects = useMemo(() => {
    if (!team) return [];
    return projects.filter((p) => p.team_ids?.includes(team.id));
  }, [projects, team]);

  const loadData = useCallback(async () => {
    if (!organizationId || !team) return;
    try {
      setLoading(true);
      setError(false);
      const [s, p, m, a] = await Promise.all([
        api.getTeamStats(organizationId, team.id),
        api.getProjects(organizationId),
        api.getTeamMembers(organizationId, team.id),
        api.getActivities(organizationId, { team_id: team.id, limit: 20 }).then(acts =>
          acts.map((act: any) => ({
            id: act.id,
            source: 'activity' as const,
            type: act.activity_type ?? 'other',
            title: act.activity_type?.replace(/_/g, ' ') ?? 'Activity',
            description: act.description ?? '',
            metadata: act.metadata ?? {},
            created_at: act.created_at,
          })),
        ),
      ]);
      setStats(s);
      setProjects(p);
      setMembers(m);
      setActivities(a);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [organizationId, team?.id]);

  useEffect(() => { loadData(); }, [loadData]);

  if (!team) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-muted rounded w-48" />
          <StatsStrip cards={[]} loading />
        </div>
      </main>
    );
  }

  const hasProjects = teamProjects.length > 0;

  const statsCards: StatCardData[] = stats ? [
    {
      icon: <Package className="h-4 w-4" />,
      iconBg: 'bg-blue-500/15', iconColor: 'text-blue-400',
      label: 'Projects', value: stats.projects.total,
      sub: `${stats.projects.healthy} healthy, ${stats.projects.at_risk} at-risk`,
      onClick: () => navigate(`/organizations/${organizationId}/teams/${team.id}/projects`),
    },
    {
      icon: <Shield className="h-4 w-4" />,
      iconBg: stats.vulnerabilities.total > 0 ? 'bg-orange-500/15' : 'bg-emerald-500/15',
      iconColor: stats.vulnerabilities.total > 0 ? 'text-orange-400' : 'text-emerald-400',
      label: 'Vulnerabilities', value: stats.vulnerabilities.total,
      sub: `${stats.vulnerabilities.critical} critical, ${stats.vulnerabilities.high} high`,
    },
    {
      icon: <FileCode className="h-4 w-4" />,
      iconBg: 'bg-blue-500/15', iconColor: 'text-blue-400',
      label: 'Compliance', value: `${stats.compliance.percent}%`,
      sub: `${stats.projects.total - Math.round(stats.compliance.percent * stats.projects.total / 100)} projects non-compliant`,
    },
    {
      icon: <ActivityIcon className="h-4 w-4" />,
      iconBg: 'bg-violet-500/15', iconColor: 'text-violet-400',
      label: 'Dependencies', value: stats.dependencies_total,
    },
  ] : [];

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Header with member avatars */}
      <div className="mb-6 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold text-foreground">{team.name}</h1>
          {members.length > 0 && (
            <div className="flex items-center -space-x-2 ml-2">
              {members.slice(0, 5).map((m) => (
                <div key={m.user_id} className="relative" title={m.full_name ?? m.email}>
                  {m.avatar_url ? (
                    <img src={m.avatar_url} alt="" className="h-7 w-7 rounded-full border-2 border-background object-cover" />
                  ) : (
                    <div className="flex h-7 w-7 items-center justify-center rounded-full border-2 border-background bg-muted text-xs font-medium text-foreground-secondary">
                      {(m.full_name ?? m.email)?.[0]?.toUpperCase()}
                    </div>
                  )}
                </div>
              ))}
              {members.length > 5 && (
                <div className="flex h-7 w-7 items-center justify-center rounded-full border-2 border-background bg-muted text-xs font-medium text-foreground-secondary">
                  +{members.length - 5}
                </div>
              )}
            </div>
          )}
          <span className="text-sm text-foreground-secondary">{stats?.projects.total ?? 0} projects</span>
        </div>
      </div>

      {/* No members CTA */}
      {!loading && members.length <= 1 && (
        <div className="mb-4 px-4 py-3 rounded-lg border border-border bg-background-card text-sm flex items-center gap-3">
          <UserPlus className="h-4 w-4 text-foreground-secondary" />
          <span className="text-foreground-secondary">Invite team members to collaborate</span>
          <Button variant="outline" size="sm" className="ml-auto" onClick={() => navigate(`/organizations/${organizationId}/teams/${team.id}/members`)}>
            Invite Members
          </Button>
        </div>
      )}

      {/* No projects CTA */}
      {!loading && !hasProjects && (
        <div className="mb-6 rounded-lg border border-border bg-background-card p-8 text-center">
          <Package className="h-10 w-10 text-foreground-secondary/40 mx-auto mb-3" />
          <h2 className="text-lg font-semibold text-foreground mb-1">Assign projects to this team</h2>
          <p className="text-sm text-foreground-secondary mb-4">Projects assigned to this team will show their health, vulnerabilities, and compliance here.</p>
          <Button onClick={() => navigate(`/organizations/${organizationId}/teams/${team.id}/settings`)}>
            Team Settings
          </Button>
        </div>
      )}

      {/* Stats strip */}
      {hasProjects && <div className="mb-6"><StatsStrip cards={statsCards} loading={loading} /></div>}

      {/* Two-column: Graph + Security Summary */}
      {hasProjects && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
          <OverviewGraph
            mode="team"
            organizationId={organizationId}
            teamName={team.name}
            projects={teamProjects.map(p => ({ id: p.id, name: p.name, health_score: (p as any).health_score ?? 0 }))}
          />
          <div className="rounded-lg border border-border bg-background-card p-4">
            <h3 className="text-sm font-semibold text-foreground mb-3">Security Summary</h3>
            {stats && stats.vulnerabilities.total === 0 && stats.code_findings.semgrep_total === 0 ? (
              <div className="flex flex-col items-center justify-center py-6 text-center">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/15 mb-3">
                  <Shield className="h-5 w-5 text-emerald-400" />
                </div>
                <p className="text-sm font-medium text-foreground">No vulnerabilities detected across team projects</p>
              </div>
            ) : stats ? (
              <div className="space-y-4">
                <SeverityBar {...stats.vulnerabilities} />
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div><span className="text-red-400 font-medium">{stats.vulnerabilities.critical}</span> <span className="text-foreground-secondary">Critical</span></div>
                  <div><span className="text-orange-400 font-medium">{stats.vulnerabilities.high}</span> <span className="text-foreground-secondary">High</span></div>
                  <div><span className="text-yellow-400 font-medium">{stats.vulnerabilities.medium}</span> <span className="text-foreground-secondary">Medium</span></div>
                  <div><span className="text-slate-400 font-medium">{stats.vulnerabilities.low}</span> <span className="text-foreground-secondary">Low</span></div>
                </div>
                <div className="flex items-center gap-4 text-sm text-foreground-secondary pt-2 border-t border-border">
                  <span>Semgrep: {stats.code_findings.semgrep_total}</span>
                  <span>Secrets: {stats.code_findings.secret_total}</span>
                </div>
                {/* Top 5 vulns */}
                {stats.top_vulnerabilities.length > 0 && (
                  <div className="pt-2 border-t border-border">
                    <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-2">Top Vulnerabilities</p>
                    <div className="space-y-1.5">
                      {stats.top_vulnerabilities.map((v) => (
                        <button
                          key={v.osv_id}
                          className="flex items-center gap-2 w-full text-left rounded-md px-2 py-1.5 hover:bg-muted/50 transition-colors"
                          onClick={() => navigate(`/organizations/${organizationId}/projects/${v.worst_project.id}/security`)}
                        >
                          <span className={`h-2 w-2 rounded-full shrink-0 ${v.severity === 'critical' ? 'bg-red-500' : 'bg-orange-500'}`} />
                          <span className="text-xs font-mono text-foreground truncate">{v.osv_id}</span>
                          <span className="text-xs text-foreground-secondary truncate ml-auto">{v.worst_project.name}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="animate-pulse space-y-3">
                <div className="h-2 rounded bg-muted/60 w-full" />
                <div className="h-3 rounded bg-muted/40 w-32" />
              </div>
            )}
          </div>
        </div>
      )}

      {/* Projects Health Table */}
      {hasProjects && (
        <div className="rounded-lg border border-border bg-background-card mb-4 overflow-hidden">
          <div className="px-4 py-3 border-b border-border">
            <h3 className="text-sm font-semibold text-foreground">Projects</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
                  <th className="text-left px-4 py-2">Project</th>
                  <th className="text-left px-4 py-2">Health</th>
                  <th className="text-left px-4 py-2">Vulns</th>
                  <th className="text-left px-4 py-2">Last Sync</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {teamProjects.map((proj) => (
                  <tr
                    key={proj.id}
                    className="hover:bg-muted/30 transition-colors cursor-pointer"
                    onClick={() => navigate(`/organizations/${organizationId}/projects/${proj.id}/overview`)}
                  >
                    <td className="px-4 py-2.5">
                      <span className="font-medium text-foreground">{proj.name}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`font-bold tabular-nums ${
                        ((proj as any).health_score ?? 0) >= 80 ? 'text-emerald-400' :
                        ((proj as any).health_score ?? 0) >= 50 ? 'text-yellow-400' :
                        'text-red-400'
                      }`}>
                        {(proj as any).health_score ?? 0}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-foreground-secondary">
                      {(proj as any).alerts_count ?? 0}
                    </td>
                    <td className="px-4 py-2.5 text-foreground-secondary text-xs">
                      {relativeTime(proj.updated_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Activity feed */}
      <ActivityFeed items={activities} loading={loading} emptyMessage="Team activity will appear here." />
    </main>
  );
}

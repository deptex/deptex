import { useEffect, useState, useCallback } from 'react';
import { useOutletContext, useParams, useNavigate, useLocation } from 'react-router-dom';
import {
  FolderKanban, Users, ShieldAlert, CheckCircle2, XCircle, ArrowRight, Plus,
  Activity, Clock, BookOpen, LifeBuoy, Zap, TrendingUp, Shield, Package,
} from 'lucide-react';
import {
  Organization, api, RolePermissions, Project, OrganizationIntegration, OrganizationPolicies,
  OrgStats, ProjectActivityItem,
} from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import OrgGetStartedCard from '../../components/OrgGetStartedCard';
import { StatsStrip, type StatCardData } from '../../components/StatsStrip';
import { ActivityFeed } from '../../components/ActivityFeed';
import { OverviewGraph } from '../../components/OverviewGraph';
import { cn } from '../../lib/utils';

interface OrganizationContextType {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

const allValidTabs = ['overview', 'projects', 'teams', 'members', 'policies', 'activity', 'settings', 'compliance', 'vulnerabilities', 'security'];

export default function OrganizationDetailPage() {
  const { organization, reloadOrganization } = useOutletContext<OrganizationContextType>();
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();

  const [userPermissions, setUserPermissions] = useState<RolePermissions | null>(null);
  const [permissionsLoaded, setPermissionsLoaded] = useState(false);

  // Overview data
  const [projects, setProjects] = useState<Project[]>([]);
  const [teams, setTeams] = useState<any[]>([]);
  const [integrations, setIntegrations] = useState<OrganizationIntegration[]>([]);
  const [policies, setPolicies] = useState<OrganizationPolicies | null>(null);
  const [orgStats, setOrgStats] = useState<OrgStats | null>(null);
  const [activities, setActivities] = useState<ProjectActivityItem[]>([]);
  const [overviewLoading, setOverviewLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);

  const getCachedPermissions = (): RolePermissions | null => {
    if (!id) return null;
    if (organization?.permissions) return organization.permissions;
    const cachedStr = localStorage.getItem(`org_permissions_${id}`);
    if (cachedStr) {
      try { return JSON.parse(cachedStr); } catch { return null; }
    }
    return null;
  };

  useEffect(() => {
    const loadPermissions = async () => {
      if (!id || !organization?.role) {
        setPermissionsLoaded(true);
        return;
      }
      try {
        const roles = await api.getOrganizationRoles(id);
        const userRole = roles.find((r) => r.name === organization.role);
        if (userRole?.permissions) {
          setUserPermissions(userRole.permissions);
          localStorage.setItem(`org_permissions_${id}`, JSON.stringify(userRole.permissions));
        }
      } catch {
        // Keep using cached permissions
      } finally {
        setPermissionsLoaded(true);
      }
    };
    loadPermissions();
  }, [id, organization?.role]);

  const loadOverviewData = useCallback(async () => {
    if (!id) return;
    const pathParts = location.pathname.split('/');
    const currentTab = pathParts[pathParts.length - 1];
    const isOverview = currentTab === id || currentTab === 'overview';
    if (!isOverview) return;

    setOverviewLoading(true);
    setStatsLoading(true);

    const [p, i, pol, t] = await Promise.all([
      api.getProjects(id).catch(() => [] as Project[]),
      api.getOrganizationIntegrations(id).catch(() => [] as OrganizationIntegration[]),
      api.getOrganizationPolicies(id).catch(() => null),
      api.getTeams(id).catch(() => []),
    ]);
    setProjects(p);
    setIntegrations(i);
    setPolicies(pol);
    setTeams(t);
    setOverviewLoading(false);

    // Fetch stats + activities in parallel (non-blocking)
    Promise.all([
      api.getOrgStats(id).catch(() => null),
      api.getActivities(id, { limit: 15 }).then(acts =>
        acts.map((act: any) => ({
          id: act.id,
          source: 'activity' as const,
          type: act.activity_type ?? 'other',
          title: act.activity_type?.replace(/_/g, ' ') ?? 'Activity',
          description: act.description ?? '',
          metadata: act.metadata ?? {},
          created_at: act.created_at,
        })),
      ).catch(() => []),
    ]).then(([s, a]) => {
      setOrgStats(s as OrgStats | null);
      setActivities(a as ProjectActivityItem[]);
      setStatsLoading(false);
    });
  }, [id, location.pathname]);

  useEffect(() => { loadOverviewData(); }, [loadOverviewData]);

  const effectivePermissions = userPermissions || getCachedPermissions();

  useEffect(() => {
    if (!id || !organization || !effectivePermissions) return;
    const pathParts = location.pathname.split('/');
    const currentTab = pathParts[pathParts.length - 1];
    if (currentTab !== id && !allValidTabs.includes(currentTab)) {
      navigate(`/organizations/${id}`, { replace: true });
      return;
    }
    if (currentTab === 'activity' && !effectivePermissions.view_activity) {
      navigate(`/organizations/${id}`, { replace: true });
    }
  }, [effectivePermissions, id, location.pathname, navigate, organization]);

  if (!organization || !effectivePermissions) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </main>
    );
  }

  const pathParts = location.pathname.split('/');
  const currentTab = pathParts[pathParts.length - 1];
  const isOverviewPage = currentTab === id || currentTab === 'overview';
  if (!isOverviewPage) return null;

  const handleGetStartedDismissed = async () => { await reloadOrganization(); };

  // Stats strip cards
  const statsCards: StatCardData[] = orgStats ? [
    {
      icon: <FolderKanban className="h-4 w-4" />,
      iconBg: 'bg-violet-500/15', iconColor: 'text-violet-400',
      label: 'Projects', value: orgStats.projects.total,
      sub: `${orgStats.projects.healthy} healthy, ${orgStats.projects.at_risk} at-risk, ${orgStats.projects.critical} critical`,
      badge: orgStats.projects.syncing_count > 0 ? (
        <span className="inline-flex items-center rounded-full bg-blue-500/15 px-2 py-0.5 text-[10px] font-medium text-blue-400">
          {orgStats.projects.syncing_count} syncing
        </span>
      ) : undefined,
      onClick: () => navigate(`/organizations/${id}/projects`),
    },
    {
      icon: <Package className="h-4 w-4" />,
      iconBg: 'bg-blue-500/15', iconColor: 'text-blue-400',
      label: 'Dependencies', value: orgStats.dependencies_total,
    },
    {
      icon: <ShieldAlert className="h-4 w-4" />,
      iconBg: orgStats.vulnerabilities.total > 0 ? 'bg-orange-500/15' : 'bg-emerald-500/15',
      iconColor: orgStats.vulnerabilities.total > 0 ? 'text-orange-400' : 'text-emerald-400',
      label: 'Vulnerabilities', value: orgStats.vulnerabilities.total,
      sub: `${orgStats.vulnerabilities.critical} critical, ${orgStats.vulnerabilities.high} high`,
      onClick: () => navigate(`/organizations/${id}/security`),
    },
    {
      icon: <CheckCircle2 className="h-4 w-4" />,
      iconBg: orgStats.compliance.percent >= 80 ? 'bg-emerald-500/15' : 'bg-amber-500/15',
      iconColor: orgStats.compliance.percent >= 80 ? 'text-emerald-400' : 'text-amber-400',
      label: 'Compliance', value: `${orgStats.compliance.percent}%`,
      sub: `${orgStats.compliance.status_distribution.filter(s => s.is_passing).reduce((a, s) => a + s.count, 0)} projects passing`,
    },
    {
      icon: <Users className="h-4 w-4" />,
      iconBg: 'bg-blue-500/15', iconColor: 'text-blue-400',
      label: 'Members', value: orgStats.members_count,
      onClick: () => navigate(`/organizations/${id}/settings/members`),
    },
  ] : [];

  // Build team → project_ids map for graph
  const teamProjectMap = teams.map((t: any) => ({
    id: t.id,
    name: t.name,
    project_ids: projects.filter(p => p.team_ids?.includes(t.id)).map(p => p.id),
  }));

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">{organization.name}</h1>
        <p className="text-sm text-foreground-secondary mt-1">
          {organization.plan.charAt(0).toUpperCase() + organization.plan.slice(1)} Plan
          {' · '}
          {organization.member_count ?? 0}{' '}
          {organization.member_count === 1 ? 'member' : 'members'}
        </p>
      </div>

      {/* Get Started card */}
      {!organization.get_started_dismissed && !overviewLoading && (
        <OrgGetStartedCard
          organization={organization}
          integrations={integrations}
          projects={projects}
          policies={policies}
          onDismissed={handleGetStartedDismissed}
          onCreateProject={() => navigate(`/organizations/${id}/projects`)}
        />
      )}

      {/* Stats strip */}
      <StatsStrip cards={statsCards} loading={statsLoading} />

      {/* Two-column: Graph + Security Posture */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <OverviewGraph
          mode="org"
          organizationId={id!}
          orgName={organization.name}
          teams={teamProjectMap}
          projects={projects.map(p => ({ id: p.id, name: p.name, health_score: (p as any).health_score ?? 0 }))}
        />
        <div className="rounded-lg border border-border bg-background-card p-4">
          <h3 className="text-sm font-semibold text-foreground mb-3">Security Posture</h3>
          {statsLoading ? (
            <div className="animate-pulse space-y-3">
              <div className="h-2 rounded bg-muted/60 w-full" />
              <div className="h-3 rounded bg-muted/40 w-32" />
            </div>
          ) : orgStats && orgStats.vulnerabilities.total === 0 && orgStats.code_findings.semgrep_total === 0 ? (
            <div className="flex flex-col items-center justify-center py-6 text-center">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/15 mb-3">
                <Shield className="h-5 w-5 text-emerald-400" />
              </div>
              <p className="text-sm font-medium text-foreground">No vulnerabilities detected</p>
            </div>
          ) : orgStats ? (
            <div className="space-y-4">
              {/* Severity bar */}
              <div className="flex h-2 rounded-full overflow-hidden bg-muted/30 w-full">
                {orgStats.vulnerabilities.critical > 0 && <div className="bg-red-500 h-full" style={{ width: `${(orgStats.vulnerabilities.critical / orgStats.vulnerabilities.total) * 100}%` }} />}
                {orgStats.vulnerabilities.high > 0 && <div className="bg-orange-500 h-full" style={{ width: `${(orgStats.vulnerabilities.high / orgStats.vulnerabilities.total) * 100}%` }} />}
                {orgStats.vulnerabilities.medium > 0 && <div className="bg-yellow-500 h-full" style={{ width: `${(orgStats.vulnerabilities.medium / orgStats.vulnerabilities.total) * 100}%` }} />}
                {orgStats.vulnerabilities.low > 0 && <div className="bg-slate-500 h-full" style={{ width: `${(orgStats.vulnerabilities.low / orgStats.vulnerabilities.total) * 100}%` }} />}
              </div>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div><span className="text-red-400 font-medium">{orgStats.vulnerabilities.critical}</span> <span className="text-foreground-secondary">Critical</span></div>
                <div><span className="text-orange-400 font-medium">{orgStats.vulnerabilities.high}</span> <span className="text-foreground-secondary">High</span></div>
                <div><span className="text-yellow-400 font-medium">{orgStats.vulnerabilities.medium}</span> <span className="text-foreground-secondary">Medium</span></div>
                <div><span className="text-slate-400 font-medium">{orgStats.vulnerabilities.low}</span> <span className="text-foreground-secondary">Low</span></div>
              </div>
              <div className="flex items-center gap-4 text-sm text-foreground-secondary pt-2 border-t border-border">
                <span>Semgrep: {orgStats.code_findings.semgrep_total}</span>
                <span>Secrets: {orgStats.code_findings.secret_total}</span>
              </div>
              {orgStats.top_vulnerabilities.length > 0 && (
                <div className="pt-2 border-t border-border">
                  <p className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-2">Top Vulnerabilities</p>
                  <div className="space-y-1.5">
                    {orgStats.top_vulnerabilities.map((v) => (
                      <button
                        key={v.osv_id}
                        className="flex items-center gap-2 w-full text-left rounded-md px-2 py-1.5 hover:bg-muted/50 transition-colors"
                        onClick={() => navigate(`/organizations/${id}/projects/${v.worst_project.id}/security`)}
                      >
                        <span className={`h-2 w-2 rounded-full shrink-0 ${v.severity === 'critical' ? 'bg-red-500' : 'bg-orange-500'}`} />
                        <span className="text-xs font-mono text-foreground truncate">{v.osv_id}</span>
                        <span className="text-xs text-foreground-secondary truncate ml-auto">{v.affected_project_count} project{v.affected_project_count !== 1 ? 's' : ''}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : null}
        </div>
      </div>

      {/* Status Distribution + Activity Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Status Distribution */}
        <div className="rounded-lg border border-border bg-background-card p-4">
          <h3 className="text-sm font-semibold text-foreground mb-3">Status Distribution</h3>
          {statsLoading ? (
            <div className="animate-pulse space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="flex items-center gap-2">
                  <div className="h-3 w-3 rounded-full bg-muted/60" />
                  <div className="h-3 w-24 rounded bg-muted/40" />
                </div>
              ))}
            </div>
          ) : orgStats ? (
            <div className="space-y-2">
              {orgStats.compliance.status_distribution.filter(s => s.count > 0).map((s) => (
                <div key={s.status_id} className="flex items-center gap-2.5">
                  <span className="h-3 w-3 rounded-full shrink-0" style={{ backgroundColor: s.color }} />
                  <span className="text-sm text-foreground flex-1">{s.name}</span>
                  <span className="text-sm font-medium text-foreground tabular-nums">{s.count}</span>
                </div>
              ))}
              {orgStats.compliance.status_distribution.every(s => s.count === 0) && (
                <p className="text-sm text-foreground-secondary">No projects with assigned statuses yet.</p>
              )}
            </div>
          ) : null}
        </div>

        {/* Activity Feed */}
        <div className="lg:col-span-2">
          <ActivityFeed items={activities} loading={statsLoading} emptyMessage="Organization activity will appear here." />
        </div>
      </div>

      {/* Quick Actions + Resources */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="flex items-center gap-2 px-5 py-3.5 border-b border-border bg-black/20">
            <Zap className="h-4 w-4 text-foreground-secondary" />
            <span className="text-sm font-semibold text-foreground">Quick Actions</span>
          </div>
          <div className="p-2 space-y-0.5">
            {effectivePermissions.manage_teams_and_projects && (
              <QuickAction icon={<Plus className="h-4 w-4" />} label="New project" onClick={() => navigate(`/organizations/${id}/projects`)} />
            )}
            {(effectivePermissions.add_members || effectivePermissions.kick_members) && (
              <QuickAction icon={<Users className="h-4 w-4" />} label="Invite members" onClick={() => navigate(`/organizations/${id}/settings/members`)} />
            )}
            <QuickAction icon={<TrendingUp className="h-4 w-4" />} label="View security" onClick={() => navigate(`/organizations/${id}/security`)} />
            {effectivePermissions.view_activity && (
              <QuickAction icon={<Activity className="h-4 w-4" />} label="Activity log" onClick={() => navigate(`/organizations/${id}/settings/audit_logs`)} />
            )}
          </div>
        </div>

        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="flex items-center gap-2 px-5 py-3.5 border-b border-border bg-black/20">
            <BookOpen className="h-4 w-4 text-foreground-secondary" />
            <span className="text-sm font-semibold text-foreground">Resources</span>
          </div>
          <div className="p-2 space-y-0.5">
            <QuickAction icon={<BookOpen className="h-4 w-4" />} label="Documentation" onClick={() => navigate('/docs/introduction')} />
            <QuickAction icon={<LifeBuoy className="h-4 w-4" />} label="Help Center" onClick={() => navigate('/docs/help')} />
          </div>
        </div>
      </div>
    </main>
  );
}

// ─── Sub-components ─────────────────────────────────────────────────────────

interface QuickActionProps {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
}

function QuickAction({ icon, label, onClick }: QuickActionProps) {
  return (
    <button
      onClick={onClick}
      className="w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
    >
      <span className="flex-shrink-0">{icon}</span>
      <span className="flex-1 text-left">{label}</span>
      <ArrowRight className="h-3.5 w-3.5 opacity-0 group-hover:opacity-100 transition-opacity" />
    </button>
  );
}

function formatRelativeTime(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60_000);
  const hours = Math.floor(diff / 3_600_000);
  const days = Math.floor(diff / 86_400_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

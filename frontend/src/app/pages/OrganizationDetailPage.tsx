import { useEffect, useState } from 'react';
import { useOutletContext, useParams, useNavigate, useLocation } from 'react-router-dom';
import {
  FolderKanban,
  Users,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  ArrowRight,
  Plus,
  ExternalLink,
  Activity,
  Clock,
  BookOpen,
  LifeBuoy,
  MessageSquare,
  Zap,
  TrendingUp,
} from 'lucide-react';
import { Organization, api, RolePermissions, Project, OrganizationIntegration, OrganizationPolicies } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import OrgGetStartedCard from '../../components/OrgGetStartedCard';
import { cn } from '../../lib/utils';

interface OrganizationContextType {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

// All valid tabs in the organization (handled by various pages)
const allValidTabs = ['overview', 'projects', 'teams', 'members', 'policies', 'activity', 'settings', 'compliance', 'vulnerabilities'];

export default function OrganizationDetailPage() {
  const { organization, reloadOrganization } = useOutletContext<OrganizationContextType>();
  const { id } = useParams<{ id: string; tab?: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();

  const [userPermissions, setUserPermissions] = useState<RolePermissions | null>(null);
  const [permissionsLoaded, setPermissionsLoaded] = useState(false);

  // Overview data
  const [projects, setProjects] = useState<Project[]>([]);
  const [integrations, setIntegrations] = useState<OrganizationIntegration[]>([]);
  const [policies, setPolicies] = useState<OrganizationPolicies | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(true);

  // Get cached permissions for immediate check
  const getCachedPermissions = (): RolePermissions | null => {
    if (!id) return null;
    if (organization?.permissions) return organization.permissions;
    const cachedStr = localStorage.getItem(`org_permissions_${id}`);
    if (cachedStr) {
      try { return JSON.parse(cachedStr); } catch { return null; }
    }
    return null;
  };

  // Load user permissions
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
        // Keep using cached permissions on error
      } finally {
        setPermissionsLoaded(true);
      }
    };
    loadPermissions();
  }, [id, organization?.role]);

  // Load overview data (projects, integrations, policies) in parallel
  useEffect(() => {
    if (!id) return;

    const pathParts = location.pathname.split('/');
    const currentTab = pathParts[pathParts.length - 1];
    const isOverview = currentTab === id || currentTab === 'overview';
    if (!isOverview) return;

    setOverviewLoading(true);
    Promise.all([
      api.getProjects(id).catch(() => [] as Project[]),
      api.getOrganizationIntegrations(id).catch(() => [] as OrganizationIntegration[]),
      api.getOrganizationPolicies(id).catch(() => null),
    ]).then(([p, i, pol]) => {
      setProjects(p);
      setIntegrations(i);
      setPolicies(pol);
      setOverviewLoading(false);
    });
  }, [id, location.pathname]);

  const effectivePermissions = userPermissions || getCachedPermissions();

  // Permission-based redirect after permissions load
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
    if (currentTab === 'aegis') {
      navigate(`/organizations/${id}`, { replace: true });
    }
  }, [effectivePermissions, id, location.pathname, navigate, organization]);

  if (!organization) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </main>
    );
  }

  if (!effectivePermissions) {
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

  // Derive stats
  const totalVulns = projects.reduce((sum, p) => sum + (p.alerts_count ?? 0), 0);
  const compliantProjects = projects.filter((p) => p.is_compliant === true).length;
  const hasPolicyDefined = !!policies?.policy_code && policies.policy_code.trim().length > 0;
  const recentProjects = [...projects]
    .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime())
    .slice(0, 5);

  const handleGetStartedDismissed = async () => {
    await reloadOrganization();
  };

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">{organization.name}</h1>
        <p className="text-sm text-foreground-secondary mt-1">
          {organization.plan.charAt(0).toUpperCase() + organization.plan.slice(1)} Plan
          {' · '}
          {organization.member_count ?? 0}{' '}
          {organization.member_count === 1 ? 'member' : 'members'}
        </p>
      </div>

      {/* Get Started card — hidden once dismissed */}
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

      {/* Stats row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          icon={<FolderKanban className="h-4 w-4" />}
          iconColor="text-violet-400"
          iconBg="bg-violet-500/10"
          label="Active Projects"
          value={overviewLoading ? '—' : String(projects.length)}
          sub={projects.length === 1 ? '1 project' : `${projects.length} projects`}
          onClick={() => navigate(`/organizations/${id}/projects`)}
        />
        <StatCard
          icon={<Users className="h-4 w-4" />}
          iconColor="text-blue-400"
          iconBg="bg-blue-500/10"
          label="Members"
          value={overviewLoading ? '—' : String(organization.member_count ?? 0)}
          sub="across all teams"
          onClick={() => navigate(`/organizations/${id}/settings/members`)}
        />
        <StatCard
          icon={<ShieldAlert className="h-4 w-4" />}
          iconColor={totalVulns > 0 ? 'text-orange-400' : 'text-green-400'}
          iconBg={totalVulns > 0 ? 'bg-orange-500/10' : 'bg-green-500/10'}
          label="Open Vulnerabilities"
          value={overviewLoading ? '—' : String(totalVulns)}
          sub={totalVulns === 0 ? 'All clear' : `across ${projects.length} project${projects.length !== 1 ? 's' : ''}`}
          onClick={() => navigate(`/organizations/${id}/vulnerabilities`)}
        />
        <StatCard
          icon={
            hasPolicyDefined ? (
              <CheckCircle2 className="h-4 w-4" />
            ) : (
              <XCircle className="h-4 w-4" />
            )
          }
          iconColor={hasPolicyDefined ? 'text-green-400' : 'text-foreground-secondary'}
          iconBg={hasPolicyDefined ? 'bg-green-500/10' : 'bg-background-subtle/50'}
          label="Policy"
          value={overviewLoading ? '—' : hasPolicyDefined ? 'Configured' : 'Not set'}
          sub={
            hasPolicyDefined
              ? `${compliantProjects}/${projects.length} projects compliant`
              : 'No policy defined yet'
          }
          onClick={() => navigate(`/organizations/${id}/compliance`)}
        />
      </div>

      {/* Bottom two-column layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Recent projects (wide) */}
        <div className="lg:col-span-2 rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-border bg-black/20">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-foreground-secondary" />
              <span className="text-sm font-semibold text-foreground">Recent Projects</span>
            </div>
            <button
              onClick={() => navigate(`/organizations/${id}/projects`)}
              className="flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground transition-colors"
            >
              View all
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>

          {overviewLoading ? (
            <div className="divide-y divide-border">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="flex items-center gap-3 px-5 py-3.5 animate-pulse">
                  <div className="h-8 w-8 rounded-md bg-muted" />
                  <div className="flex-1 space-y-1.5">
                    <div className="h-3.5 w-32 bg-muted rounded" />
                    <div className="h-3 w-20 bg-muted rounded" />
                  </div>
                </div>
              ))}
            </div>
          ) : recentProjects.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 px-6 text-center">
              <div className="h-12 w-12 rounded-full bg-background-subtle flex items-center justify-center mb-3">
                <FolderKanban className="h-5 w-5 text-foreground-secondary" />
              </div>
              <p className="text-sm font-medium text-foreground mb-1">No projects yet</p>
              <p className="text-xs text-foreground-secondary mb-4">
                Create a project to start tracking your dependencies.
              </p>
              <button
                onClick={() => navigate(`/organizations/${id}/projects`)}
                className="flex items-center gap-1.5 text-xs font-medium text-primary hover:text-primary/80 transition-colors"
              >
                <Plus className="h-3.5 w-3.5" />
                Create your first project
              </button>
            </div>
          ) : (
            <div className="divide-y divide-border">
              {recentProjects.map((project) => (
                <button
                  key={project.id}
                  onClick={() => navigate(`/organizations/${id}/projects/${project.id}`)}
                  className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-table-hover transition-colors text-left"
                >
                  <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-md border border-border bg-background-subtle">
                    <FolderKanban className="h-4 w-4 text-foreground-secondary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{project.name}</p>
                    <p className="text-xs text-foreground-secondary">
                      {project.dependencies_count ?? 0} dependencies
                      {project.team_name ? ` · ${project.team_name}` : ''}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    {project.alerts_count != null && project.alerts_count > 0 && (
                      <span className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium bg-orange-500/10 text-orange-400 border border-orange-500/20">
                        <ShieldAlert className="h-3 w-3" />
                        {project.alerts_count}
                      </span>
                    )}
                    {project.is_compliant === true && (
                      <span className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium bg-green-500/10 text-green-500 border border-green-500/20">
                        <CheckCircle2 className="h-3 w-3" />
                        Compliant
                      </span>
                    )}
                    <span className="flex items-center gap-1 text-xs text-foreground-secondary">
                      <Clock className="h-3 w-3" />
                      {formatRelativeTime(project.updated_at)}
                    </span>
                    <ArrowRight className="h-3.5 w-3.5 text-foreground-secondary" />
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Quick links sidebar */}
        <div className="space-y-4">
          {/* Quick actions */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="flex items-center gap-2 px-5 py-3.5 border-b border-border bg-black/20">
              <Zap className="h-4 w-4 text-foreground-secondary" />
              <span className="text-sm font-semibold text-foreground">Quick Actions</span>
            </div>
            <div className="p-2 space-y-0.5">
              <QuickAction
                icon={<Plus className="h-4 w-4" />}
                label="New project"
                onClick={() => navigate(`/organizations/${id}/projects`)}
              />
              <QuickAction
                icon={<Users className="h-4 w-4" />}
                label="Invite members"
                onClick={() => navigate(`/organizations/${id}/settings/members`)}
              />
              <QuickAction
                icon={<TrendingUp className="h-4 w-4" />}
                label="View vulnerabilities"
                onClick={() => navigate(`/organizations/${id}/vulnerabilities`)}
              />
              <QuickAction
                icon={<Activity className="h-4 w-4" />}
                label="Activity log"
                onClick={() => navigate(`/organizations/${id}/settings/audit_logs`)}
              />
            </div>
          </div>

          {/* Resources */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="flex items-center gap-2 px-5 py-3.5 border-b border-border bg-black/20">
              <BookOpen className="h-4 w-4 text-foreground-secondary" />
              <span className="text-sm font-semibold text-foreground">Resources</span>
            </div>
            <div className="p-2 space-y-0.5">
              <ResourceLink
                icon={<BookOpen className="h-4 w-4" />}
                label="Documentation"
                href="https://docs.deptex.com"
              />
              <ResourceLink
                icon={<LifeBuoy className="h-4 w-4" />}
                label="Support"
                href="https://docs.deptex.com/support"
              />
              <ResourceLink
                icon={<MessageSquare className="h-4 w-4" />}
                label="Community"
                href="https://discord.gg/deptex"
              />
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}

// ─── Sub-components ────────────────────────────────────────────────────────────

interface StatCardProps {
  icon: React.ReactNode;
  iconColor: string;
  iconBg: string;
  label: string;
  value: string;
  sub: string;
  onClick?: () => void;
}

function StatCard({ icon, iconColor, iconBg, label, value, sub, onClick }: StatCardProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'group text-left rounded-lg border border-border bg-background-card p-4 transition-colors',
        onClick && 'hover:border-border/80 hover:bg-background-card/80 cursor-pointer'
      )}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">
          {label}
        </span>
        <div className={cn('flex h-7 w-7 items-center justify-center rounded-md', iconBg)}>
          <span className={iconColor}>{icon}</span>
        </div>
      </div>
      <p className="text-2xl font-bold text-foreground tabular-nums">{value}</p>
      <p className="text-xs text-foreground-secondary mt-0.5">{sub}</p>
    </button>
  );
}

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

interface ResourceLinkProps {
  icon: React.ReactNode;
  label: string;
  href: string;
}

function ResourceLink({ icon, label, href }: ResourceLinkProps) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="flex items-center gap-2.5 px-3 py-2 rounded-md text-sm text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
    >
      <span className="flex-shrink-0">{icon}</span>
      <span className="flex-1">{label}</span>
      <ExternalLink className="h-3.5 w-3.5 flex-shrink-0" />
    </a>
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

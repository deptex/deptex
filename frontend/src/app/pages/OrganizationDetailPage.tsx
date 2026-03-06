import { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { useOutletContext, useParams, useNavigate, useLocation } from 'react-router-dom';
import {
  ReactFlow,
  Background,
  useNodesState,
  useEdgesState,
  BackgroundVariant,
  type Node,
  type Edge,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  ShieldAlert, CheckCircle2, Activity, LayoutGrid, Package, Shield,
} from 'lucide-react';
import {
  Organization, api, RolePermissions, Project, OrganizationIntegration, OrganizationPolicies,
  OrgStats, ProjectActivityItem,
} from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { usePlan, TIER_DISPLAY } from '../../contexts/PlanContext';
import {
  useOrganizationVulnerabilitiesGraphLayout,
  type TeamWithProjectsData,
} from '../../components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout';
import { GroupCenterNode } from '../../components/vulnerabilities-graph/GroupCenterNode';
import { VulnProjectNode } from '../../components/vulnerabilities-graph/VulnProjectNode';
import type { NodeTypes } from '@xyflow/react';
import { cn } from '../../lib/utils';

const UNGROUPED_TEAM_ID = 'org-ungrouped';
const nodeTypes: NodeTypes = {
  groupCenterNode: GroupCenterNode,
  vulnProjectNode: VulnProjectNode,
};

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

  // All hooks must run unconditionally (before any return) so hook count is stable across renders
  const { plan } = usePlan();
  const planTier = (plan?.tier ?? organization?.plan?.toLowerCase?.() ?? 'free') as keyof typeof TIER_DISPLAY;
  const planLabel = TIER_DISPLAY[planTier] ?? organization?.plan ?? 'Free';

  const teamsWithProjects: TeamWithProjectsData[] = useMemo(() => {
    const teamIds = new Set(teams.map((t: { id: string }) => t.id));
    const byTeam = new Map<string, Project[]>();
    teamIds.forEach((tid) => byTeam.set(tid, []));
    byTeam.set(UNGROUPED_TEAM_ID, []);

    projects.forEach((p: Project) => {
      const ownerId = (p as any).owner_team_id ?? (p.team_ids?.length ? p.team_ids[0] : null);
      const bucket = ownerId && teamIds.has(ownerId) ? ownerId : UNGROUPED_TEAM_ID;
      byTeam.get(bucket)!.push(p);
    });

    const ungrouped = byTeam.get(UNGROUPED_TEAM_ID) ?? [];
    const teamsWithAny = teams.filter((t: any) => (byTeam.get(t.id)?.length ?? 0) > 0);
    const teamList = [
      ...teamsWithAny,
      ...(ungrouped.length > 0 ? [{ id: UNGROUPED_TEAM_ID, name: 'No team' }] : []),
    ];

    return teamList.map((t: any) => ({
      teamId: t.id,
      teamName: t.name,
      projects: (byTeam.get(t.id) ?? []).map((p) => ({
        projectId: p.id,
        projectName: p.name,
        framework: p.framework ?? null,
        graphDepNodes: [],
        isExtracting: (p as any).repo_status != null && (p as any).repo_status !== 'ready',
      })),
    }));
  }, [teams, projects]);

  const { nodes: layoutNodes, edges: layoutEdges } = useOrganizationVulnerabilitiesGraphLayout(
    organization?.name ?? 'Organization',
    teamsWithProjects,
    organization?.avatar_url ?? null,
    false
  );

  const [graphNodes, setGraphNodes, onNodesChange] = useNodesState<Node>([]);
  const [graphEdges, setGraphEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const lastLayoutRef = useRef<string>('');

  useEffect(() => {
    const sig = layoutNodes.length + '-' + layoutNodes.map((n) => n.id).join(',');
    if (lastLayoutRef.current === sig) return;
    lastLayoutRef.current = sig;
    setGraphNodes(layoutNodes);
    setGraphEdges(layoutEdges);
  }, [layoutNodes, layoutEdges, setGraphNodes, setGraphEdges]);

  const onNodeClick = useCallback(
    (_: unknown, node: Node) => {
      const d = node.data as { projectId?: string; isTeamNode?: boolean };
      if (!d?.projectId || !id) return;
      if (d.isTeamNode) {
        navigate(`/organizations/${id}/teams/${d.projectId}/overview`);
      } else {
        navigate(`/organizations/${id}/projects/${d.projectId}/overview`);
      }
    },
    [id, navigate]
  );

  useEffect(() => {
    if (!id || !organization || !effectivePermissions) return;
    const pathParts = location.pathname.split('/');
    const currentTab = pathParts[pathParts.length - 1];
    if (currentTab !== id && !allValidTabs.includes(currentTab)) {
      navigate(`/organizations/${id}`, { replace: true });
      return;
    }
    if (currentTab === 'activity' && effectivePermissions.view_activity === false) {
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

  // Four overview badges (Risk, Status, Compliance, Dependencies)
  const riskLabel = orgStats
    ? orgStats.vulnerabilities.critical > 0
      ? 'High'
      : orgStats.vulnerabilities.high > 0
        ? 'Medium'
        : orgStats.vulnerabilities.total > 0
          ? 'Low'
          : 'None'
    : '—';
  const riskColor = orgStats?.vulnerabilities.critical
    ? 'text-red-400'
    : orgStats?.vulnerabilities.high
      ? 'text-amber-400'
      : orgStats?.vulnerabilities.total
        ? 'text-emerald-400'
        : 'text-foreground-secondary';
  const statusLabel = orgStats
    ? orgStats.projects.critical > 0
      ? 'Critical'
      : orgStats.projects.at_risk > 0
        ? 'At risk'
        : 'Healthy'
    : '—';
  const statusColor = orgStats?.projects.critical
    ? 'text-red-400'
    : orgStats?.projects.at_risk
      ? 'text-foreground-secondary'
      : 'text-emerald-400';

  return (
    <main className="mx-auto w-full max-w-7xl flex flex-col min-h-[calc(100vh-3rem)]">
      {/* One section: height = graph height; left content centered inside that height; section at top, not screen-centered */}
      <section className="h-[555px] flex flex-col lg:flex-row gap-12 px-4 sm:px-6 lg:px-8 pt-24 pb-8 items-stretch flex-none">
        {/* Left: vertically centered with graph */}
        <div className="flex flex-col justify-center flex-shrink-0 lg:w-[320px] space-y-4">
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-2xl font-bold text-foreground tracking-tight">{organization.name}</h1>
              <span className="inline-flex items-center rounded-md bg-transparent border border-border px-2.5 py-1 text-[11px] font-medium text-foreground-secondary uppercase tracking-widest">
                {planLabel}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-x-12 gap-y-3">
            <OverviewStat icon={<ShieldAlert className="h-6 w-6" />} label="Risk" value={riskLabel} valueClassName={riskColor} loading={statsLoading} />
            <OverviewStat icon={<Activity className="h-6 w-6" />} label="Status" value={statusLabel} valueClassName={statusColor} loading={statsLoading} />
            <OverviewStat icon={<CheckCircle2 className="h-6 w-6" />} label="Compliance" value={orgStats ? `${orgStats.compliance.percent}%` : '—'} valueClassName={orgStats && orgStats.compliance.percent >= 80 ? 'text-emerald-400' : 'text-foreground-secondary'} loading={statsLoading} />
            <OverviewStat icon={<Package className="h-6 w-6" />} label="Dependencies" value={orgStats ? orgStats.dependencies_total.toLocaleString() : '—'} valueClassName="text-foreground" loading={statsLoading} />
          </div>
        </div>

        {/* Right: graph area with border so it’s clearly visible */}
        <div className="flex-1 min-w-0 flex justify-end items-center">
          <div className="w-[600px] h-[555px] flex-shrink-0 rounded-xl border border-border bg-background overflow-hidden">
            {layoutNodes.length === 0 && !overviewLoading ? (
              <div className="flex flex-col items-center justify-center h-full text-center py-12">
                <LayoutGrid className="h-10 w-10 text-foreground-secondary/30 mb-3" />
                <p className="text-sm text-foreground-secondary">Create your first project to see the organization graph</p>
              </div>
            ) : (
              <div className="h-full w-full">
                <ReactFlow
                nodes={graphNodes}
                edges={graphEdges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onNodeClick={onNodeClick}
                nodeTypes={nodeTypes}
                fitView
                fitViewOptions={{
                  padding: { left: 0.5, right: 0.08, top: 0.2, bottom: 0.2 },
                  maxZoom: 1,
                }}
                minZoom={0.2}
                maxZoom={2}
                proOptions={{ hideAttribution: true }}
                defaultEdgeOptions={{ type: 'smoothstep' }}
              >
                <Background
                  variant={BackgroundVariant.Dots}
                  gap={20}
                  size={1}
                  color="rgba(148, 163, 184, 0.16)"
                />
              </ReactFlow>
              </div>
            )}
          </div>
        </div>
      </section>
    </main>
  );
}

// ─── Sub-components ─────────────────────────────────────────────────────────
// Supabase-style: only the icon sits in a small card; label and value are plain text beside it.

interface OverviewStatProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  valueClassName?: string;
  loading?: boolean;
}

function OverviewStat({ icon, label, value, valueClassName, loading }: OverviewStatProps) {
  return (
    <div className="flex items-center gap-5">
      <div className="flex h-14 w-14 flex-shrink-0 items-center justify-center rounded-lg border border-white/10 bg-white/[0.04] text-foreground-secondary">
        {icon}
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-xs font-medium uppercase tracking-widest text-foreground-secondary">{label}</p>
        {loading ? (
          <div className="h-5 w-16 rounded bg-white/5 animate-pulse mt-1" />
        ) : (
          <p className={cn('text-sm font-semibold truncate mt-1', valueClassName)}>{value}</p>
        )}
      </div>
    </div>
  );
}

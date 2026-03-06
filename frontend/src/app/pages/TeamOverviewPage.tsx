import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
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
  ShieldAlert, CheckCircle2, Activity as ActivityIcon, Package, LayoutGrid,
} from 'lucide-react';
import {
  api, Project, TeamWithRole, TeamPermissions, TeamStats,
} from '../../lib/api';
import { loadProjectVulnerabilityGraphData } from '../../lib/vulnerability-graph-data';
import { useTeamVulnerabilitiesGraphLayout, type ProjectWithGraphData } from '../../components/vulnerabilities-graph/useTeamVulnerabilitiesGraphLayout';
import { GroupCenterNode } from '../../components/vulnerabilities-graph/GroupCenterNode';
import { VulnProjectNode } from '../../components/vulnerabilities-graph/VulnProjectNode';
import type { NodeTypes } from '@xyflow/react';
import { cn } from '../../lib/utils';

const nodeTypes: NodeTypes = {
  groupCenterNode: GroupCenterNode,
  vulnProjectNode: VulnProjectNode,
};

interface TeamContextType {
  team: TeamWithRole | null;
  reloadTeam: () => Promise<void>;
  organizationId: string;
  userPermissions: TeamPermissions | null;
}

export default function TeamOverviewPage() {
  const { team, organizationId } = useOutletContext<TeamContextType>();
  const navigate = useNavigate();

  const [stats, setStats] = useState<TeamStats | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectsWithGraphData, setProjectsWithGraphData] = useState<ProjectWithGraphData[]>([]);
  const [statsLoading, setStatsLoading] = useState(true);
  const [graphLoading, setGraphLoading] = useState(true);

  const teamProjects = useMemo(() => {
    if (!team) return [];
    return projects.filter((p) => p.team_ids?.includes(team.id));
  }, [projects, team]);

  const loadData = useCallback(async () => {
    if (!organizationId || !team) return;
    try {
      setStatsLoading(true);
      const [s, p] = await Promise.all([
        api.getTeamStats(organizationId, team.id),
        api.getProjects(organizationId),
      ]);
      setStats(s);
      setProjects(p);
    } finally {
      setStatsLoading(false);
    }
  }, [organizationId, team?.id]);

  useEffect(() => { loadData(); }, [loadData]);

  useEffect(() => {
    if (!organizationId || !team?.id || teamProjects.length === 0) {
      setProjectsWithGraphData([]);
      setGraphLoading(false);
      return;
    }
    let cancelled = false;
    setGraphLoading(true);
    Promise.all(
      teamProjects.map((p) =>
        loadProjectVulnerabilityGraphData(organizationId, p.id).then((result) => ({
          projectId: p.id,
          projectName: p.name,
          graphDepNodes: result.graphDepNodes,
          framework: p.framework ?? null,
          isExtracting: (p as any).repo_status != null && (p as any).repo_status !== 'ready',
        }))
      )
    )
      .then((data) => {
        if (!cancelled) setProjectsWithGraphData(data);
      })
      .finally(() => {
        if (!cancelled) setGraphLoading(false);
      });
    return () => { cancelled = true; };
  }, [organizationId, team?.id, teamProjects]);

  const { nodes: layoutNodes, edges: layoutEdges } = useTeamVulnerabilitiesGraphLayout(
    team?.name ?? 'Team',
    projectsWithGraphData,
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
      const d = node.data as { projectId?: string };
      if (!d?.projectId || !organizationId) return;
      navigate(`/organizations/${organizationId}/projects/${d.projectId}/overview`);
    },
    [organizationId, navigate]
  );

  if (!team) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </main>
    );
  }

  const riskLabel = stats
    ? stats.vulnerabilities.critical > 0
      ? 'High'
      : stats.vulnerabilities.high > 0
        ? 'Medium'
        : stats.vulnerabilities.total > 0
          ? 'Low'
          : 'None'
    : '—';
  const riskColor = stats?.vulnerabilities.critical
    ? 'text-red-400'
    : stats?.vulnerabilities.high
      ? 'text-amber-400'
      : stats?.vulnerabilities.total
        ? 'text-emerald-400'
        : 'text-foreground-secondary';
  const statusLabel = stats
    ? stats.projects.critical > 0
      ? 'Critical'
      : stats.projects.at_risk > 0
        ? 'At risk'
        : 'Healthy'
    : '—';
  const statusColor = stats?.projects.critical
    ? 'text-red-400'
    : stats?.projects.at_risk
      ? 'text-foreground-secondary'
      : 'text-emerald-400';

  return (
    <main className="mx-auto w-full max-w-7xl flex flex-col min-h-[calc(100vh-3rem)]">
      <section className="h-[555px] flex flex-col lg:flex-row gap-12 px-4 sm:px-6 lg:px-8 pt-24 pb-8 items-stretch flex-none">
        <div className="flex flex-col justify-center flex-shrink-0 lg:w-[320px] space-y-4">
          <div>
            <h1 className="text-2xl font-bold text-foreground tracking-tight">{team.name}</h1>
          </div>
          <div className="grid grid-cols-2 gap-x-12 gap-y-3">
            <OverviewStat icon={<ShieldAlert className="h-6 w-6" />} label="Risk" value={riskLabel} valueClassName={riskColor} loading={statsLoading} />
            <OverviewStat icon={<ActivityIcon className="h-6 w-6" />} label="Status" value={statusLabel} valueClassName={statusColor} loading={statsLoading} />
            <OverviewStat icon={<CheckCircle2 className="h-6 w-6" />} label="Compliance" value={stats ? `${stats.compliance.percent}%` : '—'} valueClassName={stats && stats.compliance.percent >= 80 ? 'text-emerald-400' : 'text-foreground-secondary'} loading={statsLoading} />
            <OverviewStat icon={<Package className="h-6 w-6" />} label="Dependencies" value={stats ? stats.dependencies_total.toLocaleString() : '—'} valueClassName="text-foreground" loading={statsLoading} />
          </div>
        </div>
        <div className="flex-1 min-w-0 flex justify-end items-center">
          <div className="w-[600px] h-[555px] flex-shrink-0 rounded-xl border border-border bg-background overflow-hidden">
            {layoutNodes.length === 0 && !graphLoading ? (
              <div className="flex flex-col items-center justify-center h-full text-center py-12">
                <LayoutGrid className="h-10 w-10 text-foreground-secondary/30 mb-3" />
                <p className="text-sm text-foreground-secondary">Assign projects to this team to see the team graph</p>
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

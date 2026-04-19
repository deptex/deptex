import { memo, useMemo, useRef, useEffect, useState, useCallback } from 'react';
import {
  ReactFlow,
  Node,
  Edge,
  Handle,
  Position,
  type NodeProps,
  useNodesState,
  useEdgesState,
  ReactFlowProvider,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useNavigate } from 'react-router-dom';
import { Package, FolderKanban, Building, MoreHorizontal } from 'lucide-react';
import type { GraphDep } from '../lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

type GraphMode = 'project' | 'team' | 'org';

interface OverviewGraphProps {
  mode: GraphMode;
  organizationId: string;

  /** Project mode: graph_deps from stats endpoint */
  graphDeps?: GraphDep[];
  projectName?: string;
  frameworkName?: string;

  /** Team mode: projects list */
  teamName?: string;
  projects?: Array<{ id: string; name: string; health_score?: number }>;

  /** Org mode: teams + projects */
  orgName?: string;
  teams?: Array<{ id: string; name: string; project_ids?: string[] }>;

  fullGraphLink?: string;
}

// ─── Severity / Health colors ─────────────────────────────────────────────────

const severityColors: Record<string, { bg: string; border: string; glow: string }> = {
  critical: { bg: 'bg-red-950/80', border: 'border-red-500/60', glow: 'bg-red-500/20' },
  high: { bg: 'bg-orange-950/80', border: 'border-orange-500/50', glow: 'bg-orange-500/15' },
  medium: { bg: 'bg-yellow-950/80', border: 'border-yellow-500/40', glow: 'bg-yellow-500/10' },
  low: { bg: 'bg-slate-900/80', border: 'border-slate-500/30', glow: 'bg-slate-500/10' },
  none: { bg: 'bg-emerald-950/80', border: 'border-emerald-500/40', glow: 'bg-emerald-500/10' },
};

function healthToColor(score: number): { bg: string; border: string } {
  if (score >= 80) return { bg: 'bg-emerald-950/80', border: 'border-emerald-500/40' };
  if (score >= 50) return { bg: 'bg-yellow-950/80', border: 'border-yellow-500/40' };
  return { bg: 'bg-red-950/80', border: 'border-red-500/60' };
}

// ─── Custom Node Components ───────────────────────────────────────────────────

const CenterNode = memo(({ data }: NodeProps) => {
  const d = data as any;
  return (
    <div className="relative flex items-center gap-2.5 rounded-xl border border-primary/40 bg-background-card px-4 py-2.5 shadow-md min-w-[140px]">
      <div className="absolute inset-0 rounded-xl blur-xl opacity-20 -z-10 bg-primary/20" />
      <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/15">
        {d.icon === 'team' ? <FolderKanban className="h-4 w-4 text-primary" /> :
         d.icon === 'org' ? <Building className="h-4 w-4 text-primary" /> :
         <Package className="h-4 w-4 text-primary" />}
      </div>
      <span className="text-sm font-semibold text-foreground truncate max-w-[120px]">{d.label}</span>
      <Handle type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0" id="top" />
      <Handle type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0" id="right" />
      <Handle type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0" id="bottom" />
      <Handle type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0" id="left" />
    </div>
  );
});

const DepNode = memo(({ data }: NodeProps) => {
  const d = data as any;
  const col = severityColors[d.severity] ?? severityColors.none;
  return (
    <div className={`relative flex items-center rounded-lg border ${col.border} ${col.bg} px-3 py-1.5 shadow-sm min-w-[28px] min-h-[28px] cursor-pointer`}>
      <div className={`absolute inset-0 rounded-lg blur-md opacity-30 -z-10 ${col.glow}`} />
      {d.showLabel && <span className="text-xs text-foreground truncate max-w-[100px]">{d.label}</span>}
      <Handle type="target" position={Position.Top} className="!opacity-0 !w-0 !h-0" id="top" />
      <Handle type="target" position={Position.Right} className="!opacity-0 !w-0 !h-0" id="right" />
      <Handle type="target" position={Position.Bottom} className="!opacity-0 !w-0 !h-0" id="bottom" />
      <Handle type="target" position={Position.Left} className="!opacity-0 !w-0 !h-0" id="left" />
    </div>
  );
});

const ProjectNode = memo(({ data }: NodeProps) => {
  const d = data as any;
  const col = healthToColor(d.healthScore ?? 0);
  return (
    <div className={`relative flex items-center gap-2 rounded-lg border ${col.border} ${col.bg} px-3 py-1.5 shadow-sm cursor-pointer min-w-[60px]`}>
      <span className="text-xs font-medium text-foreground truncate max-w-[110px]">{d.label}</span>
      <Handle type="target" position={Position.Top} className="!opacity-0 !w-0 !h-0" id="top" />
      <Handle type="target" position={Position.Right} className="!opacity-0 !w-0 !h-0" id="right" />
      <Handle type="target" position={Position.Bottom} className="!opacity-0 !w-0 !h-0" id="bottom" />
      <Handle type="target" position={Position.Left} className="!opacity-0 !w-0 !h-0" id="left" />
      <Handle type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0" id="s-top" />
      <Handle type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0" id="s-right" />
      <Handle type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0" id="s-bottom" />
      <Handle type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0" id="s-left" />
    </div>
  );
});

const OverflowNode = memo(({ data }: NodeProps) => {
  const d = data as any;
  return (
    <div className="flex items-center gap-1.5 rounded-full border border-border bg-muted/50 px-3 py-1.5 cursor-pointer">
      <MoreHorizontal className="h-3.5 w-3.5 text-foreground-secondary" />
      <span className="text-xs text-foreground-secondary">{d.label}</span>
      <Handle type="target" position={Position.Top} className="!opacity-0 !w-0 !h-0" id="top" />
      <Handle type="target" position={Position.Left} className="!opacity-0 !w-0 !h-0" id="left" />
    </div>
  );
});

const nodeTypes = {
  center: CenterNode,
  dep: DepNode,
  project: ProjectNode,
  overflow: OverflowNode,
};

// ─── Layout helpers ───────────────────────────────────────────────────────────

function placeOnRing(count: number, radius: number, cx: number, cy: number): Array<{ x: number; y: number; angle: number }> {
  const golden = Math.PI * (3 - Math.sqrt(5));
  return Array.from({ length: count }).map((_, i) => {
    const angle = i * golden;
    return { x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius, angle };
  });
}

function edgeHandle(angle: number): { source: string; target: string } {
  const deg = ((angle * 180) / Math.PI + 360) % 360;
  if (deg < 45 || deg >= 315) return { source: 'right', target: 'left' };
  if (deg < 135) return { source: 'bottom', target: 'top' };
  if (deg < 225) return { source: 'left', target: 'right' };
  return { source: 'top', target: 'bottom' };
}

// ─── Layout builder per mode ──────────────────────────────────────────────────

function buildProjectGraph(props: OverviewGraphProps): { nodes: Node[]; edges: Edge[] } {
  const deps = props.graphDeps ?? [];
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  nodes.push({
    id: 'center',
    type: 'center',
    position: { x: 0, y: 0 },
    data: { label: props.projectName ?? 'Project', icon: 'project' },
  });

  if (deps.length === 0) return { nodes, edges };

  const maxShow = 30;
  const ranked = [...deps].sort((a, b) => {
    const r: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
    return (r[b.worst_severity] ?? 0) - (r[a.worst_severity] ?? 0);
  });
  const shown = ranked.slice(0, maxShow);
  const overflow = deps.length - maxShow;

  const radius = Math.max(250, 180 + shown.length * 10);
  const positions = placeOnRing(shown.length, radius, 0, 0);

  shown.forEach((dep, i) => {
    const pos = positions[i];
    const handles = edgeHandle(pos.angle);
    nodes.push({
      id: `dep-${dep.id}`,
      type: 'dep',
      position: { x: pos.x, y: pos.y },
      data: { label: dep.name, severity: dep.worst_severity, showLabel: shown.length <= 15, depId: dep.id },
    });
    edges.push({
      id: `e-center-${dep.id}`,
      source: 'center', target: `dep-${dep.id}`,
      sourceHandle: handles.source, targetHandle: handles.target,
      style: { stroke: 'rgba(113,113,122,0.3)', strokeWidth: 1 },
      type: 'straight',
    });
  });

  if (overflow > 0) {
    nodes.push({
      id: 'overflow',
      type: 'overflow',
      position: { x: radius + 40, y: radius - 20 },
      data: { label: `+${overflow} more`, link: 'deps' },
    });
  }

  return { nodes, edges };
}

function buildTeamGraph(props: OverviewGraphProps): { nodes: Node[]; edges: Edge[] } {
  const projects = props.projects ?? [];
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  nodes.push({
    id: 'center',
    type: 'center',
    position: { x: 0, y: 0 },
    data: { label: props.teamName ?? 'Team', icon: 'team' },
  });

  if (projects.length === 0) return { nodes, edges };

  const maxShow = 20;
  const sorted = [...projects].sort((a, b) => (a.health_score ?? 0) - (b.health_score ?? 0));
  const shown = sorted.slice(0, maxShow);
  const overflow = projects.length - maxShow;

  const radius = Math.max(250, 180 + shown.length * 12);
  const positions = placeOnRing(shown.length, radius, 0, 0);

  shown.forEach((proj, i) => {
    const pos = positions[i];
    const handles = edgeHandle(pos.angle);
    nodes.push({
      id: `proj-${proj.id}`,
      type: 'project',
      position: { x: pos.x, y: pos.y },
      data: { label: proj.name, healthScore: proj.health_score ?? 0, projectId: proj.id },
    });
    edges.push({
      id: `e-center-${proj.id}`,
      source: 'center', target: `proj-${proj.id}`,
      sourceHandle: handles.source, targetHandle: handles.target,
      style: { stroke: 'rgba(113,113,122,0.3)', strokeWidth: 1 },
      type: 'straight',
    });
  });

  if (overflow > 0) {
    nodes.push({
      id: 'overflow',
      type: 'overflow',
      position: { x: radius + 40, y: radius - 20 },
      data: { label: `+${overflow} more`, link: 'projects' },
    });
  }

  return { nodes, edges };
}

function buildOrgGraph(props: OverviewGraphProps): { nodes: Node[]; edges: Edge[] } {
  const teams = props.teams ?? [];
  const projects = props.projects ?? [];
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  nodes.push({
    id: 'center',
    type: 'center',
    position: { x: 0, y: 0 },
    data: { label: props.orgName ?? 'Organization', icon: 'org' },
  });

  if (teams.length === 0 && projects.length === 0) return { nodes, edges };

  const maxTeams = 8;
  const maxProjects = 25;
  const shownTeams = teams.slice(0, maxTeams);
  const teamRadius = Math.max(300, 220 + shownTeams.length * 30);
  const teamPositions = placeOnRing(shownTeams.length, teamRadius, 0, 0);

  let projectCount = 0;

  shownTeams.forEach((team, i) => {
    const pos = teamPositions[i];
    const handles = edgeHandle(pos.angle);
    nodes.push({
      id: `team-${team.id}`,
      type: 'project',
      position: { x: pos.x, y: pos.y },
      data: { label: team.name, healthScore: 75, teamId: team.id },
    });
    edges.push({
      id: `e-center-${team.id}`,
      source: 'center', target: `team-${team.id}`,
      sourceHandle: handles.source, targetHandle: handles.target,
      style: { stroke: 'rgba(113,113,122,0.3)', strokeWidth: 1 },
      type: 'straight',
    });

    // Team's projects
    const teamProjectIds = new Set(team.project_ids ?? []);
    const teamProjects = projects.filter(p => teamProjectIds.has(p.id));
    const projRadius = 120;
    const shownProjects = teamProjects.slice(0, Math.min(5, maxProjects - projectCount));
    const projPositions = placeOnRing(shownProjects.length, projRadius, pos.x, pos.y);

    shownProjects.forEach((proj, j) => {
      if (projectCount >= maxProjects) return;
      const pp = projPositions[j];
      const ph = edgeHandle(pp.angle - pos.angle);
      nodes.push({
        id: `proj-${proj.id}`,
        type: 'dep',
        position: { x: pp.x, y: pp.y },
        data: { label: proj.name, severity: (proj.health_score ?? 0) >= 80 ? 'none' : (proj.health_score ?? 0) >= 50 ? 'medium' : 'critical', showLabel: false },
      });
      edges.push({
        id: `e-${team.id}-${proj.id}`,
        source: `team-${team.id}`, target: `proj-${proj.id}`,
        sourceHandle: `s-${ph.source}`, targetHandle: ph.target,
        style: { stroke: 'rgba(113,113,122,0.2)', strokeWidth: 1 },
        type: 'straight',
      });
      projectCount++;
    });
  });

  return { nodes, edges };
}

// ─── Empty State ──────────────────────────────────────────────────────────────

function EmptyGraph({ mode }: { mode: GraphMode }) {
  const Icon = mode === 'project' ? Package : mode === 'team' ? FolderKanban : Building;
  const msg = mode === 'project' ? 'No dependencies detected' :
              mode === 'team' ? 'No projects assigned to this team' :
              'Create your first project to see the organization graph';
  return (
    <div className="flex flex-col items-center justify-center h-full text-center py-8">
      <Icon className="h-10 w-10 text-foreground-secondary/40 mb-3" />
      <p className="text-sm text-foreground-secondary">{msg}</p>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

function OverviewGraphInner(props: OverviewGraphProps) {
  const navigate = useNavigate();
  const containerRef = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new IntersectionObserver(([entry]) => { if (entry.isIntersecting) setVisible(true); }, { threshold: 0.1 });
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  const { initialNodes, initialEdges, isEmpty } = useMemo(() => {
    let result: { nodes: Node[]; edges: Edge[] };
    if (props.mode === 'project') result = buildProjectGraph(props);
    else if (props.mode === 'team') result = buildTeamGraph(props);
    else result = buildOrgGraph(props);

    const empty = props.mode === 'project' ? (props.graphDeps ?? []).length === 0 :
                  props.mode === 'team' ? (props.projects ?? []).length === 0 :
                  (props.teams ?? []).length === 0 && (props.projects ?? []).length === 0;

    return { initialNodes: result.nodes, initialEdges: result.edges, isEmpty: empty };
  }, [props]);

  const [nodes] = useNodesState(initialNodes);
  const [edges] = useEdgesState(initialEdges);

  const onNodeClick = useCallback((_: any, node: Node) => {
    const d = node.data as any;
    if (d.depId) navigate(`/organizations/${props.organizationId}/projects/${props.projectName ? '' : ''}dependencies/${d.depId}/overview`);
    if (d.projectId) navigate(`/organizations/${props.organizationId}/projects/${d.projectId}/overview`);
    if (d.teamId) navigate(`/organizations/${props.organizationId}/teams/${d.teamId}/overview`);
    if (d.link === 'deps') navigate(`/organizations/${props.organizationId}/projects/${props.projectName ?? ''}/dependencies`);
    if (d.link === 'projects') navigate(`/organizations/${props.organizationId}/teams/${props.teamName ?? ''}/projects`);
  }, [navigate, props.organizationId, props.projectName, props.teamName]);

  /* Canvas matches page bg; card look is for stat strips / panels elsewhere, not the graph pane. */
  return (
    <div ref={containerRef} className="rounded-lg border border-border bg-background overflow-hidden" style={{ height: 300 }}>
      <div className="flex items-center justify-between px-4 pt-3 pb-1">
        <h3 className="text-sm font-semibold text-foreground">Dependency Graph</h3>
        {props.fullGraphLink && (
          <button onClick={() => navigate(props.fullGraphLink!)} className="text-xs text-primary hover:underline">
            View full graph
          </button>
        )}
      </div>

      {isEmpty ? (
        <EmptyGraph mode={props.mode} />
      ) : !visible ? (
        <div className="flex items-center justify-center h-[250px]">
          <Package className="h-8 w-8 text-foreground-secondary/30" />
        </div>
      ) : (
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodeClick={onNodeClick}
          fitView
          fitViewOptions={{ padding: 0.3 }}
          minZoom={0.3}
          maxZoom={1.5}
          proOptions={{ hideAttribution: true }}
          panOnScroll={false}
          zoomOnScroll={false}
          preventScrolling={false}
          nodesDraggable={false}
          nodesConnectable={false}
          className="[&_.react-flow__viewport]:!cursor-default"
        />
      )}
    </div>
  );
}

export function OverviewGraph(props: OverviewGraphProps) {
  return (
    <ReactFlowProvider>
      <OverviewGraphInner {...props} />
    </ReactFlowProvider>
  );
}

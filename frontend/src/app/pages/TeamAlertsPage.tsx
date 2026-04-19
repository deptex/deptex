import { useState, useEffect, useRef } from 'react';
import { useOutletContext, useParams } from 'react-router-dom';
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
import { api, TeamWithRole, TeamPermissions, Project } from '../../lib/api';
import { loadProjectVulnerabilityGraphData } from '../../lib/vulnerability-graph-data';
import { useTeamVulnerabilitiesGraphLayout, type ProjectWithGraphData } from '../../components/vulnerabilities-graph/useTeamVulnerabilitiesGraphLayout';
import { VULN_CENTER_NODE_WIDTH, VULN_CENTER_NODE_HEIGHT } from '../../components/vulnerabilities-graph/useVulnerabilitiesGraphLayout';
import { GroupCenterNode } from '../../components/vulnerabilities-graph/GroupCenterNode';
import { SkeletonGroupCenterNode } from '../../components/vulnerabilities-graph/SkeletonGroupCenterNode';
import { VulnProjectNode } from '../../components/vulnerabilities-graph/VulnProjectNode';
import { ShowOnlyReachableCard } from '../../components/vulnerabilities-graph/ShowOnlyReachableCard';
import { DependencyNode } from '../../components/supply-chain/DependencyNode';
import { VulnerabilityNode } from '../../components/supply-chain/VulnerabilityNode';
import type { NodeTypes } from '@xyflow/react';

interface TeamContextType {
  team: TeamWithRole | null;
  reloadTeam: () => Promise<void>;
  organizationId: string;
  userPermissions: TeamPermissions | null;
}

const nodeTypes: NodeTypes = {
  groupCenterNode: GroupCenterNode,
  vulnProjectNode: VulnProjectNode,
  dependencyNode: DependencyNode,
  vulnerabilityNode: VulnerabilityNode,
};

const skeletonNodeTypes: NodeTypes = {
  skeletonGroupCenterNode: SkeletonGroupCenterNode,
};

const TEAM_SKELETON_CENTER_POS = {
  x: -VULN_CENTER_NODE_WIDTH / 2,
  y: -VULN_CENTER_NODE_HEIGHT / 2,
};

const teamSkeletonNodes = [
  {
    id: 'skeleton-team-center',
    type: 'skeletonGroupCenterNode',
    position: TEAM_SKELETON_CENTER_POS,
    data: {},
  },
];

export default function TeamAlertsPage() {
  const { team, organizationId } = useOutletContext<TeamContextType>();
  const { orgId } = useParams<{ orgId: string }>();
  const org = orgId ?? organizationId;
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectsWithGraphData, setProjectsWithGraphData] = useState<ProjectWithGraphData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showOnlyReachable, setShowOnlyReachable] = useState(false);

  useEffect(() => {
    if (!org || !team?.id) return;

    let cancelled = false;
    setLoading(true);
    setError(null);

    api
      .getProjects(org)
      .then((allProjects) => {
        if (cancelled) return;
        const teamProjects = allProjects.filter((p) => p.team_ids?.includes(team.id));
        setProjects(teamProjects);

        if (teamProjects.length === 0) {
          setProjectsWithGraphData([]);
          setLoading(false);
          return;
        }

        Promise.all(
          teamProjects.map((p) =>
            loadProjectVulnerabilityGraphData(org, p.id).then((result) => ({
              projectId: p.id,
              projectName: p.name,
              graphDepNodes: result.graphDepNodes,
              framework: p.framework,
            }))
          )
        )
          .then((data) => {
            if (!cancelled) setProjectsWithGraphData(data);
          })
          .catch((err) => {
            if (!cancelled) setError(err?.message ?? 'Failed to load vulnerability data');
          })
          .finally(() => {
            if (!cancelled) setLoading(false);
          });
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err?.message ?? 'Failed to load projects');
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [org, team?.id]);

  const { nodes: layoutNodes, edges: layoutEdges } = useTeamVulnerabilitiesGraphLayout(
    team?.name ?? 'Team',
    projectsWithGraphData,
    showOnlyReachable
  );

  const [graphNodes, setGraphNodes, onNodesChange] = useNodesState<Node>([]);
  const [graphEdges, setGraphEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const lastLayoutRef = useRef<string>('');
  const stillShowingSkeleton = loading && projectsWithGraphData.length === 0;

  useEffect(() => {
    const sig = layoutNodes.length + '-' + layoutNodes.map((n) => n.id).join(',');
    if (loading || lastLayoutRef.current === sig) return;
    lastLayoutRef.current = sig;
    setGraphNodes(layoutNodes);
    setGraphEdges(layoutEdges);
  }, [loading, layoutNodes, layoutEdges, setGraphNodes, setGraphEdges]);

  if (!team) {
    return (
      <main className="flex flex-col min-h-[calc(100vh-3rem)] w-full">
        <div className="animate-pulse space-y-6 p-4">
          <div className="h-8 bg-muted rounded w-48" />
          <div className="flex-1 min-h-[400px] bg-muted rounded" />
        </div>
      </main>
    );
  }

  return (
    <main className="relative flex flex-col min-h-[calc(100vh-3rem)] w-full bg-background-content">
      {error && (
        <div className="flex-shrink-0 px-4 pt-3">
          <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-3 text-sm text-destructive">
            {error}
          </div>
        </div>
      )}
      <div className="flex-1 min-h-0 relative">
        <div className="absolute inset-0 overflow-hidden">
          <ReactFlow
            nodes={stillShowingSkeleton ? teamSkeletonNodes : graphNodes}
            edges={stillShowingSkeleton ? [] : graphEdges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={stillShowingSkeleton ? skeletonNodeTypes : nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.3, maxZoom: stillShowingSkeleton ? 1.2 : 1 }}
            minZoom={0.2}
            maxZoom={2}
            proOptions={{ hideAttribution: true }}
            defaultEdgeOptions={{ type: 'smoothstep' }}
            >
              <Background
                variant={BackgroundVariant.Dots}
                gap={16}
                size={1.2}
                color="rgba(148, 163, 184, 0.3)"
              />
            </ReactFlow>
          </div>
          <ShowOnlyReachableCard
            showOnlyReachable={showOnlyReachable}
            onToggle={setShowOnlyReachable}
          />
        </div>
      </main>
    );
  }

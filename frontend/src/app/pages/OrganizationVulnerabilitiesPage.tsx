import { useState, useEffect, useRef } from 'react';
import { useOutletContext } from 'react-router-dom';
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
import { api, Organization, Team, Project } from '../../lib/api';
import { loadProjectVulnerabilityGraphData } from '../../lib/vulnerability-graph-data';
import {
  useOrganizationVulnerabilitiesGraphLayout,
  type TeamWithProjectsData,
} from '../../components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout';
import type { ProjectWithGraphData } from '../../components/vulnerabilities-graph/useTeamVulnerabilitiesGraphLayout';
import { VULN_CENTER_NODE_WIDTH, VULN_CENTER_NODE_HEIGHT } from '../../components/vulnerabilities-graph/useVulnerabilitiesGraphLayout';
import { GroupCenterNode } from '../../components/vulnerabilities-graph/GroupCenterNode';
import { SkeletonGroupCenterNode } from '../../components/vulnerabilities-graph/SkeletonGroupCenterNode';
import { VulnProjectNode } from '../../components/vulnerabilities-graph/VulnProjectNode';
import { ShowOnlyReachableCard } from '../../components/vulnerabilities-graph/ShowOnlyReachableCard';
import { DependencyNode } from '../../components/supply-chain/DependencyNode';
import { VulnerabilityNode } from '../../components/supply-chain/VulnerabilityNode';
import type { NodeTypes } from '@xyflow/react';

interface OrganizationContextType {
  organization: Organization | null;
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

const ORG_SKELETON_CENTER_POS = {
  x: -VULN_CENTER_NODE_WIDTH / 2,
  y: -VULN_CENTER_NODE_HEIGHT / 2,
};

const orgSkeletonNodes = [
  {
    id: 'skeleton-org-center',
    type: 'skeletonGroupCenterNode',
    position: ORG_SKELETON_CENTER_POS,
    data: {},
  },
];

const UNGROUPED_TEAM_ID = 'org-ungrouped';
const UNGROUPED_TEAM_NAME = 'No team';

export default function OrganizationVulnerabilitiesPage() {
  const { organization } = useOutletContext<OrganizationContextType>();
  const [teamsWithProjects, setTeamsWithProjects] = useState<TeamWithProjectsData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showOnlyReachable, setShowOnlyReachable] = useState(false);

  useEffect(() => {
    if (!organization?.id) return;

    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([api.getTeams(organization.id), api.getProjects(organization.id)])
      .then(([teams, allProjects]) => {
        if (cancelled) return;

        const teamIds = new Set(teams.map((t: Team) => t.id));
        const projectsByTeam = new Map<string, Project[]>();
        teamIds.forEach((tid) => projectsByTeam.set(tid, []));
        projectsByTeam.set(UNGROUPED_TEAM_ID, []);

        allProjects.forEach((p: Project) => {
          const displayTeamId: string | null =
            p.owner_team_id ?? (p.team_ids && p.team_ids.length > 0 ? p.team_ids[0] : null);
          const bucket = displayTeamId && teamIds.has(displayTeamId)
            ? displayTeamId
            : UNGROUPED_TEAM_ID;
          projectsByTeam.get(bucket)!.push(p);
        });

        const projectToTeamIds = new Map<string, string[]>();
        const projectMeta = new Map<string, { name: string; framework?: string | null }>();
        const projectIdsToLoad = new Set<string>(allProjects.map((p: Project) => p.id));
        allProjects.forEach((p: Project) => {
          projectMeta.set(p.id, { name: p.name, framework: p.framework });
          const displayTeamId =
            p.owner_team_id ?? (p.team_ids && p.team_ids.length > 0 ? p.team_ids[0] : null);
          const bucket =
            displayTeamId && teamIds.has(displayTeamId) ? displayTeamId : UNGROUPED_TEAM_ID;
          projectToTeamIds.set(p.id, [bucket]);
        });

        const ungroupedProjects = projectsByTeam.get(UNGROUPED_TEAM_ID) ?? [];
        const teamsWithAnyProjects = teams.filter(
          (t: Team) => (projectsByTeam.get(t.id)?.length ?? 0) > 0
        );
        const teamList: Array<{ id: string; name: string }> = [
          ...teamsWithAnyProjects,
          ...(ungroupedProjects.length > 0 ? [{ id: UNGROUPED_TEAM_ID, name: UNGROUPED_TEAM_NAME }] : []),
        ];
        const projectLoads = Array.from(projectIdsToLoad).map((projectId) =>
          loadProjectVulnerabilityGraphData(organization.id, projectId).then((result) => ({
            projectId,
            projectName: projectMeta.get(projectId)?.name ?? 'Project',
            framework: projectMeta.get(projectId)?.framework ?? null,
            graphDepNodes: result.graphDepNodes,
          }))
        );

        return Promise.all(projectLoads).then((projectDataList) => {
          if (cancelled) return;

          const byTeam = new Map<string, ProjectWithGraphData[]>();
          teamList.forEach((t) => byTeam.set(t.id, []));
          projectDataList.forEach((pd) => {
            const teamIds = projectToTeamIds.get(pd.projectId) ?? [];
            teamIds.forEach((teamId) => {
              if (byTeam.has(teamId)) {
                byTeam.get(teamId)!.push(pd);
              }
            });
          });

          const result: TeamWithProjectsData[] = teamList.map((t) => ({
            teamId: t.id,
            teamName: t.name,
            projects: byTeam.get(t.id) ?? [],
          }));

          setTeamsWithProjects(result);
        });
      })
      .catch((err) => {
        if (!cancelled) setError(err?.message ?? 'Failed to load data');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [organization?.id]);

  const { nodes: layoutNodes, edges: layoutEdges } = useOrganizationVulnerabilitiesGraphLayout(
    organization?.name ?? 'Organization',
    teamsWithProjects,
    organization?.avatar_url ?? null,
    showOnlyReachable
  );

  const [graphNodes, setGraphNodes, onNodesChange] = useNodesState<Node>([]);
  const [graphEdges, setGraphEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const lastLayoutRef = useRef<string>('');
  const stillShowingSkeleton = loading && teamsWithProjects.length === 0;

  useEffect(() => {
    const sig = layoutNodes.length + '-' + layoutNodes.map((n) => n.id).join(',');
    if (loading || lastLayoutRef.current === sig) return;
    lastLayoutRef.current = sig;
    setGraphNodes(layoutNodes);
    setGraphEdges(layoutEdges);
  }, [loading, layoutNodes, layoutEdges, setGraphNodes, setGraphEdges]);

  if (!organization) {
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
            nodes={stillShowingSkeleton ? orgSkeletonNodes : graphNodes}
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

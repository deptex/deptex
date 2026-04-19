import { useMemo } from 'react';
import { type Node, type Edge, MarkerType } from '@xyflow/react';
import { buildDepAndVulnNodesAndEdges, getWorstSeverity } from './useVulnerabilitiesGraphLayout';
import type { VulnGraphDepNode, WorstSeverity } from './useVulnerabilitiesGraphLayout';
import { getSlaBreachCount } from './useVulnerabilitiesGraphLayout';
import { OVERVIEW_PROJECT_NODE_WIDTH, OVERVIEW_PROJECT_NODE_HEIGHT, VULN_PROJECT_NODE_WIDTH, VULN_PROJECT_NODE_HEIGHT } from './VulnProjectNode';

export const TEAM_CENTER_ID = 'team-center';

export interface TeamCenterOptions {
  memberCount?: number;
  roleBadge?: string | null;
  roleBadgeColor?: string | null;
}

export interface ProjectWithGraphData {
  projectId: string;
  projectName: string;
  graphDepNodes: VulnGraphDepNode[];
  framework?: string | null;
  worstSeverity?: WorstSeverity;
  /** When true, show only project node with extracting spinner (no dependencies/vulnerabilities). */
  isExtracting?: boolean;
  /** Org-overview-style card: status badge. */
  statusName?: string | null;
  statusColor?: string | null;
  /** Org-overview-style card: asset tier. */
  assetTierName?: string | null;
  assetTierColor?: string | null;
  /** Org-overview-style card: dependency count in bottom bar. */
  dependenciesCount?: number | null;
}

function getHandlePair(angle: number): { sourceHandle: string; targetHandle: string } {
  const a = ((angle % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
  if (a < Math.PI / 4 || a >= (7 * Math.PI) / 4) return { sourceHandle: 'right', targetHandle: 'left' };
  if (a < (3 * Math.PI) / 4) return { sourceHandle: 'bottom', targetHandle: 'top' };
  if (a < (5 * Math.PI) / 4) return { sourceHandle: 'left', targetHandle: 'right' };
  return { sourceHandle: 'top', targetHandle: 'bottom' };
}

/**
 * Builds nodes and edges for team vulnerabilities graph:
 * Team (center) --gray--> Projects (ring) --per-project--> deps/vulns (namespaced, translated).
 * Center and project nodes use org-overview-style cards (VulnProjectNode with neutralStyle) when possible.
 */
export function useTeamVulnerabilitiesGraphLayout(
  teamName: string,
  projectsWithGraphData: ProjectWithGraphData[],
  showOnlyReachable = false,
  teamCenterOptions?: TeamCenterOptions
): { nodes: Node[]; edges: Edge[] } {
  return useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const centerX = 0;
    const centerY = 0;

    // Team center: styled like org overview team cards (VulnProjectNode with isTeamNode + neutralStyle)
    nodes.push({
      id: TEAM_CENTER_ID,
      type: 'vulnProjectNode',
      position: {
        x: centerX - OVERVIEW_PROJECT_NODE_WIDTH / 2,
        y: centerY - OVERVIEW_PROJECT_NODE_HEIGHT / 2,
      },
      data: {
        projectName: teamName,
        projectId: '', // avoid navigate on click
        isTeamNode: true,
        neutralStyle: true,
        roleBadge: teamCenterOptions?.roleBadge ?? undefined,
        roleBadgeColor: teamCenterOptions?.roleBadgeColor ?? undefined,
        riskGrade: 'A+',
        projectsCount: projectsWithGraphData.length,
        membersCount: teamCenterOptions?.memberCount ?? undefined,
      },
      draggable: true,
      selectable: false,
    });

    if (projectsWithGraphData.length === 0) {
      return { nodes, edges };
    }

    const goldenAngle = Math.PI * (3 - Math.sqrt(5));
    const projectRingRadius = Math.max(1400, 1000 + projectsWithGraphData.length * 120);

    const grayStroke = 'rgba(100, 116, 139, 0.4)';

    projectsWithGraphData.forEach((proj, i) => {
      const angle = i * goldenAngle;
      const projectNodeId = `project-${proj.projectId}`;

      // Use overview card dimensions so project nodes match org overview style
      const px = centerX + Math.cos(angle) * projectRingRadius - OVERVIEW_PROJECT_NODE_WIDTH / 2;
      const py = centerY + Math.sin(angle) * projectRingRadius - OVERVIEW_PROJECT_NODE_HEIGHT / 2;

      const worstSeverity = proj.worstSeverity ?? getWorstSeverity(proj.graphDepNodes);
      const slaBreachCount = getSlaBreachCount(proj.graphDepNodes);
      const isExtracting = proj.isExtracting === true;

      nodes.push({
        id: projectNodeId,
        type: 'vulnProjectNode',
        position: { x: px, y: py },
        data: {
          projectName: proj.projectName,
          projectId: proj.projectId,
          framework: proj.framework,
          worstSeverity,
          slaBreachCount,
          isExtracting,
          neutralStyle: true,
          statusBadge: proj.statusName ?? undefined,
          statusBadgeColor: proj.statusColor ?? undefined,
          assetTierName: proj.assetTierName ?? undefined,
          assetTierColor: proj.assetTierColor ?? undefined,
          riskGrade: 'A+',
          dependenciesCount: proj.dependenciesCount ?? undefined,
        },
        draggable: true,
        selectable: false,
      });

      // Team center is VulnProjectNode: source handles are "source-right", "source-left", etc.
      const { sourceHandle, targetHandle } = getHandlePair(angle);
      edges.push({
        id: `edge-team-${projectNodeId}`,
        source: TEAM_CENTER_ID,
        target: projectNodeId,
        sourceHandle: 'source-' + sourceHandle,
        targetHandle,
        type: 'default',
        style: { stroke: grayStroke, strokeWidth: 1.2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: grayStroke, width: 12, height: 12 },
      });

      // When extracting, do not show dependencies or vulnerabilities (match Project Security tab).
      if (isExtracting || proj.graphDepNodes.length === 0) return;

      const prefix = `project-${proj.projectId}-`;
      const namespacedDepNodes: VulnGraphDepNode[] = proj.graphDepNodes.map((d) => ({
        ...d,
        id: prefix + d.id,
        parentId: d.parentId === 'project' ? projectNodeId : prefix + d.parentId,
      }));

      const sub = buildDepAndVulnNodesAndEdges(projectNodeId, namespacedDepNodes, showOnlyReachable);

      const offsetX = centerX + Math.cos(angle) * projectRingRadius;
      const offsetY = centerY + Math.sin(angle) * projectRingRadius;

      sub.nodes.forEach((n) => {
        const pos = n.position;
        nodes.push({
          ...n,
          position: {
            x: (typeof pos.x === 'number' ? pos.x : 0) + offsetX,
            y: (typeof pos.y === 'number' ? pos.y : 0) + offsetY,
          },
        } as Node);
      });

      // buildDepAndVulnNodesAndEdges already uses sourceHandle like "source-right"; do not double-prefix
      sub.edges.forEach((e) => {
        const edge: Edge = { ...e, id: prefix + e.id } as Edge;
        if (e.source === projectNodeId && e.sourceHandle && !e.sourceHandle.startsWith('source-')) {
          edge.sourceHandle = 'source-' + e.sourceHandle;
        }
        edges.push(edge);
      });
    });

    return { nodes, edges };
  }, [teamName, projectsWithGraphData, showOnlyReachable, teamCenterOptions]);
}

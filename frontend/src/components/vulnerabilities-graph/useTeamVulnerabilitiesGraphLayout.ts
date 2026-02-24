import { useMemo } from 'react';
import { type Node, type Edge, MarkerType } from '@xyflow/react';
import { buildDepAndVulnNodesAndEdges, getWorstSeverity } from './useVulnerabilitiesGraphLayout';
import type { VulnGraphDepNode, WorstSeverity } from './useVulnerabilitiesGraphLayout';
import { VULN_CENTER_NODE_WIDTH, VULN_CENTER_NODE_HEIGHT } from './useVulnerabilitiesGraphLayout';
import { VULN_PROJECT_NODE_WIDTH, VULN_PROJECT_NODE_HEIGHT } from './VulnProjectNode';

export const TEAM_CENTER_ID = 'team-center';

export interface ProjectWithGraphData {
  projectId: string;
  projectName: string;
  graphDepNodes: VulnGraphDepNode[];
  framework?: string | null;
  worstSeverity?: WorstSeverity;
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
 */
export function useTeamVulnerabilitiesGraphLayout(
  teamName: string,
  projectsWithGraphData: ProjectWithGraphData[],
  showOnlyReachable = false
): { nodes: Node[]; edges: Edge[] } {
  return useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const centerX = 0;
    const centerY = 0;

    const allDepNodes = projectsWithGraphData.flatMap((p) => p.graphDepNodes);
    const teamIsHealthy = allDepNodes.length === 0 || getWorstSeverity(allDepNodes) === 'none';

    // Team center at (0, 0)
    nodes.push({
      id: TEAM_CENTER_ID,
      type: 'groupCenterNode',
      position: {
        x: centerX - VULN_CENTER_NODE_WIDTH / 2,
        y: centerY - VULN_CENTER_NODE_HEIGHT / 2,
      },
      data: {
        title: teamName,
        subtitle: `${projectsWithGraphData.length} project${projectsWithGraphData.length === 1 ? '' : 's'}`,
        isHealthy: teamIsHealthy,
        kind: 'team',
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

      const px = centerX + Math.cos(angle) * projectRingRadius - VULN_PROJECT_NODE_WIDTH / 2;
      const py = centerY + Math.sin(angle) * projectRingRadius - VULN_PROJECT_NODE_HEIGHT / 2;

      const worstSeverity = proj.worstSeverity ?? getWorstSeverity(proj.graphDepNodes);

      nodes.push({
        id: projectNodeId,
        type: 'vulnProjectNode',
        position: { x: px, y: py },
        data: {
          projectName: proj.projectName,
          projectId: proj.projectId,
          framework: proj.framework,
          worstSeverity,
        },
        draggable: true,
        selectable: false,
      });

      // Use the same angle for both the team (source) and project (target) handles
      // so the edge always connects on the side of each node that faces the other.
      const { sourceHandle, targetHandle } = getHandlePair(angle);
      edges.push({
        id: `edge-team-${projectNodeId}`,
        source: TEAM_CENTER_ID,
        target: projectNodeId,
        sourceHandle,
        targetHandle,
        type: 'default',
        style: { stroke: grayStroke, strokeWidth: 1.2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: grayStroke, width: 12, height: 12 },
      });

      if (proj.graphDepNodes.length === 0) return;

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

      sub.edges.forEach((e) => {
        const edge: Edge = { ...e, id: prefix + e.id } as Edge;
        if (e.source === projectNodeId && e.sourceHandle) {
          edge.sourceHandle = 'source-' + e.sourceHandle;
        }
        edges.push(edge);
      });
    });

    return { nodes, edges };
  }, [teamName, projectsWithGraphData, showOnlyReachable]);
}

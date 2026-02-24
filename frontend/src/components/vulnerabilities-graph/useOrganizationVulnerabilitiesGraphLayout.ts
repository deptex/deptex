import { useMemo } from 'react';
import { type Node, type Edge, MarkerType } from '@xyflow/react';
import { buildDepAndVulnNodesAndEdges, getWorstSeverity } from './useVulnerabilitiesGraphLayout';
import type { VulnGraphDepNode, WorstSeverity } from './useVulnerabilitiesGraphLayout';
import { VULN_CENTER_NODE_WIDTH, VULN_CENTER_NODE_HEIGHT } from './useVulnerabilitiesGraphLayout';
import { VULN_PROJECT_NODE_WIDTH, VULN_PROJECT_NODE_HEIGHT } from './VulnProjectNode';
import type { ProjectWithGraphData } from './useTeamVulnerabilitiesGraphLayout';

export const ORG_CENTER_ID = 'org-center';
/** Synthetic team id for projects with no owner_team_id and no team_ids (display team = org). */
export const UNGROUPED_TEAM_ID = 'org-ungrouped';

export interface TeamWithProjectsData {
  teamId: string;
  teamName: string;
  projects: (ProjectWithGraphData & { worstSeverity?: WorstSeverity })[];
}

function getHandlePair(angle: number): { sourceHandle: string; targetHandle: string } {
  const a = ((angle % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
  if (a < Math.PI / 4 || a >= (7 * Math.PI) / 4) return { sourceHandle: 'right', targetHandle: 'left' };
  if (a < (3 * Math.PI) / 4) return { sourceHandle: 'bottom', targetHandle: 'top' };
  if (a < (5 * Math.PI) / 4) return { sourceHandle: 'left', targetHandle: 'right' };
  return { sourceHandle: 'top', targetHandle: 'bottom' };
}

/**
 * Builds nodes and edges for org vulnerabilities graph:
 * Org (center) --gray--> Teams (ring) --gray--> Projects (ring per team) --per-project--> deps/vulns.
 */
export function useOrganizationVulnerabilitiesGraphLayout(
  orgName: string,
  teamsWithProjects: TeamWithProjectsData[],
  orgAvatarUrl?: string | null,
  showOnlyReachable = false
): { nodes: Node[]; edges: Edge[] } {
  return useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const centerX = 0;
    const centerY = 0;

    const grayStroke = 'rgba(100, 116, 139, 0.4)';

    const allDepNodes: VulnGraphDepNode[] = teamsWithProjects.flatMap((team) =>
      team.projects.flatMap((p) => p.graphDepNodes)
    );
    const orgIsHealthy = allDepNodes.length === 0 || getWorstSeverity(allDepNodes) === 'none';

    nodes.push({
      id: ORG_CENTER_ID,
      type: 'groupCenterNode',
      position: {
        x: centerX - VULN_CENTER_NODE_WIDTH / 2,
        y: centerY - VULN_CENTER_NODE_HEIGHT / 2,
      },
      data: {
        title: orgName,
        subtitle: `${teamsWithProjects.length} team${teamsWithProjects.length === 1 ? '' : 's'}`,
        avatarUrl: orgAvatarUrl,
        isHealthy: orgIsHealthy,
        kind: 'org',
      },
      draggable: true,
      selectable: false,
    });

    if (teamsWithProjects.length === 0) return { nodes, edges };

    const goldenAngle = Math.PI * (3 - Math.sqrt(5));
    const teamRingRadius = Math.max(900, 700 + teamsWithProjects.length * 100);

    teamsWithProjects.forEach((teamData, teamIdx) => {
      const teamAngle = teamIdx * goldenAngle;
      const teamNodeId = `team-${teamData.teamId}`;
      const tx = centerX + Math.cos(teamAngle) * teamRingRadius;
      const ty = centerY + Math.sin(teamAngle) * teamRingRadius;

      const teamWorstSeverity = getWorstSeverity(
        teamData.projects.flatMap((p) => p.graphDepNodes)
      );

      nodes.push({
        id: teamNodeId,
        type: 'vulnProjectNode',
        position: {
          x: tx - VULN_PROJECT_NODE_WIDTH / 2,
          y: ty - VULN_PROJECT_NODE_HEIGHT / 2,
        },
        data: {
          projectName: teamData.teamName,
          projectId: teamData.teamId,
          worstSeverity: teamWorstSeverity,
          isTeamNode: true,
        },
        draggable: true,
        selectable: false,
      });

      const { sourceHandle, targetHandle } = getHandlePair(teamAngle);
      edges.push({
        id: `edge-org-${teamNodeId}`,
        source: ORG_CENTER_ID,
        target: teamNodeId,
        sourceHandle,
        targetHandle,
        type: 'default',
        style: { stroke: grayStroke, strokeWidth: 1.2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: grayStroke, width: 12, height: 12 },
      });

      const projectRingRadius = Math.max(500, 400 + teamData.projects.length * 80);

      teamData.projects.forEach((proj, projIdx) => {
        const projAngle = projIdx * goldenAngle;
        const projectNodeId = `project-${proj.projectId}`;
        const px = tx + Math.cos(projAngle) * projectRingRadius;
        const py = ty + Math.sin(projAngle) * projectRingRadius;

        const projectWorstSeverity = proj.worstSeverity ?? getWorstSeverity(proj.graphDepNodes);

        nodes.push({
          id: projectNodeId,
          type: 'vulnProjectNode',
          position: {
            x: px - VULN_PROJECT_NODE_WIDTH / 2,
            y: py - VULN_PROJECT_NODE_HEIGHT / 2,
          },
          data: {
            projectName: proj.projectName,
            projectId: proj.projectId,
            framework: proj.framework ?? undefined,
            worstSeverity: projectWorstSeverity,
          },
          draggable: true,
          selectable: false,
        });

        // Use the same angle for both the team (source) and project (target) handles
        // so the edge connects on the sides of each node that face one another.
        const { sourceHandle: teamSourceHandle, targetHandle: teamTargetHandle } = getHandlePair(projAngle);
        edges.push({
          id: `edge-${teamNodeId}-${projectNodeId}`,
          source: teamNodeId,
          target: projectNodeId,
          sourceHandle: 'source-' + teamSourceHandle,
          targetHandle: teamTargetHandle,
          type: 'default',
          style: { stroke: grayStroke, strokeWidth: 1.2 },
          markerEnd: { type: MarkerType.ArrowClosed, color: grayStroke, width: 12, height: 12 },
        });

        if (teamData.teamId === UNGROUPED_TEAM_ID) {
          const { sourceHandle: orgSourceHandle, targetHandle: orgTargetHandle } = getHandlePair(projAngle);
          edges.push({
            id: `edge-org-direct-${projectNodeId}`,
            source: ORG_CENTER_ID,
            target: projectNodeId,
            sourceHandle: orgSourceHandle,
            targetHandle: orgTargetHandle,
            type: 'default',
            style: { stroke: grayStroke, strokeWidth: 1.2 },
            markerEnd: { type: MarkerType.ArrowClosed, color: grayStroke, width: 12, height: 12 },
          });
        }

        if (proj.graphDepNodes.length === 0) return;

        const prefix = `project-${proj.projectId}-`;
        const namespacedDepNodes: VulnGraphDepNode[] = proj.graphDepNodes.map((d) => ({
          ...d,
          id: prefix + d.id,
          parentId: d.parentId === 'project' ? projectNodeId : prefix + d.parentId,
        }));

        const sub = buildDepAndVulnNodesAndEdges(projectNodeId, namespacedDepNodes, showOnlyReachable);

        sub.nodes.forEach((n) => {
          const pos = n.position;
          nodes.push({
            ...n,
            position: {
              x: (typeof pos.x === 'number' ? pos.x : 0) + px,
              y: (typeof pos.y === 'number' ? pos.y : 0) + py,
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
    });

    return { nodes, edges };
  }, [orgName, teamsWithProjects, showOnlyReachable]);
}

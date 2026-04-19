import { useMemo } from 'react';
import { type Node, type Edge, MarkerType } from '@xyflow/react';
import { buildDepAndVulnNodesAndEdges, getWorstSeverity, getWorstDepscore } from './useVulnerabilitiesGraphLayout';
import type { VulnGraphDepNode, WorstSeverity } from './useVulnerabilitiesGraphLayout';
import { VULN_CENTER_NODE_WIDTH, VULN_CENTER_NODE_HEIGHT, getSlaBreachCount } from './useVulnerabilitiesGraphLayout';
import { VULN_PROJECT_NODE_WIDTH, VULN_PROJECT_NODE_HEIGHT, OVERVIEW_PROJECT_NODE_WIDTH, OVERVIEW_PROJECT_NODE_HEIGHT } from './VulnProjectNode';
import {
  TEAM_CONTAINER_MIN_WIDTH,
  TEAM_CONTAINER_MIN_HEIGHT,
  TEAM_CONTAINER_PADDING,
  TEAM_CONTAINER_HEADER_HEIGHT,
  TEAM_CONTAINER_GRID_GAP,
  TEAM_CONTAINER_FOOTER_HEIGHT,
} from './TeamGroupNode';
import type { ProjectWithGraphData } from './useTeamVulnerabilitiesGraphLayout';
import type { OverviewStatusRollup } from '../../lib/overviewStatusRollup';
import {
  layoutOverviewSatellitesAroundOrg,
  getOrgToSatelliteHandles,
  computeOrgOverviewEdgeRouting,
  ORG_OVERVIEW_EDGE_STROKE,
  ORG_OVERVIEW_CENTER_WIDTH,
  ORG_OVERVIEW_CENTER_HEIGHT,
} from './overviewOrgLayout';

export const ORG_CENTER_ID = 'org-center';
/** @deprecated Synthetic team id for ungrouped projects. Phase 6 places these directly at team ring level. */
export const UNGROUPED_TEAM_ID = 'org-ungrouped';

export interface TeamWithProjectsData {
  teamId: string;
  teamName: string;
  projects: (ProjectWithGraphData & { worstSeverity?: WorstSeverity })[];
}

/** Projects not assigned to any team; rendered at the same ring as team nodes. */
export interface UngroupedProject extends ProjectWithGraphData {
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
 * Builds nodes and edges for org vulnerabilities graph:
 * Org (center) --gray--> Teams (ring) --gray--> Projects (ring per team) --per-project--> deps/vulns.
 */
export function useOrganizationVulnerabilitiesGraphLayout(
  orgName: string,
  teamsWithProjects: TeamWithProjectsData[],
  orgAvatarUrl?: string | null,
  showOnlyReachable = false,
  ungroupedProjects?: UngroupedProject[]
): { nodes: Node[]; edges: Edge[] } {
  return useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const centerX = 0;
    const centerY = 0;

    const grayStroke = '#262626';

    const realTeams = teamsWithProjects.filter(t => t.teamId !== UNGROUPED_TEAM_ID);
    const ungrouped = ungroupedProjects ?? teamsWithProjects
      .filter(t => t.teamId === UNGROUPED_TEAM_ID)
      .flatMap(t => t.projects);

    const allDepNodes: VulnGraphDepNode[] = [
      ...realTeams.flatMap((team) => team.projects.flatMap((p) => p.graphDepNodes)),
      ...ungrouped.flatMap((p) => p.graphDepNodes),
    ];
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
      draggable: false,
      selectable: false,
    });

    const totalRingItems = realTeams.length + ungrouped.length;
    if (totalRingItems === 0) return { nodes, edges };

    const goldenAngle = Math.PI * (3 - Math.sqrt(5));
    const teamRingRadius = Math.max(900, 700 + totalRingItems * 100);

    let ringIdx = 0;

    // Place ungrouped projects directly at team ring level (no "No Team" intermediary)
    ungrouped.forEach((proj) => {
      const angle = ringIdx * goldenAngle;
      ringIdx++;
      const projectNodeId = `project-${proj.projectId}`;
      const px = centerX + Math.cos(angle) * teamRingRadius;
      const py = centerY + Math.sin(angle) * teamRingRadius;
      const projectWorstSeverity = proj.worstSeverity ?? getWorstSeverity(proj.graphDepNodes);
      const slaBreachCount = getSlaBreachCount(proj.graphDepNodes);
      const isExtracting = proj.isExtracting === true;

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
          slaBreachCount,
          isExtracting,
        },
        draggable: false,
        selectable: false,
      });

      const { sourceHandle, targetHandle } = getHandlePair(angle);
      edges.push({
        id: `edge-org-${projectNodeId}`,
        source: ORG_CENTER_ID,
        target: projectNodeId,
        sourceHandle,
        targetHandle,
        type: 'step',
        style: { stroke: grayStroke, strokeWidth: 1.2, strokeDasharray: '5 5' },
        markerEnd: { type: MarkerType.ArrowClosed, color: grayStroke, width: 12, height: 12 },
      });

      if (isExtracting || proj.graphDepNodes.length === 0) return;

      const prefix = `project-${proj.projectId}-`;
      const namespacedDepNodes: VulnGraphDepNode[] = proj.graphDepNodes.map((d) => ({
        ...d,
        id: prefix + d.id,
        parentId: d.parentId === 'project' ? projectNodeId : prefix + d.parentId,
      }));
      const sub = buildDepAndVulnNodesAndEdges(projectNodeId, namespacedDepNodes, showOnlyReachable);
      sub.nodes.forEach((n) => {
        nodes.push({ ...n, position: { x: (n.position.x ?? 0) + px, y: (n.position.y ?? 0) + py } } as Node);
      });
      sub.edges.forEach((e) => {
        const edge: Edge = { ...e, id: prefix + e.id } as Edge;
        if (e.source === projectNodeId && e.sourceHandle) edge.sourceHandle = 'source-' + e.sourceHandle;
        edges.push(edge);
      });
    });

    realTeams.forEach((teamData) => {
      const teamAngle = ringIdx * goldenAngle;
      ringIdx++;
      const teamNodeId = `team-${teamData.teamId}`;
      const tx = centerX + Math.cos(teamAngle) * teamRingRadius;
      const ty = centerY + Math.sin(teamAngle) * teamRingRadius;

      const hasExtractingProjects = teamData.projects.some((p) => p.isExtracting === true);
      const teamWorstSeverity = getWorstSeverity(
        teamData.projects.filter((p) => !p.isExtracting).flatMap((p) => p.graphDepNodes)
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
          hasExtractingProjects,
        },
        draggable: false,
        selectable: false,
      });

      const { sourceHandle, targetHandle } = getHandlePair(teamAngle);
      edges.push({
        id: `edge-org-${teamNodeId}`,
        source: ORG_CENTER_ID,
        target: teamNodeId,
        sourceHandle,
        targetHandle,
        type: 'step',
        style: { stroke: grayStroke, strokeWidth: 1.2, strokeDasharray: '5 5' },
        markerEnd: { type: MarkerType.ArrowClosed, color: grayStroke, width: 12, height: 12 },
      });

      const projectRingRadius = Math.max(500, 400 + teamData.projects.length * 80);

      teamData.projects.forEach((proj, projIdx) => {
        const projAngle = projIdx * goldenAngle;
        const projectNodeId = `project-${proj.projectId}`;
        const px = tx + Math.cos(projAngle) * projectRingRadius;
        const py = ty + Math.sin(projAngle) * projectRingRadius;

        const projectWorstSeverity = proj.worstSeverity ?? getWorstSeverity(proj.graphDepNodes);
        const slaBreachCount = getSlaBreachCount(proj.graphDepNodes);
        const isExtracting = proj.isExtracting === true;

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
            slaBreachCount,
            isExtracting,
          },
          draggable: false,
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
          type: 'step',
          style: { stroke: grayStroke, strokeWidth: 1.2, strokeDasharray: '5 5' },
          markerEnd: { type: MarkerType.ArrowClosed, color: grayStroke, width: 12, height: 12 },
        });

        if (isExtracting || proj.graphDepNodes.length === 0) return;

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
  }, [orgName, teamsWithProjects, showOnlyReachable, ungroupedProjects]);
}

/** Minimal project shape for org overview (no dependency/vuln data). */
export interface OverviewProjectItem {
  projectId: string;
  projectName: string;
  framework?: string | null;
  /** Project status for badge (e.g. Compliant, Non-Compliant). */
  statusName?: string | null;
  statusColor?: string | null;
  /** Status id for filtering (organization_statuses.id). */
  statusId?: string | null;
  /** Asset tier name shown in badge on project card (e.g. Crown Jewels, External). */
  assetTierName?: string | null;
  /** Hex color for asset tier badge (from organization_asset_tiers). */
  assetTierColor?: string | null;
  /** When true, same overview card as other projects with an Extracting + spinner badge; click opens sync sidebar. */
  isExtracting?: boolean;
  /** Project health score 0–100 when available (for org center aggregate). */
  healthScore?: number | null;
  /** Number of direct dependencies shown as subtext on project card. */
  dependenciesCount?: number | null;
}

export interface OverviewTeamWithProjects {
  teamId: string;
  teamName: string;
  /** User's role in this team (e.g. Owner, Member) for badge. */
  userRoleLabel?: string | null;
  /** Hex color for user's role badge (e.g. from team.role_color). */
  userRoleColor?: string | null;
  projects: OverviewProjectItem[];
  /** Number of projects (for team node bottom bar). */
  projectCount?: number;
  /** Number of members (for team node bottom bar). */
  memberCount?: number;
}

/** Match OrganizationSwitcher / RoleBadge defaults when API has no role_color */
const OVERVIEW_DEFAULT_ROLE_COLORS: Record<string, string> = {
  owner: '#3b82f6',
  admin: '#14b8a6',
  member: '#71717a',
};

/** When a team has more than this many projects, the org overview grid shows only this many until expanded. */
export const OVERVIEW_TEAM_PROJECTS_COLLAPSE_AT = 4;

/**
 * Project grid inside a team card: column count grows with √(n) so the container widens predictably.
 * Examples: 2 → 1×2, 3 → 2+1, 4 → 2×2, 5–6 → 3-wide rows, 7–9 → 3 cols, 10+ → 4+ cols as needed.
 */
function getOverviewTeamProjectGridDimensions(projectCount: number): { cols: number; rows: number } {
  const n = Math.max(0, projectCount);
  if (n === 0) return { cols: 1, rows: 1 };
  const cols = Math.max(1, Math.ceil(Math.sqrt(n)));
  const rows = Math.max(1, Math.ceil(n / cols));
  return { cols, rows };
}

interface OverviewOrgGridCell {
  globalIndex: number;
  width: number;
  height: number;
  teamData: OverviewTeamWithProjects | null;
  ungroupedProject: OverviewProjectItem | null;
  teamInner?: {
    cols: number;
    rows: number;
    projectWidth: number;
    projectHeight: number;
    gap: number;
    projectGridTopInset: number;
    projectGridBottomInset: number;
    visibleProjectCount: number;
    totalProjectCount: number;
    collapsedSummary: boolean;
  };
}

/**
 * Builds nodes and edges for org overview only: org center, teams, projects. No dependency/vuln nodes.
 * All nodes use neutral styling. Team containers size to their project grid (tight hug).
 */
export function useOrganizationOverviewGraphLayout(
  orgName: string,
  teamsWithProjects: OverviewTeamWithProjects[],
  orgAvatarUrl: string | null | undefined,
  orgRoleLabel?: string | null,
  orgRoleColor?: string | null,
  organizationId?: string | null,
  /** Raw role name (owner/admin/member) for RoleBadge color fallback — same as OrganizationSwitcher */
  orgRole?: string | null,
  orgStatusRollup?: OverviewStatusRollup | null,
  teamStatusRollups?: Record<string, OverviewStatusRollup> | null,
  orgPlan?: string | null
): { nodes: Node[]; edges: Edge[] } {
  return useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const centerX = 0;
    const centerY = 0;

    const realTeams = teamsWithProjects.filter((t) => t.teamId !== UNGROUPED_TEAM_ID);
    const ungrouped = teamsWithProjects
      .filter((t) => t.teamId === UNGROUPED_TEAM_ID)
      .flatMap((t) => t.projects);

    const resolvedRoleColor =
      orgRoleColor && orgRoleColor.trim() !== ''
        ? orgRoleColor
        : orgRole && OVERVIEW_DEFAULT_ROLE_COLORS[orgRole]
          ? OVERVIEW_DEFAULT_ROLE_COLORS[orgRole]
          : OVERVIEW_DEFAULT_ROLE_COLORS.member;

    // Aggregate health score across all projects (0–100) for org center line "Risk score: N/100"
    const allOverviewProjects = teamsWithProjects.flatMap((t) => t.projects);
    const healthScores = allOverviewProjects
      .map((p) => p.healthScore)
      .filter((n): n is number => typeof n === 'number' && !Number.isNaN(n));
    const organizationRiskScore =
      healthScores.length > 0
        ? Math.round(healthScores.reduce((a, b) => a + b, 0) / healthScores.length)
        : null;

    const totalProjectCount = allOverviewProjects.length;
    const totalMemberCount = teamsWithProjects.reduce((sum, t) => sum + (t.memberCount ?? 0), 0);

    const orgCenterData = {
      title: orgName,
      avatarUrl: orgAvatarUrl,
      kind: 'org' as const,
      roleBadge: orgRoleLabel ?? undefined,
      roleBadgeColor: resolvedRoleColor,
      organizationRole: orgRole ?? undefined,
      organizationRiskScore,
      projectCount: totalProjectCount,
      teamCount: realTeams.length,
      memberCount: totalMemberCount,
      plan: orgPlan ?? undefined,
      ...(orgStatusRollup
        ? {
            overviewStatusBadgeLabel: orgStatusRollup.badgeLabel,
            overviewStatusBadgeColor: orgStatusRollup.badgeColor,
            overviewStatusTooltip: orgStatusRollup.tooltipText,
          }
        : {}),
    };

    nodes.push({
      id: ORG_CENTER_ID,
      type: 'groupCenterNode',
      position: {
        x: centerX - ORG_OVERVIEW_CENTER_WIDTH / 2,
        y: centerY - ORG_OVERVIEW_CENTER_HEIGHT / 2,
      },
      data: orgCenterData,
      draggable: false,
      selectable: false,
      style: { zIndex: 3, width: ORG_OVERVIEW_CENTER_WIDTH, height: ORG_OVERVIEW_CENTER_HEIGHT },
    });

    const totalRingItems = realTeams.length + ungrouped.length;
    if (totalRingItems === 0) return { nodes, edges };

    const overviewEdgeStyle = {
      stroke: ORG_OVERVIEW_EDGE_STROKE,
      strokeWidth: 1,
      strokeDasharray: '5 5',
    };

    const projectWidth = OVERVIEW_PROJECT_NODE_WIDTH;
    const projectHeight = OVERVIEW_PROJECT_NODE_HEIGHT;
    const innerGap = TEAM_CONTAINER_GRID_GAP;
    const projectGridTopInset = 6;
    const projectGridBottomInset = 8;

    const gridCells: OverviewOrgGridCell[] = [];

    const COLLAPSED_SUMMARY_BODY_PX = 32;

    realTeams.forEach((teamData, teamIndex) => {
      const totalProjects = teamData.projects.length;
      /** Org overview always uses compact team cards (project count + members; no in-card project grid). */
      const collapsedSummary = true;

      let visibleCount: number;
      let cols: number;
      let rows: number;
      let containerWidth: number;
      let containerHeight: number;

      if (collapsedSummary) {
        visibleCount = 0;
        cols = 0;
        rows = 0;
        containerWidth = 270;
        containerHeight = 118;
      } else {
        visibleCount = totalProjects;
        const dim = getOverviewTeamProjectGridDimensions(visibleCount);
        cols = dim.cols;
        rows = dim.rows;
        containerWidth = Math.max(
          TEAM_CONTAINER_MIN_WIDTH,
          cols * projectWidth + Math.max(0, cols - 1) * innerGap + TEAM_CONTAINER_PADDING * 2
        );
        containerHeight = Math.max(
          TEAM_CONTAINER_MIN_HEIGHT,
          TEAM_CONTAINER_HEADER_HEIGHT +
            projectGridTopInset +
            rows * projectHeight +
            Math.max(0, rows - 1) * innerGap +
            projectGridBottomInset +
            TEAM_CONTAINER_FOOTER_HEIGHT
        );
      }

      gridCells.push({
        globalIndex: teamIndex,
        width: containerWidth,
        height: containerHeight,
        teamData,
        ungroupedProject: null,
        teamInner: {
          cols,
          rows,
          projectWidth,
          projectHeight,
          gap: innerGap,
          projectGridTopInset,
          projectGridBottomInset,
          visibleProjectCount: visibleCount,
          totalProjectCount: totalProjects,
          collapsedSummary,
        },
      });
    });

    ungrouped.forEach((proj, ungroupedIdx) => {
      const globalIndex = realTeams.length + ungroupedIdx;
      gridCells.push({
        globalIndex,
        width: OVERVIEW_PROJECT_NODE_WIDTH,
        height: OVERVIEW_PROJECT_NODE_HEIGHT,
        teamData: null,
        ungroupedProject: proj,
      });
    });

    const layoutInputs = gridCells.map((c) => ({
      globalIndex: c.globalIndex,
      width: c.width,
      height: c.height,
    }));
    const gridPositions = layoutOverviewSatellitesAroundOrg(layoutInputs);

    const orgLinkItems: Array<{ targetId: string; cx: number; cy: number }> = [];
    for (const cell of gridCells) {
      const pos = gridPositions.get(cell.globalIndex);
      if (!pos) continue;
      const cx = pos.x + cell.width / 2;
      const cy = pos.y + cell.height / 2;
      if (cell.teamData && cell.teamInner) {
        orgLinkItems.push({ targetId: `team-${cell.teamData.teamId}`, cx, cy });
      } else if (cell.ungroupedProject) {
        orgLinkItems.push({ targetId: `project-${cell.ungroupedProject.projectId}`, cx, cy });
      }
    }
    const orgEdgeRouting = computeOrgOverviewEdgeRouting(orgLinkItems);

    gridCells
      .sort((a, b) => a.globalIndex - b.globalIndex)
      .forEach((cell) => {
        const pos = gridPositions.get(cell.globalIndex);
        if (!pos) return;
        const cx = pos.x + cell.width / 2;
        const cy = pos.y + cell.height / 2;
        const { targetEdge } = getOrgToSatelliteHandles(cx, cy);

        if (cell.teamData && cell.teamInner) {
          const teamData = cell.teamData;
          const teamNodeId = `team-${teamData.teamId}`;
          const {
            cols,
            rows,
            gap,
            projectGridTopInset: pti,
            projectHeight: ph,
            projectWidth: pw,
            totalProjectCount,
            collapsedSummary,
          } = cell.teamInner;
          const teamRollup = teamStatusRollups?.[teamData.teamId];

          nodes.push({
            id: teamNodeId,
            type: 'teamGroupNode',
            position: { x: pos.x, y: pos.y },
            width: cell.width,
            height: cell.height,
            data: {
              teamName: teamData.teamName,
              teamId: teamData.teamId,
              roleLabel: teamData.userRoleLabel ?? undefined,
              roleColor: teamData.userRoleColor ?? undefined,
              role: teamData.userRoleLabel?.toLowerCase() ?? undefined,
              width: cell.width,
              height: cell.height,
              overviewOrgEdgeTargetHandle: targetEdge,
              ...(typeof teamData.memberCount === 'number'
                ? { overviewMemberCount: teamData.memberCount }
                : {}),
              ...(collapsedSummary
                ? {
                    overviewProjectsTotal: totalProjectCount,
                    overviewCollapsedSummary: true,
                  }
                : {}),
              ...(teamRollup
                ? {
                    overviewStatusBadgeLabel: teamRollup.badgeLabel,
                    overviewStatusBadgeColor: teamRollup.badgeColor,
                    overviewStatusTooltip: teamRollup.tooltipText,
                    overviewNonPassingCount: teamRollup.nonPassingCount,
                  }
                : {}),
            },
            draggable: false,
            selectable: false,
            style: { zIndex: 1 },
          });

          const route = orgEdgeRouting.get(teamNodeId);
          if (route) {
            edges.push({
              id: `edge-org-${teamNodeId}`,
              source: ORG_CENTER_ID,
              target: teamNodeId,
              sourceHandle: route.sourceHandle,
              targetHandle: route.targetHandle,
              type: 'smoothstep',
              style: overviewEdgeStyle,
              pathOptions: { borderRadius: 20 },
            } as Edge);
          }

          const visibleProjects = teamData.projects.slice(0, cell.teamInner.visibleProjectCount);
          visibleProjects.forEach((proj, projIdx) => {
            const col = projIdx % cols;
            const row = Math.floor(projIdx / cols);
            const projectNodeId = `project-${proj.projectId}`;
            const px = TEAM_CONTAINER_PADDING + col * (pw + gap);
            const py = TEAM_CONTAINER_HEADER_HEIGHT + pti + row * (ph + gap);

            if (proj.isExtracting) {
              nodes.push({
                id: projectNodeId,
                type: 'vulnProjectNode',
                position: { x: px, y: py },
                parentId: teamNodeId,
                extent: 'parent' as const,
                width: pw,
                height: ph,
                data: {
                  projectName: proj.projectName,
                  projectId: proj.projectId,
                  framework: proj.framework ?? undefined,
                  neutralStyle: true,
                  isExtracting: true,
                  organizationId: organizationId ?? undefined,
                },
                draggable: false,
                selectable: false,
                style: { zIndex: 2 },
              });
            } else {
              nodes.push({
                id: projectNodeId,
                type: 'vulnProjectNode',
                position: { x: px, y: py },
                parentId: teamNodeId,
                extent: 'parent' as const,
                width: pw,
                height: ph,
                data: {
                  projectName: proj.projectName,
                  projectId: proj.projectId,
                  framework: proj.framework ?? undefined,
                  neutralStyle: true,
                  statusBadge: proj.statusName ?? undefined,
                  statusBadgeColor: proj.statusColor ?? undefined,
                  dependenciesCount: proj.dependenciesCount ?? undefined,
                  organizationId: organizationId ?? undefined,
                },
                draggable: false,
                selectable: false,
                style: { zIndex: 2 },
              });
            }
          });
        } else if (cell.ungroupedProject) {
          const proj = cell.ungroupedProject;
          const projectNodeId = `project-${proj.projectId}`;

          if (proj.isExtracting) {
            nodes.push({
              id: projectNodeId,
              type: 'vulnProjectNode',
              position: { x: pos.x, y: pos.y },
              width: OVERVIEW_PROJECT_NODE_WIDTH,
              height: OVERVIEW_PROJECT_NODE_HEIGHT,
              data: {
                projectName: proj.projectName,
                projectId: proj.projectId,
                framework: proj.framework ?? undefined,
                neutralStyle: true,
                isExtracting: true,
                organizationId: organizationId ?? undefined,
                overviewOrgEdgeTargetHandle: targetEdge,
              },
              draggable: false,
              selectable: false,
              style: { zIndex: 1 },
            });
          } else {
            nodes.push({
              id: projectNodeId,
              type: 'vulnProjectNode',
              position: { x: pos.x, y: pos.y },
              width: OVERVIEW_PROJECT_NODE_WIDTH,
              height: OVERVIEW_PROJECT_NODE_HEIGHT,
              data: {
                projectName: proj.projectName,
                projectId: proj.projectId,
                framework: proj.framework ?? undefined,
                neutralStyle: true,
                statusBadge: proj.statusName ?? undefined,
                statusBadgeColor: proj.statusColor ?? undefined,
                organizationId: organizationId ?? undefined,
                overviewOrgEdgeTargetHandle: targetEdge,
              },
              draggable: false,
              selectable: false,
              style: { zIndex: 1 },
            });
          }

          const projRoute = orgEdgeRouting.get(projectNodeId);
          if (projRoute) {
            edges.push({
              id: `edge-org-${projectNodeId}`,
              source: ORG_CENTER_ID,
              target: projectNodeId,
              sourceHandle: projRoute.sourceHandle,
              targetHandle: projRoute.targetHandle,
              type: 'smoothstep',
              style: overviewEdgeStyle,
              pathOptions: { borderRadius: 20 },
            } as Edge);
          }
        }
      });

    return { nodes, edges };
  }, [
    orgName,
    teamsWithProjects,
    orgAvatarUrl,
    orgRoleLabel,
    orgRoleColor,
    organizationId,
    orgRole,
    orgStatusRollup,
    teamStatusRollups,
  ]);
}

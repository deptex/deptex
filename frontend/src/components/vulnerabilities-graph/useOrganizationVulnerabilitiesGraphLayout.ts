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
        type: 'default',
        style: { stroke: grayStroke, strokeWidth: 1.2 },
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
          type: 'default',
          style: { stroke: grayStroke, strokeWidth: 1.2 },
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
  /** When true, show as extracting center node (spinner) and clicking opens extraction logs sidebar. */
  isExtracting?: boolean;
  /** Project health score 0–100 when available (for org center aggregate). */
  healthScore?: number | null;
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

const ORG_OVERVIEW_ORG_NODE_HALF_W = VULN_CENTER_NODE_WIDTH / 2;
const ORG_OVERVIEW_ORG_NODE_HALF_H = VULN_CENTER_NODE_HEIGHT / 2;

/** Cardinal slots: 1st right, 2nd down, 3rd left, 4th up (repeats for additional rings). */
type OverviewOrgGridSlot = 'right' | 'down' | 'left' | 'up';

const OVERVIEW_ORG_GRID_SLOT_ORDER: OverviewOrgGridSlot[] = ['right', 'down', 'left', 'up'];

/** Gap between stacked nodes in the same cardinal column (px). */
const OVERVIEW_ORG_GRID_STACK_GAP = 48;

/** Side of satellite node that receives the org edge (flat horizontal segment). */
function overviewOrgEdgeTargetSideForSlot(slot: OverviewOrgGridSlot): 'left' | 'right' | undefined {
  if (slot === 'right') return 'left';
  if (slot === 'left') return 'right';
  return undefined;
}

/**
 * Extra horizontal space from org when a team/card is wider than the reference min width.
 * Keeps single-column teams from feeling tighter than wide multi-project teams.
 */
function overviewOrgGridGapX(containerWidth: number): number {
  const ref = TEAM_CONTAINER_MIN_WIDTH;
  return 72 + 0.22 * Math.max(0, containerWidth - ref);
}

/** Extra vertical gap below/above org for tall team stacks (px). */
function overviewOrgGridGapY(containerHeight: number): number {
  const ref = TEAM_CONTAINER_MIN_HEIGHT;
  return 56 + 0.16 * Math.max(0, containerHeight - ref);
}

interface OverviewOrgGridCell {
  globalIndex: number;
  slot: OverviewOrgGridSlot;
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
  };
}

/**
 * Snap overview satellites to a grid around the org:
 * - Right/left: top aligns with org top; extra rows in that direction stack further out horizontally.
 * - Down/up: horizontally centered on org; stack further down/up; growth extends away from the org.
 */
function layoutOverviewOrgGrid(
  cells: OverviewOrgGridCell[],
  centerY: number
): Map<number, { x: number; y: number }> {
  const positions = new Map<number, { x: number; y: number }>();
  const Wo = ORG_OVERVIEW_ORG_NODE_HALF_W;
  const Ho = ORG_OVERVIEW_ORG_NODE_HALF_H;
  const orgTop = centerY - Ho;
  const orgBottom = centerY + Ho;
  const stack = OVERVIEW_ORG_GRID_STACK_GAP;

  for (const slot of OVERVIEW_ORG_GRID_SLOT_ORDER) {
    const inSlot = cells.filter((c) => c.slot === slot).sort((a, b) => a.globalIndex - b.globalIndex);
    if (inSlot.length === 0) continue;

    if (slot === 'right') {
      for (let i = 0; i < inSlot.length; i++) {
        const it = inSlot[i];
        const x =
          i === 0
            ? Wo + overviewOrgGridGapX(it.width)
            : positions.get(inSlot[i - 1].globalIndex)!.x + inSlot[i - 1].width + stack;
        positions.set(it.globalIndex, { x, y: orgTop });
      }
    } else if (slot === 'down') {
      for (let i = 0; i < inSlot.length; i++) {
        const it = inSlot[i];
        const y =
          i === 0
            ? orgBottom + overviewOrgGridGapY(it.height)
            : positions.get(inSlot[i - 1].globalIndex)!.y + inSlot[i - 1].height + stack;
        positions.set(it.globalIndex, { x: -it.width / 2, y });
      }
    } else if (slot === 'left') {
      for (let i = 0; i < inSlot.length; i++) {
        const it = inSlot[i];
        const x =
          i === 0
            ? -Wo - overviewOrgGridGapX(it.width) - it.width
            : positions.get(inSlot[i - 1].globalIndex)!.x - stack - it.width;
        positions.set(it.globalIndex, { x, y: orgTop });
      }
    } else {
      for (let i = 0; i < inSlot.length; i++) {
        const it = inSlot[i];
        const y =
          i === 0
            ? orgTop - overviewOrgGridGapY(it.height) - it.height
            : positions.get(inSlot[i - 1].globalIndex)!.y - stack - it.height;
        positions.set(it.globalIndex, { x: -it.width / 2, y });
      }
    }
  }

  return positions;
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
  teamStatusRollups?: Record<string, OverviewStatusRollup> | null
): { nodes: Node[]; edges: Edge[] } {
  return useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const centerX = 0;
    const centerY = 0;
    const grayStroke = '#262626';

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

    nodes.push({
      id: ORG_CENTER_ID,
      type: 'groupCenterNode',
      position: {
        x: centerX - VULN_CENTER_NODE_WIDTH / 2,
        y: centerY - VULN_CENTER_NODE_HEIGHT / 2,
      },
      data: {
        title: orgName,
        avatarUrl: orgAvatarUrl,
        kind: 'org',
        roleBadge: orgRoleLabel ?? undefined,
        roleBadgeColor: resolvedRoleColor,
        organizationRole: orgRole ?? undefined,
        organizationRiskScore,
        ...(orgStatusRollup
          ? {
              overviewStatusBadgeLabel: orgStatusRollup.badgeLabel,
              overviewStatusBadgeColor: orgStatusRollup.badgeColor,
              overviewStatusTooltip: orgStatusRollup.tooltipText,
            }
          : {}),
      },
      draggable: false,
      selectable: false,
    });

    const totalRingItems = realTeams.length + ungrouped.length;
    if (totalRingItems === 0) return { nodes, edges };

    // Handles / edges use pure cardinals (right, down, left, up) matching slot order.
    const cardinalAngles = [0, Math.PI / 2, Math.PI, (3 * Math.PI) / 2];

    const projectWidth = OVERVIEW_PROJECT_NODE_WIDTH;
    const projectHeight = OVERVIEW_PROJECT_NODE_HEIGHT;
    const innerGap = TEAM_CONTAINER_GRID_GAP;
    const projectGridTopInset = 6;
    const projectGridBottomInset = 8;

    const gridCells: OverviewOrgGridCell[] = [];

    realTeams.forEach((teamData, teamIndex) => {
      const projectCount = teamData.projects.length;
      const { cols, rows } = getOverviewTeamProjectGridDimensions(projectCount);
      const containerWidth = Math.max(
        TEAM_CONTAINER_MIN_WIDTH,
        cols * projectWidth + Math.max(0, cols - 1) * innerGap + TEAM_CONTAINER_PADDING * 2
      );
      const containerHeight = Math.max(
        TEAM_CONTAINER_MIN_HEIGHT,
        TEAM_CONTAINER_HEADER_HEIGHT +
          projectGridTopInset +
          rows * projectHeight +
          Math.max(0, rows - 1) * innerGap +
          projectGridBottomInset +
          TEAM_CONTAINER_FOOTER_HEIGHT
      );
      gridCells.push({
        globalIndex: teamIndex,
        slot: OVERVIEW_ORG_GRID_SLOT_ORDER[teamIndex % 4],
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
        },
      });
    });

    ungrouped.forEach((proj, ungroupedIdx) => {
      const globalIndex = realTeams.length + ungroupedIdx;
      gridCells.push({
        globalIndex,
        slot: OVERVIEW_ORG_GRID_SLOT_ORDER[globalIndex % 4],
        width: OVERVIEW_PROJECT_NODE_WIDTH,
        height: OVERVIEW_PROJECT_NODE_HEIGHT,
        teamData: null,
        ungroupedProject: proj,
      });
    });

    const gridPositions = layoutOverviewOrgGrid(gridCells, centerY);

    gridCells
      .sort((a, b) => a.globalIndex - b.globalIndex)
      .forEach((cell) => {
        const pos = gridPositions.get(cell.globalIndex);
        if (!pos) return;
        const angle = cardinalAngles[cell.globalIndex % 4];
        const { sourceHandle, targetHandle } = getHandlePair(angle);

        if (cell.teamData && cell.teamInner) {
          const teamData = cell.teamData;
          const teamNodeId = `team-${teamData.teamId}`;
          const { cols, rows, gap, projectGridTopInset: pti, projectHeight: ph, projectWidth: pw } = cell.teamInner;
          const overviewOrgEdgeOnTargetSide = overviewOrgEdgeTargetSideForSlot(cell.slot);
          const teamRollup = teamStatusRollups?.[teamData.teamId];

          nodes.push({
            id: teamNodeId,
            type: 'teamGroupNode',
            position: { x: pos.x, y: pos.y },
            data: {
              teamName: teamData.teamName,
              teamId: teamData.teamId,
              roleLabel: teamData.userRoleLabel ?? undefined,
              roleColor: teamData.userRoleColor ?? undefined,
              role: teamData.userRoleLabel?.toLowerCase() ?? undefined,
              width: cell.width,
              height: cell.height,
              ...(overviewOrgEdgeOnTargetSide ? { overviewOrgEdgeOnTargetSide } : {}),
              ...(teamRollup
                ? {
                    overviewStatusBadgeLabel: teamRollup.badgeLabel,
                    overviewStatusBadgeColor: teamRollup.badgeColor,
                    overviewStatusTooltip: teamRollup.tooltipText,
                  }
                : {}),
            },
            draggable: false,
            selectable: false,
            style: { zIndex: 0 },
          });

          edges.push({
            id: `edge-org-${teamNodeId}`,
            source: ORG_CENTER_ID,
            target: teamNodeId,
            sourceHandle,
            targetHandle,
            type: 'straight',
            style: { stroke: grayStroke, strokeWidth: 1.2, strokeDasharray: '6 6' },
          });

          teamData.projects.forEach((proj, projIdx) => {
            const col = projIdx % cols;
            const row = Math.floor(projIdx / cols);
            const projectNodeId = `project-${proj.projectId}`;
            const px = TEAM_CONTAINER_PADDING + col * (pw + gap);
            const py = TEAM_CONTAINER_HEADER_HEIGHT + pti + row * (ph + gap);

            if (proj.isExtracting) {
              nodes.push({
                id: projectNodeId,
                type: 'projectCenterNode',
                position: { x: px, y: py },
                parentId: teamNodeId,
                extent: 'parent' as const,
                data: {
                  projectName: proj.projectName,
                  isExtracting: true,
                  projectId: proj.projectId,
                  organizationId: organizationId ?? undefined,
                },
                draggable: false,
                selectable: false,
                style: { zIndex: 1 },
              });
            } else {
              nodes.push({
                id: projectNodeId,
                type: 'vulnProjectNode',
                position: { x: px, y: py },
                parentId: teamNodeId,
                extent: 'parent' as const,
                data: {
                  projectName: proj.projectName,
                  projectId: proj.projectId,
                  framework: proj.framework ?? undefined,
                  neutralStyle: true,
                  statusBadge: proj.statusName ?? undefined,
                  statusBadgeColor: proj.statusColor ?? undefined,
                  organizationId: organizationId ?? undefined,
                },
                draggable: false,
                selectable: false,
                style: { zIndex: 1 },
              });
            }
          });
        } else if (cell.ungroupedProject) {
          const proj = cell.ungroupedProject;
          const projectNodeId = `project-${proj.projectId}`;
          const overviewOrgEdgeOnTargetSide = overviewOrgEdgeTargetSideForSlot(cell.slot);

          if (proj.isExtracting) {
            nodes.push({
              id: projectNodeId,
              type: 'projectCenterNode',
              position: { x: pos.x, y: pos.y },
              data: {
                projectName: proj.projectName,
                isExtracting: true,
                projectId: proj.projectId,
                organizationId: organizationId ?? undefined,
                ...(overviewOrgEdgeOnTargetSide ? { overviewOrgEdgeOnTargetSide } : {}),
              },
              draggable: false,
              selectable: false,
            });
          } else {
            nodes.push({
              id: projectNodeId,
              type: 'vulnProjectNode',
              position: { x: pos.x, y: pos.y },
              data: {
                projectName: proj.projectName,
                projectId: proj.projectId,
                framework: proj.framework ?? undefined,
                neutralStyle: true,
                statusBadge: proj.statusName ?? undefined,
                statusBadgeColor: proj.statusColor ?? undefined,
                organizationId: organizationId ?? undefined,
                ...(overviewOrgEdgeOnTargetSide ? { overviewOrgEdgeOnTargetSide } : {}),
              },
              draggable: false,
              selectable: false,
            });
          }

          edges.push({
            id: `edge-org-${projectNodeId}`,
            source: ORG_CENTER_ID,
            target: projectNodeId,
            sourceHandle,
            targetHandle,
            type: 'straight',
            style: { stroke: grayStroke, strokeWidth: 1.2, strokeDasharray: '6 6' },
          });
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

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
  getOrgToSatelliteHandles,
  computeOrgOverviewEdgeRouting,
  ORG_OVERVIEW_EDGE_STROKE,
  ORG_OVERVIEW_CENTER_WIDTH,
  ORG_OVERVIEW_CENTER_HEIGHT,
  type OrgSatelliteTargetEdge,
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
      const isInitialExtracting = proj.isInitialExtracting === true;

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
          isInitialExtracting,
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
  /** When true, extraction pipeline is running (sync button spins, etc.). */
  isExtracting?: boolean;
  /** When true, this is the first-ever extraction — block UI with ExtractionProgressCard / grey node. */
  isInitialExtracting?: boolean;
  /** When true, the first-ever extraction failed — show "Extraction failed" in the node status strip. */
  isInitialExtractionFailed?: boolean;
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
/** Max projects shown in a ring around a team node before overflow. */
const MAX_PROJECTS_PER_TEAM_RING = 8;

/** Compute ring radius for N project satellites around a team hub. */
function teamProjectRingRadius(count: number): number {
  const clearance =
    Math.max(ORG_OVERVIEW_CENTER_WIDTH, ORG_OVERVIEW_CENTER_HEIGHT) / 2 +
    Math.max(OVERVIEW_PROJECT_NODE_WIDTH, OVERVIEW_PROJECT_NODE_HEIGHT) / 2 +
    50;
  return clearance + Math.max(0, count - 3) * 18;
}

/**
 * Place N project nodes in a fan on the **far side** of the team — away from the
 * org center — so no project lands between the team and the org, preventing
 * edges from crossing over other nodes.
 *
 * @param awayAngle  Angle (radians) from org center (0,0) to team center.
 *                   Projects fan out centered on this direction.
 */
function placeProjectsInRing(
  count: number,
  teamCX: number,
  teamCY: number,
  awayAngle: number,
): Array<{ x: number; y: number; angle: number }> {
  const radius = teamProjectRingRadius(count);

  // Wide fan (~280°) so projects spread naturally; single project sits directly away.
  const arcWidth = count <= 1 ? 0 : (14 * Math.PI) / 9; // ≈ 280°

  return Array.from({ length: count }, (_, i) => {
    const t = count <= 1 ? 0 : (i / (count - 1)) - 0.5; // –0.5 … +0.5
    const angle = awayAngle + t * arcWidth;
    return {
      x: teamCX + Math.cos(angle) * radius - OVERVIEW_PROJECT_NODE_WIDTH / 2,
      y: teamCY + Math.sin(angle) * radius - OVERVIEW_PROJECT_NODE_HEIGHT / 2,
      angle,
    };
  });
}

/** Pick cardinal source/target handles for a team→project edge based on angle. */
function getTeamProjectHandles(angle: number): {
  sourceHandle: string;
  targetHandle: string;
  targetEdge: OrgSatelliteTargetEdge;
} {
  const a = ((angle % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
  if (a >= (7 * Math.PI) / 4 || a < Math.PI / 4) return { sourceHandle: 'source-right', targetHandle: 'left', targetEdge: 'left' };
  if (a < (3 * Math.PI) / 4) return { sourceHandle: 'source-bottom', targetHandle: 'top', targetEdge: 'top' };
  if (a < (5 * Math.PI) / 4) return { sourceHandle: 'source-left', targetHandle: 'right', targetEdge: 'right' };
  return { sourceHandle: 'source-top', targetHandle: 'bottom', targetEdge: 'bottom' };
}

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
  orgPlan?: string | null,
  /** When true, collapse project satellites back into compact team-only cards. */
  compactTeams?: boolean
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

    // ── Concentric ring layout ──────────────────────────────────────────────
    //   Ring 1 (inner):  ungrouped projects — close to org
    //   Ring 2 (outer):  team hubs — further out
    //   Around each team: project fan (placeProjectsInRing)

    const teamW = ORG_OVERVIEW_CENTER_WIDTH;   // 300
    const teamH = ORG_OVERVIEW_CENTER_HEIGHT;  // 140

    // ── Ring 1: ungrouped projects ─────────────────────────────────────────
    const UNGROUPED_RING_RADIUS = 360;
    const ungroupedPositions = new Map<string, { x: number; y: number; angle: number }>();

    if (ungrouped.length > 0) {
      ungrouped.forEach((proj, i) => {
        const angle = (2 * Math.PI * i) / ungrouped.length - Math.PI / 2;
        const cx = Math.cos(angle) * UNGROUPED_RING_RADIUS;
        const cy = Math.sin(angle) * UNGROUPED_RING_RADIUS;
        ungroupedPositions.set(proj.projectId, {
          x: cx - OVERVIEW_PROJECT_NODE_WIDTH / 2,
          y: cy - OVERVIEW_PROJECT_NODE_HEIGHT / 2,
          angle,
        });
      });
    }

    // ── Ring 2: teams ──────────────────────────────────────────────────────
    // Radius clears the ungrouped ring + enough room for the team node itself.
    // When projects are expanded, add extra for the largest project fan so
    // adjacent team clusters don't overlap.
    const teamVisibleCounts = realTeams.map((t) =>
      Math.min(t.projects.length, MAX_PROJECTS_PER_TEAM_RING)
    );
    const maxFanRadius = compactTeams
      ? 0
      : Math.max(0, ...teamVisibleCounts.map((n) => (n > 0 ? teamProjectRingRadius(n) : 0)));

    const TEAM_RING_BASE = ungrouped.length > 0
      ? UNGROUPED_RING_RADIUS + Math.max(OVERVIEW_PROJECT_NODE_HEIGHT, OVERVIEW_PROJECT_NODE_WIDTH) / 2 + 200
      : 450;
    const TEAM_RING_RADIUS = TEAM_RING_BASE + maxFanRadius;

    interface TeamPlacement {
      teamData: OverviewTeamWithProjects;
      cx: number;
      cy: number;
      angle: number;
      visibleProjectCount: number;
      totalProjectCount: number;
    }
    const teamPlacements: TeamPlacement[] = [];

    if (realTeams.length > 0) {
      // Offset team ring so it sits in the gaps between ungrouped projects
      const teamOffset = ungrouped.length > 0
        ? Math.PI / Math.max(ungrouped.length, 1) // half-step between ungrouped angles
        : 0;

      realTeams.forEach((teamData, i) => {
        const angle = (2 * Math.PI * i) / realTeams.length - Math.PI / 2 + teamOffset;
        const cx = Math.cos(angle) * TEAM_RING_RADIUS;
        const cy = Math.sin(angle) * TEAM_RING_RADIUS;
        teamPlacements.push({
          teamData,
          cx,
          cy,
          angle,
          visibleProjectCount: teamVisibleCounts[i],
          totalProjectCount: teamData.projects.length,
        });
      });
    }

    // ── Edge routing from org ──────────────────────────────────────────────
    const orgLinkItems: Array<{ targetId: string; cx: number; cy: number }> = [];
    for (const tp of teamPlacements) {
      orgLinkItems.push({ targetId: `team-${tp.teamData.teamId}`, cx: tp.cx, cy: tp.cy });
    }
    for (const proj of ungrouped) {
      const up = ungroupedPositions.get(proj.projectId);
      if (!up) continue;
      orgLinkItems.push({
        targetId: `project-${proj.projectId}`,
        cx: up.x + OVERVIEW_PROJECT_NODE_WIDTH / 2,
        cy: up.y + OVERVIEW_PROJECT_NODE_HEIGHT / 2,
      });
    }
    const orgEdgeRouting = computeOrgOverviewEdgeRouting(orgLinkItems);

    // ── Emit team nodes & edges ───────────────────────────────────────────────

    for (const tp of teamPlacements) {
      const { teamData, cx: teamCX, cy: teamCY, totalProjectCount, visibleProjectCount } = tp;
      const teamNodeId = `team-${teamData.teamId}`;
      const teamX = teamCX - teamW / 2;
      const teamY = teamCY - teamH / 2;
      const { targetEdge } = getOrgToSatelliteHandles(teamCX, teamCY);

      nodes.push({
        id: teamNodeId,
        type: 'teamGroupNode',
        position: { x: teamX, y: teamY },
        width: teamW,
        height: teamH,
        data: {
          teamName: teamData.teamName,
          teamId: teamData.teamId,
          roleLabel: teamData.userRoleLabel ?? undefined,
          roleColor: teamData.userRoleColor ?? undefined,
          role: teamData.userRoleLabel?.toLowerCase() ?? undefined,
          width: teamW,
          height: teamH,
          overviewOrgEdgeTargetHandle: targetEdge,
          overviewProjectsTotal: totalProjectCount,
          overviewCollapsedSummary: true,
          ...(typeof teamData.memberCount === 'number'
            ? { overviewMemberCount: teamData.memberCount }
            : {}),
        },
        draggable: false,
        selectable: false,
        style: { zIndex: 2 },
      });

      // Org → team edge
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

      // ── Project satellites around team ──────────────────────────────────
      if (!compactTeams && visibleProjectCount > 0) {
        const shownProjects = teamData.projects.slice(0, visibleProjectCount);
        const awayAngle = Math.atan2(teamCY, teamCX);
        const projectPositions = placeProjectsInRing(shownProjects.length, teamCX, teamCY, awayAngle);

        shownProjects.forEach((proj, projIdx) => {
          const pp = projectPositions[projIdx];
          const projectNodeId = `project-${proj.projectId}`;
          const handles = getTeamProjectHandles(pp.angle);

          nodes.push({
            id: projectNodeId,
            type: 'vulnProjectNode',
            position: { x: pp.x, y: pp.y },
            width: OVERVIEW_PROJECT_NODE_WIDTH,
            height: OVERVIEW_PROJECT_NODE_HEIGHT,
            data: {
              projectName: proj.projectName,
              projectId: proj.projectId,
              framework: proj.framework ?? undefined,
              neutralStyle: true,
              organizationId: organizationId ?? undefined,
              overviewOrgEdgeTargetHandle: handles.targetEdge,
              ...(proj.isInitialExtracting
                ? { isExtracting: true, isInitialExtracting: true }
                : proj.isInitialExtractionFailed
                  ? { isInitialExtractionFailed: true }
                  : {
                      statusBadge: proj.statusName ?? undefined,
                      statusBadgeColor: proj.statusColor ?? undefined,
                      dependenciesCount: proj.dependenciesCount ?? undefined,
                      ...(proj.isExtracting ? { isExtracting: true } : {}),
                    }),
            },
            draggable: false,
            selectable: false,
            style: { zIndex: 1 },
          });

          edges.push({
            id: `edge-${teamNodeId}-${projectNodeId}`,
            source: teamNodeId,
            target: projectNodeId,
            sourceHandle: handles.sourceHandle,
            targetHandle: handles.targetHandle,
            type: 'smoothstep',
            style: overviewEdgeStyle,
            pathOptions: { borderRadius: 16 },
          } as Edge);
        });
      }
    }

    // ── Ungrouped projects (from separate ring) ──────────────────────────────
    for (const proj of ungrouped) {
      const up = ungroupedPositions.get(proj.projectId);
      if (!up) continue;
      const projectNodeId = `project-${proj.projectId}`;
      const cx = up.x + OVERVIEW_PROJECT_NODE_WIDTH / 2;
      const cy = up.y + OVERVIEW_PROJECT_NODE_HEIGHT / 2;
      const { targetEdge } = getOrgToSatelliteHandles(cx, cy);

      nodes.push({
        id: projectNodeId,
        type: 'vulnProjectNode',
        position: { x: up.x, y: up.y },
        width: OVERVIEW_PROJECT_NODE_WIDTH,
        height: OVERVIEW_PROJECT_NODE_HEIGHT,
        data: {
          projectName: proj.projectName,
          projectId: proj.projectId,
          framework: proj.framework ?? undefined,
          neutralStyle: true,
          organizationId: organizationId ?? undefined,
          overviewOrgEdgeTargetHandle: targetEdge,
          ...(proj.isInitialExtracting
            ? { isExtracting: true, isInitialExtracting: true }
            : proj.isInitialExtractionFailed
              ? { isInitialExtractionFailed: true }
              : {
                  statusBadge: proj.statusName ?? undefined,
                  statusBadgeColor: proj.statusColor ?? undefined,
                  ...(proj.isExtracting ? { isExtracting: true } : {}),
                }),
        },
        draggable: false,
        selectable: false,
        style: { zIndex: 1 },
      });

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
    compactTeams,
  ]);
}

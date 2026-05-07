import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { TeamGroupChip } from '../TeamIcon';
import { overviewStatusBadgeInlineStyle } from '../../lib/overviewStatusRollup';
import type { OrgSatelliteTargetEdge } from './overviewOrgLayout';
import { OverviewOrgTargetHandleFan } from './overviewOrgFlowHandles';

export interface TeamGroupNodeData {
  /** Team name displayed at top-left. */
  teamName: string;
  /** Team ID for click handling. */
  teamId: string;
  /** User's role label in this team (e.g. Owner, Member). */
  roleLabel?: string | null;
  /** Hex color for the user's role badge (e.g. from team.role_color). */
  roleColor?: string | null;
  /** Raw role (owner/admin/member) for RoleBadge fallback. */
  role?: string | null;
  /** Width of the container (calculated based on projects inside). */
  width?: number;
  /** Height of the container (calculated based on projects inside). */
  height?: number;
  /**
   * Org overview: which side receives the edge from the org (handle centered on that edge).
   */
  overviewOrgEdgeTargetHandle?: OrgSatelliteTargetEdge;
  /** Org overview: worst project status badge + tooltip breakdown. */
  overviewStatusBadgeLabel?: string;
  overviewStatusBadgeColor?: string | null;
  overviewStatusTooltip?: string;
  overviewProjectsTotal?: number;
  /** Compact card: project count + members only (no project tiles). */
  overviewCollapsedSummary?: boolean;
  /** Optional member count for collapsed summary line. */
  overviewMemberCount?: number;
  /** Count of projects with a non-passing status (for "X issues" display). */
  overviewNonPassingCount?: number;
}

/** Floor only for empty / degenerate layouts; normal sizes come from content. */
export const TEAM_CONTAINER_MIN_WIDTH = 260;
export const TEAM_CONTAINER_MIN_HEIGHT = 140;
/** Inset around the project grid (tight “hug” around cards). */
export const TEAM_CONTAINER_PADDING = 24;
/** Header row (team name + role); allows two-line team titles on org overview. */
export const TEAM_CONTAINER_HEADER_HEIGHT = 56;
/** Gap between project cards in the grid. */
export const TEAM_CONTAINER_GRID_GAP = 16;
/** Reserved footer height for aggregated status badge row (matches org overview project card footer: border-t + py-2). */
export const TEAM_CONTAINER_FOOTER_HEIGHT = 36;

function TeamGroupNodeComponent({ data }: NodeProps) {
  const {
    teamName = 'Team',
    width = TEAM_CONTAINER_MIN_WIDTH,
    height = TEAM_CONTAINER_MIN_HEIGHT,
    overviewOrgEdgeTargetHandle,
    overviewStatusBadgeLabel,
    overviewStatusBadgeColor,
    overviewStatusTooltip,
    overviewProjectsTotal,
    overviewMemberCount,
  } = (data as unknown as TeamGroupNodeData) ?? {};

  const hasStatusRollup =
    overviewStatusBadgeLabel != null &&
    overviewStatusBadgeLabel !== '' &&
    overviewStatusTooltip != null &&
    overviewStatusTooltip !== '';

  const sideMid = height / 2;
  const tbMid = width / 2;
  const overviewSideHandleStyle = { top: sideMid, transform: 'translateY(-50%)' } as const;
  const overviewTopBottomHandleStyle = { left: tbMid, transform: 'translateX(-50%)' } as const;
  const edge = overviewOrgEdgeTargetHandle;

  const subtitle = (() => {
    const parts: string[] = [];
    if (typeof overviewProjectsTotal === 'number') {
      parts.push(`${overviewProjectsTotal} ${overviewProjectsTotal === 1 ? 'project' : 'projects'}`);
    }
    if (typeof overviewMemberCount === 'number') {
      parts.push(`${overviewMemberCount} ${overviewMemberCount === 1 ? 'member' : 'members'}`);
    }
    return parts.join(' · ');
  })();

  return (
    <div className="relative h-full w-full rounded-xl" style={{ width, height }}>
      {/* Handles for edges - invisible but functional */}
      <Handle
        id="top"
        type="target"
        position={Position.Top}
        className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
        style={edge === 'top' ? overviewTopBottomHandleStyle : undefined}
      />
      <Handle
        id="right"
        type="target"
        position={Position.Right}
        className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
        style={edge === 'right' ? overviewSideHandleStyle : undefined}
      />
      <Handle
        id="bottom"
        type="target"
        position={Position.Bottom}
        className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
        style={edge === 'bottom' ? overviewTopBottomHandleStyle : undefined}
      />
      <Handle
        id="left"
        type="target"
        position={Position.Left}
        className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
        style={edge === 'left' ? overviewSideHandleStyle : undefined}
      />
      {edge != null && <OverviewOrgTargetHandleFan side={edge} />}
      <Handle id="source-top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      {/* Top-right: status rollup badge (only when present) */}
      {hasStatusRollup && (
        <div className="pointer-events-auto absolute top-1.5 right-1.5 z-[2]">
          <span
            className="inline-flex cursor-default items-center rounded-md border px-1.5 py-0.5 text-[10px] font-medium leading-none"
            style={overviewStatusBadgeInlineStyle(overviewStatusBadgeLabel!, overviewStatusBadgeColor ?? null)}
          >
            {overviewStatusBadgeLabel}
          </span>
        </div>
      )}

      {/* Card body — icon tile left, text right (matches org card family) */}
      <div className={`relative flex h-full w-full items-center gap-2.5 overflow-hidden rounded-xl border border-border bg-background-card-header shadow-lg shadow-slate-500/5 pl-2.5 ${hasStatusRollup ? 'pr-9' : 'pr-2.5'}`}>
        <TeamGroupChip />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-foreground truncate leading-tight tracking-tight">
            {teamName}
          </p>
        </div>
      </div>
    </div>
  );
}

export const TeamGroupNode = memo(TeamGroupNodeComponent);

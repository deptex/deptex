import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { overviewStatusBadgeInlineStyle } from '../../lib/overviewStatusRollup';
import { GraphScopePill } from './GraphScopePill';
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
    overviewCollapsedSummary,
    overviewMemberCount,
    overviewNonPassingCount,
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

  return (
    <div
      className="relative box-border flex min-h-0 min-w-0 flex-col overflow-hidden rounded-xl border border-border bg-background-card-header shadow-lg shadow-slate-500/5"
      style={{
        width,
        height,
      }}
    >
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

      {/* Header: team name + role badge vertically centered as a row (2-line title: badge centers on block) */}
      <div className="relative z-[1] flex flex-1 flex-col justify-start gap-0.5 px-4 pr-11 pt-4">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="min-w-0 text-left text-base font-semibold leading-snug text-foreground line-clamp-2 break-words">
              {teamName}
            </span>
          </TooltipTrigger>
          <TooltipContent side="bottom" sideOffset={4} className="max-w-sm">
            {teamName}
          </TooltipContent>
        </Tooltip>
        {overviewCollapsedSummary && overviewProjectsTotal != null && (
          <p className="text-xs text-muted-foreground tabular-nums">
            {overviewProjectsTotal} {overviewProjectsTotal === 1 ? 'project' : 'projects'}
          </p>
        )}
      </div>

      {/* Top-right: scope */}
      <div className="pointer-events-auto absolute top-2 right-2 z-[2] flex items-center gap-0.5">
        <GraphScopePill type="team" />
      </div>



      {/* Bottom bar: aggregated project status (worst-of + breakdown tooltip) — parity with VulnProjectNode org overview footer */}
      {hasStatusRollup && (
        <div className="relative z-[1] flex shrink-0 items-center gap-2 bg-background-card-header/95 px-4 py-3">
          <Tooltip>
            <TooltipTrigger asChild>
              <span
                className="inline-flex max-w-full cursor-default items-center truncate rounded-md border px-2 py-0.5 text-[10px] font-medium"
                style={overviewStatusBadgeInlineStyle(overviewStatusBadgeLabel!, overviewStatusBadgeColor ?? null)}
              >
                {overviewStatusBadgeLabel}
              </span>
            </TooltipTrigger>
            <TooltipContent side="top" sideOffset={6} className="max-w-xs">
              {overviewStatusTooltip}
            </TooltipContent>
          </Tooltip>
        </div>
      )}
    </div>
  );
}

export const TeamGroupNode = memo(TeamGroupNodeComponent);

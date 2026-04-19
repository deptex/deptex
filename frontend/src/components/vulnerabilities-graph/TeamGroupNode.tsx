import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { VULN_CENTER_NODE_HEIGHT } from './useVulnerabilitiesGraphLayout';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { overviewStatusBadgeInlineStyle } from '../../lib/overviewStatusRollup';
import { RoleBadge } from '../RoleBadge';
import { GraphScopePill } from './GraphScopePill';

export interface TeamGroupNodeData {
  /** Team name displayed at top-left. */
  teamName: string;
  /** Team ID for click handling. */
  teamId: string;
  /** User's role label in this team (e.g. Owner, Member). */
  roleLabel?: string | null;
  /** Hex color for the role badge. */
  roleColor?: string | null;
  /** Raw role (owner/admin/member) for RoleBadge fallback. */
  role?: string | null;
  /** Width of the container (calculated based on projects inside). */
  width?: number;
  /** Height of the container (calculated based on projects inside). */
  height?: number;
  /**
   * Org overview: which side receives the edge from the org so the handle sits on the org’s layout
   * midline (flat horizontal connector). `left` = team is to the right of org; `right` = team is to the left.
   */
  overviewOrgEdgeOnTargetSide?: 'left' | 'right';
  /** Org overview: worst project status badge + tooltip breakdown. */
  overviewStatusBadgeLabel?: string;
  overviewStatusBadgeColor?: string | null;
  overviewStatusTooltip?: string;
}

/** Floor only for empty / degenerate layouts; normal sizes come from content. */
export const TEAM_CONTAINER_MIN_WIDTH = 260;
export const TEAM_CONTAINER_MIN_HEIGHT = 140;
/** Inset around the project grid (tight “hug” around cards). */
export const TEAM_CONTAINER_PADDING = 24;
/** Header row (team name + role). */
export const TEAM_CONTAINER_HEADER_HEIGHT = 44;
/** Gap between project cards in the grid. */
export const TEAM_CONTAINER_GRID_GAP = 16;
/** Reserved footer height for aggregated status badge row (px-ish via layout). */
export const TEAM_CONTAINER_FOOTER_HEIGHT = 48;

function TeamGroupNodeComponent({ data }: NodeProps) {
  const {
    teamName = 'Team',
    roleLabel,
    roleColor,
    role,
    width = TEAM_CONTAINER_MIN_WIDTH,
    height = TEAM_CONTAINER_MIN_HEIGHT,
    overviewOrgEdgeOnTargetSide,
    overviewStatusBadgeLabel,
    overviewStatusBadgeColor,
    overviewStatusTooltip,
  } = (data as unknown as TeamGroupNodeData) ?? {};

  const hasStatusRollup =
    overviewStatusBadgeLabel != null &&
    overviewStatusBadgeLabel !== '' &&
    overviewStatusTooltip != null &&
    overviewStatusTooltip !== '';

  const roleForBadge = (role || roleLabel || 'member').toLowerCase();
  const overviewFlatY = VULN_CENTER_NODE_HEIGHT / 2;
  const overviewSideHandleStyle = { top: overviewFlatY, transform: 'translateY(-50%)' } as const;

  return (
    <div
      className="relative"
      style={{
        width,
        height,
      }}
    >
      {/* Handles for edges - invisible but functional */}
      <Handle id="top" type="target" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle
        id="right"
        type="target"
        position={Position.Right}
        className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
        style={overviewOrgEdgeOnTargetSide === 'right' ? overviewSideHandleStyle : undefined}
      />
      <Handle id="bottom" type="target" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle
        id="left"
        type="target"
        position={Position.Left}
        className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
        style={overviewOrgEdgeOnTargetSide === 'left' ? overviewSideHandleStyle : undefined}
      />
      <Handle id="source-top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      {/* Match org center card: same surface, border, and radius as GroupCenterNode (org) */}
      <div
        className="absolute inset-0 rounded-xl border border-border bg-background-card-header shadow-lg shadow-slate-500/5"
      />

      {/* Header: Team name + role badge in top-left; scope + Safe top-right */}
      <div className="absolute top-3.5 left-4 right-44 flex items-center gap-3 min-w-0">
        <span className="text-base font-semibold text-foreground truncate">{teamName}</span>
        {roleLabel && (
          <RoleBadge
            role={roleForBadge}
            roleDisplayName={roleLabel}
            roleColor={roleColor ?? null}
          />
        )}
      </div>

      {/* Top-right: scope pill only */}
      <div className="absolute top-3 right-3 flex items-center gap-2">
        <GraphScopePill type="team" />
      </div>

      {/* Bottom bar: aggregated project status (worst-of + breakdown tooltip) */}
      {hasStatusRollup && (
        <div className="absolute bottom-0 left-0 right-0 border-t border-border px-4 py-3 flex items-center gap-2 rounded-b-xl">
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

import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Folder, Loader2 } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { FrameworkIcon } from '../framework-icon';
import { OverviewTeamSatelliteChip, TeamIcon } from '../TeamIcon';
import { type WorstSeverity } from './useVulnerabilitiesGraphLayout';
import { GraphScopePill } from './GraphScopePill';
import type { OrgSatelliteTargetEdge } from './overviewOrgLayout';
import { OverviewOrgTargetHandleFan } from './overviewOrgFlowHandles';

export interface VulnProjectNodeData {
  projectName: string;
  projectId: string;
  /** When set, show framework icon (same as project vulnerabilities tab header); otherwise Folder. */
  framework?: string | null;
  /** Worst vulnerability severity for this project (used to color the card). */
  worstSeverity?: WorstSeverity;
  /** When true, render as a team node (Users icon) instead of a project (framework/folder icon). */
  isTeamNode?: boolean;
  /** Phase 15: Number of vulnerabilities with SLA breached. Shown as "SLA: X breached" when > 0. */
  slaBreachCount?: number;
  /** When true, extraction pipeline is running (sync button spins). */
  isExtracting?: boolean;
  /** When true, this is the first-ever extraction — grey out node, show spinner badge. Re-syncs keep normal appearance. */
  isInitialExtracting?: boolean;
  /** When true, the first-ever extraction failed — show "Extraction failed" in status strip instead of "No status". */
  isInitialExtractionFailed?: boolean;
  /** When true (team node only), team has projects still extracting — show grey so color reflects known risk only. */
  hasExtractingProjects?: boolean;
  /** When true, use neutral grey styling only (no severity colors). Used for org overview graph. */
  neutralStyle?: boolean;
  /** Badge on the right: user's role in this team (team nodes). */
  roleBadge?: string | null;
  /** Hex color for role badge (e.g. from team.role_color). */
  roleBadgeColor?: string | null;
  /** Badge on the right for project nodes: project status (e.g. Compliant, Non-Compliant). */
  statusBadge?: string | null;
  /** Hex color for status badge (e.g. from organization_statuses.color). */
  statusBadgeColor?: string | null;
  /** Team nodes: risk grade shown on the right (e.g. A+). */
  riskGrade?: string | null;
  /** Team nodes (org overview): number of projects for bottom bar. */
  projectsCount?: number | null;
  /** Team nodes (org overview): number of members for bottom bar. */
  membersCount?: number | null;
  /** Project nodes (org overview): per-project importance multiplier in [0.5, 2.0]. The number IS the depscore multiplier. */
  importance?: number | null;
  /** Org overview: number of dependencies to show in bottom bar. */
  dependenciesCount?: number | null;
  /** Org overview: opens extraction sync sidebar when set (extracting projects). */
  organizationId?: string | null;
  /** Org overview: which side receives the org→project edge (handle centered on that edge). */
  overviewOrgEdgeTargetHandle?: OrgSatelliteTargetEdge;
}

const NODE_WIDTH = 220;
const NODE_HEIGHT = 64;
/**
 * Org / team graph: satellite “team” cards on the ring — wider/taller than project cards so hierarchy reads clearly.
 */
export const OVERVIEW_TEAM_RING_CARD_WIDTH = 276;
export const OVERVIEW_TEAM_RING_CARD_HEIGHT = 104;
/** Org overview project tiles + ungrouped satellites: compact icon-only node with the label rendered below. */
export const OVERVIEW_PROJECT_NODE_WIDTH = 60;
export const OVERVIEW_PROJECT_NODE_HEIGHT = 60;

function getColorScheme(worstSeverity: WorstSeverity | undefined) {
  const s = worstSeverity ?? 'none';
  switch (s) {
    case 'critical':
      return {
        border: 'border-red-500/40',
        shadow: 'shadow-red-500/5',
        glow: 'bg-red-500',
        iconBg: 'bg-red-500/10',
        iconText: 'text-red-500',
      };
    case 'high':
      return {
        border: 'border-orange-500/40',
        shadow: 'shadow-orange-500/5',
        glow: 'bg-orange-500',
        iconBg: 'bg-orange-500/10',
        iconText: 'text-orange-500',
      };
    case 'medium':
      return {
        border: 'border-yellow-500/40',
        shadow: 'shadow-yellow-500/5',
        glow: 'bg-yellow-500',
        iconBg: 'bg-yellow-500/10',
        iconText: 'text-yellow-500',
      };
    case 'low':
      return {
        border: 'border-slate-500/40',
        shadow: 'shadow-slate-500/5',
        glow: 'bg-slate-500',
        iconBg: 'bg-slate-500/10',
        iconText: 'text-slate-500',
      };
    case 'none':
    default:
      return {
        border: 'border-primary/50',
        shadow: 'shadow-primary/10',
        glow: 'bg-primary',
        iconBg: 'bg-primary/15',
        iconText: 'text-primary',
      };
  }
}

const greyExtractingScheme = {
  border: 'border-slate-400/40',
  shadow: 'shadow-slate-400/5',
  glow: 'bg-slate-400',
  iconBg: 'bg-slate-400/15',
  iconText: 'text-slate-500',
};

const neutralScheme = {
  border: 'border-[#22272b]',
  shadow: 'shadow-slate-500/5',
  glow: 'bg-slate-500',
  iconBg: 'bg-[#1a1c1e]',
  iconText: 'text-muted-foreground',
};

function hexToRgba(hex: string, alpha: number): string {
  if (!hex || hex.length < 4) return `rgba(0,0,0,${alpha})`;
  let r = 0, g = 0, b = 0;
  if (hex.length === 4) {
    r = parseInt(hex[1] + hex[1], 16);
    g = parseInt(hex[2] + hex[2], 16);
    b = parseInt(hex[3] + hex[3], 16);
  } else if (hex.length >= 7) {
    r = parseInt(hex.slice(1, 3), 16);
    g = parseInt(hex.slice(3, 5), 16);
    b = parseInt(hex.slice(5, 7), 16);
  }
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

/** Fallback status colors when API doesn't return status_color (e.g. projects list). */
function statusBadgeColorFallback(label: string | null | undefined): string | null {
  if (!label || typeof label !== 'string') return null;
  const lower = label.toLowerCase();
  if (lower.includes('compliant') && !lower.includes('non') && !lower.includes('not')) return '#22c55e';
  if (lower.includes('non-compliant') || lower.includes('not compliant') || lower.includes('non compliant')) return '#ef4444';
  if (lower.includes('under review') || lower.includes('review')) return '#f59e0b';
  if (lower.includes('failed') || lower.includes('error')) return '#ef4444';
  return null;
}

function VulnProjectNodeComponent({ data }: NodeProps) {
  const { projectName = 'Project', projectId, framework, worstSeverity, isTeamNode, slaBreachCount, isExtracting, isInitialExtracting, isInitialExtractionFailed, hasExtractingProjects, neutralStyle, roleBadge, roleBadgeColor, statusBadge, statusBadgeColor, riskGrade, projectsCount, membersCount, dependenciesCount, importance, overviewOrgEdgeTargetHandle } =
    (data as unknown as VulnProjectNodeData) ?? {};
  const hasKnownFramework = framework && framework.toLowerCase() !== 'unknown';
  const frameworkIdForIcon = hasKnownFramework ? framework : undefined;
  // Only grey out for initial extraction (first-ever scan); re-syncs keep normal colors
  const useGrey = neutralStyle || isInitialExtracting || (isTeamNode && hasExtractingProjects);
  const colorScheme = useGrey ? (neutralStyle ? neutralScheme : greyExtractingScheme) : getColorScheme(worstSeverity);
  const showSlaBreach = !isInitialExtracting && typeof slaBreachCount === 'number' && slaBreachCount > 0;
  const showTeamRoleBadge = !isInitialExtracting && roleBadge != null && roleBadge !== '' && isTeamNode;
  const showStatusBadge = !isInitialExtracting && !isInitialExtractionFailed && statusBadge != null && statusBadge !== '' && !isTeamNode;
  const showTeamRiskGrade = !isInitialExtracting && isTeamNode && (riskGrade ?? 'A+');
  const showProjectRiskGrade = !isInitialExtracting && !isTeamNode && neutralStyle && (riskGrade ?? 'A+');
  const showImportanceSubtext = !isInitialExtracting && !isInitialExtractionFailed && !isTeamNode && typeof importance === 'number' && Number.isFinite(importance);
  const importanceLabel = typeof importance === 'number' && Number.isFinite(importance) ? `Importance: ${importance.toFixed(2)}` : null;
  const importanceColors = (() => {
    if (typeof importance !== 'number' || !Number.isFinite(importance)) return null;
    const v = Math.max(0.5, Math.min(2.0, importance));
    if (v >= 1.5) return { text: 'text-destructive', dotClass: 'bg-destructive', dotOpacity: 1.0 };
    if (v >= 1.1) return { text: 'text-foreground', dotClass: 'bg-foreground', dotOpacity: 0.75 };
    if (v >= 0.8) return { text: 'text-foreground-secondary', dotClass: 'bg-foreground-secondary', dotOpacity: 0.5 };
    return { text: 'text-muted-foreground', dotClass: 'bg-muted-foreground', dotOpacity: 0.3 };
  })();
  const showCardTooltip = !isTeamNode && neutralStyle && !isInitialExtracting && !isInitialExtractionFailed;
  const rawStatusColor = statusBadgeColor?.trim() ? statusBadgeColor : (showStatusBadge ? statusBadgeColorFallback(statusBadge) : null);
  const effectiveStatusColor = rawStatusColor && !rawStatusColor.startsWith('#') ? `#${rawStatusColor}` : rawStatusColor;

  /** Org overview: project card with header + status footer — same shell for ready and extracting. */
  const isOverviewProjectCard = Boolean(neutralStyle && !isTeamNode);
  /** Org overview: team satellite card with border, risk badge, bottom bar (x projects, x members). */
  const isOverviewTeamCard = Boolean(neutralStyle && isTeamNode && !isInitialExtracting);
  const nodeWidth = isOverviewTeamCard
    ? OVERVIEW_TEAM_RING_CARD_WIDTH
    : isOverviewProjectCard
      ? OVERVIEW_PROJECT_NODE_WIDTH
      : NODE_WIDTH;
  const nodeHeight = isOverviewTeamCard
    ? OVERVIEW_TEAM_RING_CARD_HEIGHT
    : isOverviewProjectCard
      ? OVERVIEW_PROJECT_NODE_HEIGHT
      : NODE_HEIGHT;
  const overviewSideMidY = nodeHeight / 2;
  const overviewTopBottomMidX = nodeWidth / 2;
  const overviewSideHandleStyle = { top: overviewSideMidY, transform: 'translateY(-50%)' } as const;
  const overviewTopBottomHandleStyle = { left: overviewTopBottomMidX, transform: 'translateX(-50%)' } as const;
  const orgEdge = overviewOrgEdgeTargetHandle;

  /** Fixed box for org overview cards so RF sub-flow slots stay non-overlapping (min-* alone can grow with content). */
  const rootStyle =
    isOverviewProjectCard || isOverviewTeamCard
      ? ({
          width: nodeWidth,
          height: nodeHeight,
          minWidth: nodeWidth,
          minHeight: nodeHeight,
          maxWidth: nodeWidth,
          boxSizing: 'border-box' as const,
        })
      : { minWidth: nodeWidth, minHeight: nodeHeight };

  return (
    <div className="relative rounded-xl" style={rootStyle}>
      <Handle
        id="top"
        type="target"
        position={Position.Top}
        className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
        style={orgEdge === 'top' ? overviewTopBottomHandleStyle : undefined}
      />
      <Handle
        id="right"
        type="target"
        position={Position.Right}
        className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
        style={orgEdge === 'right' ? overviewSideHandleStyle : undefined}
      />
      <Handle
        id="bottom"
        type="target"
        position={Position.Bottom}
        className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
        style={orgEdge === 'bottom' ? overviewTopBottomHandleStyle : undefined}
      />
      <Handle
        id="left"
        type="target"
        position={Position.Left}
        className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
        style={orgEdge === 'left' ? overviewSideHandleStyle : undefined}
      />
      {orgEdge != null && <OverviewOrgTargetHandleFan side={orgEdge} />}
      <Handle id="source-top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      {isOverviewTeamCard ? (
        <div className="relative rounded-xl border border-border bg-background-card-header shadow-lg shadow-slate-500/5 h-full flex flex-col overflow-hidden cursor-pointer hover:border-border/80 transition-all">
          {/* Top: Team icon, name, scope pill */}
          <div className="px-4 py-3 flex items-center gap-3 min-w-0 flex-1">
            <OverviewTeamSatelliteChip />
            <div className="min-w-0 flex-1">
              <p className="text-base font-semibold text-foreground truncate leading-tight" title={projectName}>
                {projectName}
              </p>
            </div>
            <GraphScopePill type="team" className="shrink-0" />
          </div>
          {/* Bottom bar: risk badge only */}
          <div className="border-t border-border px-4 py-2.5 flex items-center rounded-b-xl">
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="flex-shrink-0 rounded-md border border-green-500/35 bg-green-500/15 px-2 py-0.5 text-xs font-semibold text-green-500 cursor-default">
                  {riskGrade ?? 'A+'}
                </span>
              </TooltipTrigger>
              <TooltipContent side="top">Calculated risk score based on vulnerabilities, secrets, and code findings.</TooltipContent>
            </Tooltip>
          </div>
        </div>
      ) : isOverviewProjectCard ? (
        <>
          {/* Compact icon-only node. Project name (and status) render below the
              card, outside the clipping box, n8n / Tines style. */}
          <div className="relative h-full w-full rounded-xl border border-border bg-background-card-header shadow-lg shadow-slate-500/5 cursor-pointer flex items-center justify-center hover:border-border/80 transition-colors">
            {isInitialExtracting ? (
              <Loader2 className="h-6 w-6 text-muted-foreground animate-spin" aria-hidden />
            ) : frameworkIdForIcon ? (
              <FrameworkIcon frameworkId={frameworkIdForIcon} size={30} className="text-white" />
            ) : (
              <Folder className="h-7 w-7 text-white" strokeWidth={1.5} />
            )}
          </div>
          {/* Label stack positioned below the card; overflow escapes the 84x84 node box. */}
          <div
            className="absolute left-1/2 top-full -translate-x-1/2 mt-2 flex flex-col items-center text-center select-none"
            style={{ width: 160 }}
          >
            <p className="text-[12px] font-medium text-foreground leading-tight truncate max-w-full">
              {projectName}
            </p>
            {isInitialExtracting ? (
              <span className="text-[10px] text-muted-foreground mt-0.5">Creating</span>
            ) : isInitialExtractionFailed ? (
              <span className="text-[10px] text-destructive/80 mt-0.5">Failed</span>
            ) : showStatusBadge ? (
              <span
                className="mt-0.5 text-[10px] font-medium truncate max-w-full"
                style={{ color: effectiveStatusColor ?? undefined }}
              >
                {statusBadge}
              </span>
            ) : null}
          </div>
        </>
      ) : showCardTooltip ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <div
              className={`relative rounded-xl border-2 bg-background-card px-3 py-2.5 shadow-sm h-full flex flex-col justify-center gap-0.5 min-w-0 overflow-hidden ${colorScheme.border} ${colorScheme.shadow}`}
            >
              {!isInitialExtracting && <div className={`absolute inset-0 rounded-xl blur-xl opacity-15 -z-10 ${colorScheme.glow}`} />}
              <div className="flex items-center gap-2 min-w-0">
                {isTeamNode && !isInitialExtracting ? (
                  <TeamIcon />
                ) : frameworkIdForIcon ? (
                  <div
                    className={`flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0 ${colorScheme.iconBg} ${colorScheme.iconText}`}
                  >
                    <FrameworkIcon frameworkId={frameworkIdForIcon} size={18} className="text-current" />
                  </div>
                ) : (
                  <div
                    className={`flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0 ${colorScheme.iconBg} ${colorScheme.iconText}`}
                  >
                    <Folder className="w-4 h-4" />
                  </div>
                )}
                <div className="min-w-0 flex-1 flex flex-col gap-1">
                  <p className="text-sm font-medium text-foreground truncate" title={projectName}>
                    {projectName}
                  </p>
                  {isTeamNode && showTeamRoleBadge ? (
                    <span
                      className="inline-flex w-fit rounded-md border px-2 py-0.5 text-[10px] font-medium"
                      style={roleBadgeColor && roleBadgeColor.trim() !== ''
                        ? { backgroundColor: hexToRgba(roleBadgeColor, 0.1), color: roleBadgeColor, borderColor: hexToRgba(roleBadgeColor, 0.2) }
                        : { backgroundColor: 'transparent', color: 'var(--muted-foreground)', borderColor: 'rgba(255,255,255,0.2)' }
                      }
                    >
                      {roleBadge}
                    </span>
                  ) : null}
                  {!showTeamRoleBadge && isInitialExtracting ? (
                    <p className="text-[10px] text-foreground-secondary">Project still extracting</p>
                  ) : !isTeamNode && showImportanceSubtext && importanceColors ? (
                    <p className={`text-[10px] truncate flex items-center gap-1 ${importanceColors.text}`} title={importanceLabel ?? undefined}>
                      <span
                        className={`inline-block h-1.5 w-1.5 rounded-full ${importanceColors.dotClass}`}
                        style={{ opacity: importanceColors.dotOpacity }}
                      />
                      {importanceLabel}
                    </p>
                  ) : null}
                </div>
                {(showTeamRiskGrade || showProjectRiskGrade) && (
                  <span className="flex-shrink-0 rounded-md border border-green-500/35 bg-green-500/15 px-2 py-0.5 text-sm font-semibold text-green-500">
                    {riskGrade ?? 'A+'}
                  </span>
                )}
                {showStatusBadge && (
                  <span
                    className="flex-shrink-0 inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium"
                    style={effectiveStatusColor
                      ? { backgroundColor: `${effectiveStatusColor}20`, color: effectiveStatusColor, borderColor: `${effectiveStatusColor}40` }
                      : { backgroundColor: 'transparent', color: 'var(--muted-foreground)', borderColor: 'rgba(255,255,255,0.2)' }
                    }
                  >
                    {statusBadge}
                  </span>
                )}
                {!showTeamRiskGrade && !showProjectRiskGrade && !showStatusBadge && isInitialExtracting && (
                  <div className="flex-shrink-0" aria-hidden>
                    <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                  </div>
                )}
              </div>
              {showSlaBreach && (
                <p className="text-[10px] text-red-400 font-medium truncate" title={`${slaBreachCount} SLA breach(es)`}>
                  SLA: {slaBreachCount} breached
                </p>
              )}
            </div>
          </TooltipTrigger>
          <TooltipContent side="top">Calculated risk score based on vulnerabilities, secrets, and code findings.</TooltipContent>
        </Tooltip>
      ) : (
        <div
          className={`relative rounded-xl border-2 bg-background-card px-3 py-2.5 shadow-sm h-full flex flex-col justify-center gap-0.5 min-w-0 overflow-hidden ${colorScheme.border} ${colorScheme.shadow}`}
        >
          {!isExtracting && <div className={`absolute inset-0 rounded-xl blur-xl opacity-15 -z-10 ${colorScheme.glow}`} />}
          <div className="flex items-center gap-2 min-w-0">
            {isTeamNode && !isExtracting ? (
              <TeamIcon />
            ) : frameworkIdForIcon ? (
              <div
                className={`flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0 ${colorScheme.iconBg} ${colorScheme.iconText}`}
              >
                <FrameworkIcon frameworkId={frameworkIdForIcon} size={18} className="text-current" />
              </div>
            ) : (
              <div
                className={`flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0 ${colorScheme.iconBg} ${colorScheme.iconText}`}
              >
                <Folder className="w-4 h-4" />
              </div>
            )}
            <div className="min-w-0 flex-1 flex flex-col gap-1">
              <p className="text-sm font-medium text-foreground truncate" title={projectName}>
                {projectName}
              </p>
              {isTeamNode && showTeamRoleBadge ? (
                <span
                  className="inline-flex w-fit rounded-md border px-2 py-0.5 text-[10px] font-medium"
                  style={roleBadgeColor && roleBadgeColor.trim() !== ''
                    ? { backgroundColor: hexToRgba(roleBadgeColor, 0.1), color: roleBadgeColor, borderColor: hexToRgba(roleBadgeColor, 0.2) }
                    : { backgroundColor: 'transparent', color: 'var(--muted-foreground)', borderColor: 'rgba(255,255,255,0.2)' }
                  }
                >
                  {roleBadge}
                </span>
              ) : null}
              {!showTeamRoleBadge && isExtracting ? (
                <p className="text-[10px] text-foreground-secondary">Project still extracting</p>
              ) : !isTeamNode && showImportanceSubtext && importanceColors ? (
                <p className={`text-[10px] truncate flex items-center gap-1 ${importanceColors.text}`} title={importanceLabel ?? undefined}>
                  <span
                    className={`inline-block h-1.5 w-1.5 rounded-full ${importanceColors.dotClass}`}
                    style={{ opacity: importanceColors.dotOpacity }}
                  />
                  {importanceLabel}
                </p>
              ) : null}
            </div>
            {(showTeamRiskGrade || showProjectRiskGrade) && (
              <span className="flex-shrink-0 rounded-md border border-green-500/35 bg-green-500/15 px-2 py-0.5 text-sm font-semibold text-green-500">
                {riskGrade ?? 'A+'}
              </span>
            )}
            {showStatusBadge && (
              <span
                className="flex-shrink-0 inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium"
                style={effectiveStatusColor
                  ? { backgroundColor: `${effectiveStatusColor}20`, color: effectiveStatusColor, borderColor: `${effectiveStatusColor}40` }
                  : { backgroundColor: 'transparent', color: 'var(--muted-foreground)', borderColor: 'rgba(255,255,255,0.2)' }
                }
              >
                {statusBadge}
              </span>
            )}
            {!showTeamRiskGrade && !showProjectRiskGrade && !showStatusBadge && isExtracting && (
              <div className="flex-shrink-0" aria-hidden>
                <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
              </div>
            )}
          </div>
          {showSlaBreach && (
            <p className="text-[10px] text-red-400 font-medium truncate" title={`${slaBreachCount} SLA breach(es)`}>
              SLA: {slaBreachCount} breached
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export const VulnProjectNode = memo(VulnProjectNodeComponent);
export const VULN_PROJECT_NODE_WIDTH = NODE_WIDTH;
export const VULN_PROJECT_NODE_HEIGHT = NODE_HEIGHT;

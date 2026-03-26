import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Folder, Loader2, Users } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { FrameworkIcon } from '../framework-icon';
import { TeamIcon } from '../TeamIcon';
import { type WorstSeverity, VULN_CENTER_NODE_HEIGHT } from './useVulnerabilitiesGraphLayout';
import { GraphScopePill } from './GraphScopePill';

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
  /** When true, show extracting spinner and no dependency/vulnerability data (like Project Security tab). */
  isExtracting?: boolean;
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
  /** Project nodes (org overview): asset tier name shown in badge (e.g. Crown Jewels, External). */
  assetTierName?: string | null;
  /** Project nodes (org overview): hex color for asset tier badge (from organization_asset_tiers). */
  assetTierColor?: string | null;
  /** Org overview: number of dependencies to show in bottom bar. */
  dependenciesCount?: number | null;
  /**
   * Org overview: target handle side for org→project edge so the connector stays horizontal
   * (aligned to org layout midline). See TeamGroupNodeData.overviewOrgEdgeOnTargetSide.
   */
  overviewOrgEdgeOnTargetSide?: 'left' | 'right';
}

const NODE_WIDTH = 220;
const NODE_HEIGHT = 64;
/** Larger project card for org overview (border, single row: icon, name, status). */
export const OVERVIEW_PROJECT_NODE_WIDTH = 268;
/** Org overview project cards: single-row height (no footer). */
export const OVERVIEW_PROJECT_NODE_HEIGHT = 68;

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
  const { projectName = 'Project', projectId, framework, worstSeverity, isTeamNode, slaBreachCount, isExtracting, hasExtractingProjects, neutralStyle, roleBadge, roleBadgeColor, statusBadge, statusBadgeColor, riskGrade, projectsCount, membersCount, assetTierName, overviewOrgEdgeOnTargetSide } =
    (data as unknown as VulnProjectNodeData) ?? {};
  const hasKnownFramework = framework && framework.toLowerCase() !== 'unknown';
  const frameworkIdForIcon = hasKnownFramework ? framework : undefined;
  const useGrey = neutralStyle || isExtracting || (isTeamNode && hasExtractingProjects);
  const colorScheme = useGrey ? (neutralStyle ? neutralScheme : greyExtractingScheme) : getColorScheme(worstSeverity);
  const showSlaBreach = !isExtracting && typeof slaBreachCount === 'number' && slaBreachCount > 0;
  const showTeamRoleBadge = !isExtracting && roleBadge != null && roleBadge !== '' && isTeamNode;
  const showStatusBadge = !isExtracting && statusBadge != null && statusBadge !== '' && !isTeamNode;
  const showTeamRiskGrade = !isExtracting && isTeamNode && (riskGrade ?? 'A+');
  const showProjectRiskGrade = !isExtracting && !isTeamNode && neutralStyle && (riskGrade ?? 'A+');
  const showAssetTierSubtext = !isExtracting && !isTeamNode && assetTierName != null && assetTierName !== '';
  const showCardTooltip = !isTeamNode && neutralStyle;
  const rawStatusColor = statusBadgeColor?.trim() ? statusBadgeColor : (showStatusBadge ? statusBadgeColorFallback(statusBadge) : null);
  const effectiveStatusColor = rawStatusColor && !rawStatusColor.startsWith('#') ? `#${rawStatusColor}` : rawStatusColor;

  /** Org overview: larger project card with border, single row (no dependency footer). */
  const isOverviewProjectCard = Boolean(neutralStyle && !isTeamNode && !isExtracting);
  /** Org overview: larger team card with border, risk badge, bottom bar (x projects, x members), no arrow. */
  const isOverviewTeamCard = Boolean(neutralStyle && isTeamNode && !isExtracting);
  const nodeWidth = (isOverviewProjectCard || isOverviewTeamCard) ? OVERVIEW_PROJECT_NODE_WIDTH : NODE_WIDTH;
  const nodeHeight = (isOverviewProjectCard || isOverviewTeamCard) ? OVERVIEW_PROJECT_NODE_HEIGHT : NODE_HEIGHT;
  const overviewFlatY = VULN_CENTER_NODE_HEIGHT / 2;
  const overviewSideHandleStyle = { top: overviewFlatY, transform: 'translateY(-50%)' } as const;

  return (
    <div className="relative" style={{ minWidth: nodeWidth, minHeight: nodeHeight }}>
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

      {isOverviewTeamCard ? (
        <div className="relative rounded-xl border border-border bg-background-card-header shadow-lg shadow-slate-500/5 h-full flex flex-col overflow-hidden cursor-pointer hover:border-border/80 transition-all">
          {/* Top: Team icon, name, scope pill */}
          <div className="px-4 py-3 flex items-center gap-3 min-w-0 flex-1">
            <div className="flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0 bg-[#1a1c1e] text-muted-foreground">
              <TeamIcon />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-base font-semibold text-foreground truncate leading-tight" title={projectName}>
                {projectName}
              </p>
            </div>
            <GraphScopePill type="team" className="shrink-0" />
          </div>
          {/* Bottom bar: risk badge + project count (icon) + member count (icon) */}
          <div className="border-t border-border px-4 py-2.5 flex items-center gap-3 flex-wrap w-full text-left rounded-b-xl">
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="flex-shrink-0 rounded-md border border-green-500/35 bg-green-500/15 px-2 py-0.5 text-xs font-semibold text-green-500 cursor-default">
                  {riskGrade ?? 'A+'}
                </span>
              </TooltipTrigger>
              <TooltipContent side="top">Calculated risk score based on vulnerabilities, secrets, and code findings.</TooltipContent>
            </Tooltip>
            {typeof projectsCount === 'number' && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="flex items-center gap-1 text-[11px] text-muted-foreground cursor-default">
                    <Folder className="h-3.5 w-3.5 flex-shrink-0" />
                    {projectsCount}
                  </span>
                </TooltipTrigger>
                <TooltipContent side="top">{projectsCount} project{projectsCount === 1 ? '' : 's'}</TooltipContent>
              </Tooltip>
            )}
            {typeof membersCount === 'number' && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="flex items-center gap-1 text-[11px] text-muted-foreground cursor-default">
                    <Users className="h-3.5 w-3.5 flex-shrink-0" />
                    {membersCount}
                  </span>
                </TooltipTrigger>
                <TooltipContent side="top">{membersCount} member{membersCount === 1 ? '' : 's'}</TooltipContent>
              </Tooltip>
            )}
          </div>
        </div>
      ) : isOverviewProjectCard ? (
        <div className="relative rounded-xl border border-border bg-background-card-header shadow-lg shadow-slate-500/5 h-full flex items-center gap-3 min-w-0 overflow-hidden cursor-pointer hover:border-border/80 transition-all px-4 py-3">
          {frameworkIdForIcon ? (
            <span className="flex h-10 w-10 flex-shrink-0 items-center justify-center [&_svg]:text-white">
              <FrameworkIcon frameworkId={frameworkIdForIcon} size={22} className="text-white" />
            </span>
          ) : (
            <span className="flex h-10 w-10 flex-shrink-0 items-center justify-center text-white">
              <Folder className="h-5 w-5" strokeWidth={1.75} />
            </span>
          )}
          <div className="min-w-0 flex-1">
            <p className="text-base font-semibold text-foreground truncate leading-tight" title={projectName}>
              {projectName}
            </p>
          </div>
          <div className="flex items-center justify-end shrink-0">
            {showStatusBadge && (
              <span
                className="inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium"
                style={effectiveStatusColor
                  ? { backgroundColor: `${effectiveStatusColor}20`, color: effectiveStatusColor, borderColor: `${effectiveStatusColor}40` }
                  : { backgroundColor: 'transparent', color: 'var(--muted-foreground)', borderColor: 'rgba(255,255,255,0.2)' }
                }
              >
                {statusBadge}
              </span>
            )}
          </div>
        </div>
      ) : showCardTooltip ? (
        <Tooltip>
          <TooltipTrigger asChild>
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
                  ) : !isTeamNode && showAssetTierSubtext ? (
                    <p className="text-[10px] text-muted-foreground truncate" title={assetTierName ?? undefined}>
                      {assetTierName}
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
              ) : !isTeamNode && showAssetTierSubtext ? (
                <p className="text-[10px] text-muted-foreground truncate" title={assetTierName ?? undefined}>
                  {assetTierName}
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

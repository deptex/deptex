import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Folder, Layers, Loader2, Package } from 'lucide-react';
import { FrameworkIcon } from '../framework-icon';

export type WorstSeverity = 'critical' | 'high' | 'medium' | 'low' | 'none';

export interface ProjectCenterNodeData {
  projectName: string;
  worstVulnerabilitySeverity?: WorstSeverity;
  worstDepscore?: number;
  frameworkName?: string;
  vulnCount?: number;
  semgrepCount?: number;
  secretCount?: number;
  /** When true, show spinner and "Project still extracting" instead of framework/vuln counts */
  isExtracting?: boolean;
  /** Project status from policy (e.g. Compliant, Under Review). Shown as badge. */
  statusName?: string | null;
  statusColor?: string | null;
  /** Org overview: when set, click opens extraction logs sidebar for this project. */
  projectId?: string;
  organizationId?: string;
  /** When true, use org-overview-style card (border, bottom bar with risk grade + deps count). */
  overviewStyle?: boolean;
  /** For overview style: number of direct dependencies (shown in bottom bar). */
  dependenciesCount?: number;
  /** For overview style: asset tier name (e.g. Crown Jewels). */
  assetTierName?: string | null;
  /** For overview style: asset tier badge color. */
  assetTierColor?: string | null;
}

function getColorScheme(worstVulnerabilitySeverity: WorstSeverity) {
  switch (worstVulnerabilitySeverity) {
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

/** Fallback status colors when API doesn't return status_color (matches VulnProjectNode). */
function statusBadgeColorFallback(label: string | null | undefined): string | null {
  if (!label || typeof label !== 'string') return null;
  const lower = label.toLowerCase();
  if (lower.includes('compliant') && !lower.includes('non') && !lower.includes('not')) return '#22c55e';
  if (lower.includes('non-compliant') || lower.includes('not compliant') || lower.includes('non compliant')) return '#ef4444';
  if (lower.includes('under review') || lower.includes('review')) return '#f59e0b';
  if (lower.includes('failed') || lower.includes('error')) return '#ef4444';
  return null;
}

function ProjectCenterNodeComponent({ data }: NodeProps) {
  const {
    projectName = 'Project',
    worstVulnerabilitySeverity = 'none',
    worstDepscore,
    frameworkName,
    vulnCount,
    semgrepCount,
    secretCount,
    isExtracting = false,
    statusName,
    statusColor,
    projectId,
    organizationId,
    overviewStyle = false,
    dependenciesCount,
    assetTierName,
    assetTierColor,
  } = (data as unknown as ProjectCenterNodeData) ?? {};
  const isOrgOverviewExtracting = Boolean(isExtracting && projectId && organizationId);
  const colorScheme = isExtracting ? greyExtractingScheme : getColorScheme(worstVulnerabilitySeverity);
  const hasKnownFramework = frameworkName && frameworkName.toLowerCase() !== 'unknown';
  const frameworkIdForIcon = hasKnownFramework ? frameworkName : undefined;

  const hasCounts = (vulnCount ?? 0) > 0 || (semgrepCount ?? 0) > 0 || (secretCount ?? 0) > 0;
  const statusStyle = statusColor
    ? { backgroundColor: `${statusColor}20`, borderColor: `${statusColor}66` }
    : undefined;
  const showStatusBadge = !isExtracting && statusName != null && statusName !== '';
  const rawStatusColor = statusColor?.trim() ? statusColor : (showStatusBadge ? statusBadgeColorFallback(statusName) : null);
  const effectiveStatusColor = rawStatusColor && !rawStatusColor.startsWith('#') ? `#${rawStatusColor}` : rawStatusColor;

  return (
    <div className="relative cursor-pointer">
      {/* Target handles so edges from team/org can connect (same ids as VulnProjectNode) */}
      <Handle id="top" type="target" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="target" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="target" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="target" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="source-left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      {overviewStyle && !isExtracting ? (
        <div className="relative rounded-lg border border-border bg-background-card shadow-md h-full min-h-[80px] min-w-[260px] flex flex-col overflow-hidden cursor-pointer hover:shadow-lg hover:border-border/80 transition-all">
          <div className="px-3.5 py-3 flex items-center gap-2.5 min-w-0 flex-1">
            {frameworkIdForIcon ? (
              <div className="flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0 bg-[#1a1c1e] text-muted-foreground">
                <FrameworkIcon frameworkId={frameworkIdForIcon} size={18} className="text-current" />
              </div>
            ) : (
              <div className="flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0 bg-[#1a1c1e] text-muted-foreground">
                <Folder className="w-4 h-4" />
              </div>
            )}
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-foreground truncate" title={projectName}>
                {projectName}
              </p>
            </div>
            {showStatusBadge && (
              <span
                className="flex-shrink-0 inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium"
                style={
                  effectiveStatusColor
                    ? { backgroundColor: `${effectiveStatusColor}20`, color: effectiveStatusColor, borderColor: `${effectiveStatusColor}40` }
                    : { backgroundColor: 'transparent', color: 'var(--muted-foreground)', borderColor: 'rgba(255,255,255,0.2)' }
                }
              >
                {statusName}
              </span>
            )}
          </div>
          <div className="border-t border-border px-3 py-2 flex items-center gap-2 flex-wrap w-full text-left rounded-b-lg">
            <span className="flex-shrink-0 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs font-semibold text-emerald-400">
              A+
            </span>
            {typeof dependenciesCount === 'number' && (
              <span className="flex items-center gap-1 text-[11px] text-muted-foreground">
                <Package className="h-3 w-3 flex-shrink-0" />
                {dependenciesCount} direct dep{dependenciesCount === 1 ? '' : 's'}
              </span>
            )}
            <div className="flex-1 min-w-0" />
            {assetTierName && (
              <span className="flex items-center gap-1 text-[11px] text-muted-foreground truncate max-w-[120px]" title={assetTierName}>
                <Layers className="h-3 w-3 flex-shrink-0 text-muted-foreground/80" aria-hidden />
                {assetTierName}
              </span>
            )}
          </div>
        </div>
      ) : isOrgOverviewExtracting ? (
        <div className="relative rounded-lg border border-border bg-background-card shadow-md h-full min-h-[100px] min-w-[268px] flex flex-col overflow-hidden cursor-pointer hover:shadow-lg hover:border-border/80 transition-all">
          {/* Top: icon + name only (like team card) */}
          <div className="px-3.5 py-3 flex items-center gap-2.5 min-w-0 flex-1">
            <div className="flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0 text-muted-foreground">
              <FrameworkIcon frameworkId={frameworkIdForIcon} size={18} className="text-current" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-foreground truncate" title={projectName}>
                {projectName}
              </p>
            </div>
          </div>
          {/* Bottom bar: "Project still extracting" + spinner (like team card's bottom bar) */}
          <div className="border-t border-border px-3 py-2 flex items-center gap-3 flex-wrap w-full text-left rounded-b-lg">
            <span className="text-[11px] text-muted-foreground">Project still extracting</span>
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground flex-shrink-0" aria-hidden />
          </div>
        </div>
      ) : (
        <>
          <div
            className={`relative rounded-xl border-2 shadow-lg overflow-hidden min-w-[260px] ${colorScheme.border} ${colorScheme.shadow}`}
          >
            <div className={`absolute inset-0 rounded-xl blur-xl opacity-20 -z-10 ${colorScheme.glow}`} />
            <div className="bg-background-card px-5 pt-4 pb-4 rounded-xl">
              <div className="flex items-center gap-2.5">
                <div
                  className={`flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0 ${colorScheme.iconBg} ${colorScheme.iconText}`}
                >
                  <FrameworkIcon frameworkId={frameworkIdForIcon} size={20} className="text-current" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-sm font-semibold text-foreground truncate">{projectName}</p>
                    {statusName && (
                      <span
                        className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-medium border flex-shrink-0"
                        style={statusStyle}
                      >
                        {statusName}
                      </span>
                    )}
                  </div>
                  {isExtracting ? (
                    <p className="text-[10px] text-foreground-secondary mt-0.5">Project still extracting</p>
                  ) : hasCounts ? (
                    <p className="text-[10px] text-foreground-secondary mt-0.5">
                      {[
                        vulnCount ? `${vulnCount} vulns` : null,
                        semgrepCount ? `${semgrepCount} code issues` : null,
                        secretCount ? `${secretCount} secrets` : null,
                      ].filter(Boolean).join(' · ')}
                    </p>
                  ) : null}
                </div>
                {isExtracting && (
                  <div className="flex-shrink-0" aria-hidden>
                    <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                  </div>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export const ProjectCenterNode = memo(ProjectCenterNodeComponent);

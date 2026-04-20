import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Package, ChevronDown, GitPullRequest, Loader2, Scale, Ban, AlertTriangle, ShieldCheck } from 'lucide-react';
import type { CenterNodeData } from './useGraphLayout';
import type { BannedVersion } from '../../lib/api';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from '../ui/dropdown-menu';
import { Tooltip, TooltipTrigger, TooltipContent } from '../ui/tooltip';

function CenterNodeComponent({ data }: NodeProps) {
  const {
    name,
    version,
    isDirect,
    worstVulnerabilitySeverity,
    license,
    policies,
    availableVersions,
    selectedVersionId,
    onVersionChange,
    isViewingAlternateVersion,
    bumpPrs,
    canManage,
    bannedVersions,
    bannedVersionsLoading,
    bumpScopeLoading,
    onBanClick,
    onUnbanClick,
    currentVersion,
    safeVersion,
    versionVulnerabilitySummary,
    versionSwitching,
    onOpenVersionsSidebar,
  } = data as unknown as CenterNodeData;

  const hasMultipleVersions = availableVersions && availableVersions.length > 1;

  // Check if a bump PR already exists for the currently viewed version
  const existingPr = isViewingAlternateVersion
    ? bumpPrs.find((pr) => pr.target_version === version)
    : null;

  // Determine colors based on worst vulnerability severity
  const getColorScheme = () => {
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
          glow: 'bg-transparent',
          iconBg: 'bg-primary/15',
          iconText: 'text-primary',
        };
    }
  };

  const colorScheme = getColorScheme();

  // License badge color — always neutral gray
  const licenseLabel = license && license !== 'Unknown' ? license : null;
  const licenseBadgeClass = 'bg-transparent text-foreground-secondary border border-border/60';

  return (
    <div
      className={`
        relative px-5 pt-4 pb-0 rounded-xl border-2 shadow-lg
        bg-background-card
        ${colorScheme.border} ${colorScheme.shadow}
      `}
      style={{ minWidth: 260 }}
    >
      {/* Subtle glow behind the card (only for vulnerability states) */}
      {colorScheme.glow !== 'bg-transparent' && (
        <div
          className={`absolute inset-0 rounded-xl blur-xl opacity-20 -z-10 ${colorScheme.glow}`}
        />
      )}

      <div className="flex items-center gap-3">
        <div
          className={`flex items-center justify-center w-9 h-9 rounded-lg ${colorScheme.iconBg} ${colorScheme.iconText}`}
        >
          <Package className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-foreground truncate">{name}</p>

          {/* When onOpenVersionsSidebar provided: click opens sidebar. Else: dropdown when multiple versions, static text otherwise. */}
          {onOpenVersionsSidebar ? (
            <button
              type="button"
              className="flex items-center gap-1 text-xs text-foreground-secondary font-mono hover:text-foreground transition-colors cursor-pointer rounded px-1 -ml-1 hover:bg-table-hover disabled:cursor-default disabled:hover:bg-transparent"
              onClick={(e) => {
                e.stopPropagation();
                onOpenVersionsSidebar();
              }}
            >
              {version}
              {versionSwitching ? (
                <Loader2 className="h-3 w-3 animate-spin shrink-0 opacity-60" />
              ) : (
                <ChevronDown className="h-3 w-3 opacity-60" />
              )}
            </button>
          ) : hasMultipleVersions ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  className="flex items-center gap-1 text-xs text-foreground-secondary font-mono hover:text-foreground transition-colors cursor-pointer rounded px-1 -ml-1 hover:bg-table-hover disabled:cursor-default disabled:hover:bg-transparent"
                  onClick={(e) => e.stopPropagation()}
                >
                  {version}
                  {versionSwitching ? (
                    <Loader2 className="h-3 w-3 animate-spin shrink-0 opacity-60" />
                  ) : (
                    <ChevronDown className="h-3 w-3 opacity-60" />
                  )}
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="start"
                className="max-h-64 overflow-y-auto min-w-[180px]"
                onPointerDownOutside={(e) => e.stopPropagation()}
              >
                <DropdownMenuLabel className="text-xs text-foreground-secondary">
                  Switch version
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuRadioGroup
                  value={selectedVersionId}
                  onValueChange={(value) => {
                    if (value !== selectedVersionId) {
                      onVersionChange(value);
                    }
                  }}
                >
                  {availableVersions.map((v) => {
                    const isBanned = bannedVersions?.some((b: BannedVersion) => b.banned_version === v.version);
                    const isCurrent = currentVersion != null && v.version === currentVersion;
                    const isSafest = safeVersion != null && v.version === safeVersion;
                    const vulnSummary = versionVulnerabilitySummary?.[v.version];
                    const hasVulnerabilities = vulnSummary ? vulnSummary.hasDirect || vulnSummary.hasTransitive : false;
                    return (
                      <DropdownMenuRadioItem
                        key={v.dependency_version_id}
                        value={v.dependency_version_id}
                        className="font-mono text-xs cursor-pointer flex items-center gap-2 flex-wrap"
                      >
                        <span>{v.version}</span>
                        <span className="flex items-center gap-0.5">
                          {isCurrent && (
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-primary/15 text-green-500 border border-primary/30">
                              Current
                            </span>
                          )}
                          {isBanned && (
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-destructive/15 text-destructive border border-destructive/30">
                              Banned
                            </span>
                          )}
                          {isSafest && (
                            <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-medium bg-primary/15 text-green-500 border border-primary/30">
                              <ShieldCheck className="h-3 w-3 shrink-0" />
                              Recommended
                            </span>
                          )}
                          {hasVulnerabilities && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="inline-flex cursor-default text-destructive">
                                  <AlertTriangle className="h-3 w-3 shrink-0" />
                                </span>
                              </TooltipTrigger>
                              <TooltipContent>Vulnerabilities present (direct or transitive)</TooltipContent>
                            </Tooltip>
                          )}
                        </span>
                      </DropdownMenuRadioItem>
                    );
                  })}
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <p className="text-xs text-foreground-secondary font-mono">{version}</p>
          )}
        </div>
        {/* License badge (right side) */}
        {licenseLabel && (
          <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-[10px] font-medium border flex-shrink-0 ${licenseBadgeClass}`}>
            <Scale className="h-2.5 w-2.5" />
            {licenseLabel}
          </span>
        )}
      </div>

      {/* View PR strip (only shown when a bump PR already exists for the viewed alternate version). */}
      {isViewingAlternateVersion && existingPr && (() => {
        const isBanned = bannedVersions?.some((b: BannedVersion) => b.banned_version === version);
        const banStripBelow = bannedVersionsLoading || isBanned || canManage;
        return (
          <div className={`mt-2 -mx-5 px-5 ${banStripBelow ? 'pt-2.5 pb-1.5' : 'py-2.5'} border-t border-border bg-background-card ${!banStripBelow ? 'rounded-b-xl' : ''}`}>
            <a
              href={existingPr.pr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-center gap-1.5 w-full px-3 py-1.5 rounded-md text-xs font-medium bg-foreground-secondary/5 text-foreground-secondary border border-border hover:bg-foreground-secondary/10 hover:text-foreground transition-colors cursor-pointer"
              onClick={(e) => e.stopPropagation()}
            >
              <GitPullRequest className="h-3 w-3" />
              View PR #{existingPr.pr_number}
            </a>
          </div>
        );
      })()}

      {/* Ban / Banned button — full-width strip; compact (mt-0) only when PR strip is directly above. Show loading when banned status OR bump scope (canManage) is still loading to avoid empty flash when prefetch wins. */}
      {(bannedVersionsLoading || bumpScopeLoading) ? (
        <div className={`${isViewingAlternateVersion && (existingPr || !bannedVersions?.some((b: BannedVersion) => b.banned_version === version)) ? 'mt-0 border-t-0 pt-1.5 pb-2.5' : 'mt-2 border-t border-border py-2.5'} -mx-5 px-5 bg-background-card rounded-b-xl`}>
          <div
            className="flex items-center justify-center gap-1.5 w-full px-3 py-1.5 rounded-md text-xs font-medium bg-foreground-secondary/5 text-foreground-secondary border border-border cursor-default"
            aria-busy="true"
            aria-label="Loading banned status"
          >
            <Loader2 className="h-3 w-3 animate-spin shrink-0" />
            Banned
          </div>
        </div>
      ) : (() => {
        const activeBan = bannedVersions?.find((b: BannedVersion) => b.banned_version === version);
        if (activeBan) {
          const hasPrStripAbove = isViewingAlternateVersion && (existingPr || !bannedVersions?.some((b: BannedVersion) => b.banned_version === version));
          return (
            <div className={`${hasPrStripAbove ? 'mt-0 border-t-0 pt-1.5 pb-2.5' : 'mt-2 border-t border-border py-2.5'} -mx-5 px-5 bg-background-card rounded-b-xl`}>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onUnbanClick?.(activeBan.id);
                }}
                className="flex items-center justify-center gap-1.5 w-full px-3 py-1.5 rounded-md text-xs font-medium bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/15 transition-colors cursor-pointer"
              >
                <Ban className="h-3 w-3" />
                Banned
              </button>
            </div>
          );
        }
        if (canManage) {
          const hasPrStripAbove = isViewingAlternateVersion && (existingPr || !bannedVersions?.some((b: BannedVersion) => b.banned_version === version));
          return (
            <div className={`${hasPrStripAbove ? 'mt-0 border-t-0 pt-1.5 pb-2.5' : 'mt-2 border-t border-border py-2.5'} -mx-5 px-5 bg-background-card rounded-b-xl`}>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onBanClick?.(version);
                }}
                className="flex items-center justify-center gap-1.5 w-full px-3 py-1.5 rounded-md text-xs font-medium bg-destructive/5 text-destructive/70 border border-destructive/15 hover:bg-destructive/10 hover:text-destructive hover:border-destructive/25 transition-colors cursor-pointer"
              >
                <Ban className="h-3 w-3" />
                Ban version
              </button>
            </div>
          );
        }
        return null;
      })()}

      {/* Invisible handles on all four sides for radial edges */}
      <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
    </div>
  );
}

export const CenterNode = memo(CenterNodeComponent);

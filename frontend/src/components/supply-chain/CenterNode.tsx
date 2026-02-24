import { memo, useState } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Package, ChevronDown, GitPullRequest, Loader2, Scale, Ban, CheckCircle2, AlertTriangle, XCircle, ShieldCheck } from 'lucide-react';
import type { CenterNodeData } from './useGraphLayout';
import { api } from '../../lib/api';
import type { BannedVersion } from '../../lib/api';
import { isLicenseAllowed } from '../../lib/compliance-utils';
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
    dependencyId,
    orgId,
    projectId,
    onPrCreated,
    canManage,
    bannedVersions,
    bannedVersionsLoading,
    bumpScopeLoading,
    onBanClick,
    onUnbanClick,
    currentVersion,
    versionSecurityData,
    safeVersion,
    versionVulnerabilitySummary,
    versionSwitching,
    onOpenVersionsSidebar,
  } = data as unknown as CenterNodeData;

  const [creatingPr, setCreatingPr] = useState(false);

  const hasMultipleVersions = availableVersions && availableVersions.length > 1;

  // Check if a bump PR already exists for the currently viewed version
  const existingPr = isViewingAlternateVersion
    ? bumpPrs.find((pr) => pr.target_version === version)
    : null;

  const handleCreatePr = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!orgId || !projectId || !dependencyId || creatingPr) return;
    setCreatingPr(true);
    try {
      const result = await api.createWatchtowerBumpPR(orgId, projectId, dependencyId, version);
      onPrCreated({
        target_version: version,
        pr_url: result.pr_url,
        pr_number: result.pr_number,
      });
    } catch (err) {
      console.error('Failed to create bump PR:', err);
    } finally {
      setCreatingPr(false);
    }
  };

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

  // License badge color
  const licenseAllowed = isLicenseAllowed(license, policies ?? null);
  const licenseLabel = license && license !== 'Unknown' ? license : null;
  let licenseBadgeClass = 'bg-transparent text-foreground-secondary border border-border/60';
  if (licenseAllowed === true) {
    licenseBadgeClass = 'bg-transparent text-foreground-secondary border border-border/60';
  } else if (licenseAllowed === false) {
    licenseBadgeClass = 'bg-destructive/10 text-destructive border-destructive/20';
  }

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
                    const isQuarantined = versionSecurityData?.onWatchtower && versionSecurityData.quarantinedVersions?.includes(v.version);
                    const isSafest = safeVersion != null && v.version === safeVersion;
                    const vulnSummary = versionVulnerabilitySummary?.[v.version];
                    const hasVulnerabilities = vulnSummary ? vulnSummary.hasDirect || vulnSummary.hasTransitive : false;
                    const checks = versionSecurityData?.onWatchtower ? versionSecurityData.securityChecks[v.version] : null;
                    const statusIcon = (s: string | null, label: string) => {
                      const icon =
                        s === 'pass' ? (
                          <CheckCircle2 className="h-3 w-3 text-success shrink-0" />
                        ) : s === 'warning' ? (
                          <AlertTriangle className="h-3 w-3 text-warning shrink-0" />
                        ) : s === 'fail' ? (
                          <XCircle className="h-3 w-3 text-error shrink-0" />
                        ) : null;
                      if (!icon) return null;
                      return (
                        <Tooltip key={label}>
                          <TooltipTrigger asChild>
                            <span className="inline-flex cursor-default">{icon}</span>
                          </TooltipTrigger>
                          <TooltipContent>{label}</TooltipContent>
                        </Tooltip>
                      );
                    };
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
                          {isQuarantined && (
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30">
                              Quarantined
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
                          {checks && (
                            <span className="flex items-center gap-0.5 ml-0.5">
                              {statusIcon(checks.registry_integrity_status, 'Registry')}
                              {statusIcon(checks.install_scripts_status, 'Install scripts')}
                              {statusIcon(checks.entropy_analysis_status, 'Entropy')}
                            </span>
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

      {/* PR action: View PR always shown when it exists; Create PR only when version is not banned — full-width strip matches table header colour. Skip when banned (no PR strip, Ban strip directly follows) */}
      {(() => {
        const isBanned = bannedVersions?.some((b: BannedVersion) => b.banned_version === version);
        const hasPrContent = existingPr || (!isBanned && !bannedVersionsLoading);
        const banStripBelow = isViewingAlternateVersion && (bannedVersionsLoading || isBanned || canManage);
        if (!isViewingAlternateVersion || !hasPrContent) return null;
        return (
          <div className={`mt-2 -mx-5 px-5 ${banStripBelow ? 'pt-2.5 pb-1.5' : 'py-2.5'} border-t border-border bg-[#141618] ${!banStripBelow ? 'rounded-b-xl' : ''}`}>
          {existingPr ? (
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
          ) : !isBanned ? (
            <button
              onClick={handleCreatePr}
              disabled={creatingPr}
              className="flex items-center justify-center gap-1.5 w-full px-3 py-1.5 rounded-md text-xs font-medium bg-foreground-secondary/5 text-foreground-secondary border border-border hover:bg-foreground-secondary/8 hover:text-foreground-secondary transition-colors cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {creatingPr ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <GitPullRequest className="h-3 w-3" />
              )}
              Create PR
            </button>
          ) : null}
        </div>
        );
      })()}

      {/* Ban / Banned button — full-width strip; compact (mt-0) only when PR strip is directly above. Show loading when banned status OR bump scope (canManage) is still loading to avoid empty flash when prefetch wins. */}
      {(bannedVersionsLoading || bumpScopeLoading) ? (
        <div className={`${isViewingAlternateVersion && (existingPr || !bannedVersions?.some((b: BannedVersion) => b.banned_version === version)) ? 'mt-0 border-t-0 pt-1.5 pb-2.5' : 'mt-2 border-t border-border py-2.5'} -mx-5 px-5 bg-[#141618] rounded-b-xl`}>
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
            <div className={`${hasPrStripAbove ? 'mt-0 border-t-0 pt-1.5 pb-2.5' : 'mt-2 border-t border-border py-2.5'} -mx-5 px-5 bg-[#141618] rounded-b-xl`}>
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
            <div className={`${hasPrStripAbove ? 'mt-0 border-t-0 pt-1.5 pb-2.5' : 'mt-2 border-t border-border py-2.5'} -mx-5 px-5 bg-[#141618] rounded-b-xl`}>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onBanClick?.(version);
                }}
                className="flex items-center justify-center gap-1.5 w-full px-3 py-1.5 rounded-md text-xs font-medium bg-foreground-secondary/5 text-foreground-secondary border border-border hover:bg-destructive/10 hover:text-destructive hover:border-destructive/20 transition-colors cursor-pointer"
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

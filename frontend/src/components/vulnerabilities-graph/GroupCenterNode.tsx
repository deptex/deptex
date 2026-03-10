import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Users, AlertTriangle } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { RoleBadge } from '../RoleBadge';

export interface GroupCenterNodeData {
  title: string;
  subtitle?: string;
  /** Optional avatar URL for org/teams; when present for org, show instead of the Users icon. */
  avatarUrl?: string | null;
  /** When true, render healthy (green) styling; otherwise neutral slate. */
  isHealthy?: boolean;
  /** Optional kind hint to distinguish org vs team. */
  kind?: 'org' | 'team';
  /** When set for org center, show as role badge label (e.g. Owner) — passed to RoleBadge as display name. */
  roleBadge?: string | null;
  /** Hex color for role badge — passed to RoleBadge (same as org dropdown). */
  roleBadgeColor?: string | null;
  /** Raw role (owner/admin/member) for RoleBadge when label alone is ambiguous */
  organizationRole?: string | null;
  /** @deprecated Replaced by organizationRiskScore inline text */
  organizationRiskGrade?: string | null;
  /** Org center: average project health 0–100 shown as "Risk score: N/100" */
  organizationRiskScore?: number | null;
  /** Org center: number of alerts to show next to risk score row */
  organizationAlertCount?: number | null;
  /** @deprecated Members toggle removed from UI; kept for type compat. */
  onExpandMembers?: () => void;
  /** @deprecated */
  membersExpanded?: boolean;
  /** @deprecated */
  isExpandingMembers?: boolean;
}

function GroupCenterNodeComponent({ data }: NodeProps) {
  const {
    title = 'Team',
    subtitle,
    avatarUrl,
    isHealthy = false,
    kind,
    roleBadge,
    roleBadgeColor,
    organizationRole,
    organizationRiskScore,
    organizationAlertCount,
  } = (data as unknown as GroupCenterNodeData) ?? {};

  const useNeutralOrgStyle = kind === 'org';
  const borderClass = useNeutralOrgStyle ? 'border-border' : isHealthy ? 'border-primary/60' : 'border-slate-500/40';
  const shadowClass = useNeutralOrgStyle ? 'shadow-slate-500/5' : isHealthy ? 'shadow-primary/10' : 'shadow-slate-500/5';
  const glowBgClass = useNeutralOrgStyle ? 'bg-transparent' : isHealthy ? 'bg-primary' : 'bg-slate-500';
  const iconBgClass = useNeutralOrgStyle ? 'bg-[#1a1c1e]' : isHealthy ? 'bg-primary/15' : 'bg-slate-500/15';
  const iconTextClass = useNeutralOrgStyle ? 'text-muted-foreground' : isHealthy ? 'text-primary' : 'text-slate-600 dark:text-slate-400';
  const showAvatar = kind === 'org' && avatarUrl;

  // Org overview: two-section card — outer border matches divider subtlety (single border-border)
  if (useNeutralOrgStyle) {
    const roleLabel = roleBadge?.trim() || 'Member';
    const roleForBadge = (organizationRole || roleLabel).toLowerCase();

    return (
      <div className="relative">
        <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
        <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
        <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
        <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

        <div
          className={`relative rounded-xl border ${borderClass} shadow-lg ${shadowClass} overflow-hidden min-w-[280px] max-w-[320px] bg-background-card`}
        >
          {/* Top section: avatar + name, then RoleBadge (same as OrganizationSwitcher) */}
          <div className="px-4 pt-4 pb-3">
            <div className="flex items-center gap-3">
              <div
                className={`flex items-center justify-center w-10 h-10 flex-shrink-0 rounded-lg overflow-hidden ${
                  showAvatar ? '' : `${iconBgClass} ${iconTextClass}`
                }`}
              >
                {showAvatar ? (
                  <img src={avatarUrl ?? undefined} alt={title} className="h-full w-full object-contain rounded-lg" />
                ) : (
                  <Users className="w-5 h-5" />
                )}
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-base font-semibold text-foreground truncate leading-tight">{title}</p>
              </div>
            </div>
            <div className="mt-4">
              <RoleBadge
                role={roleForBadge}
                roleDisplayName={roleLabel}
                roleColor={roleBadgeColor ?? null}
              />
            </div>
          </div>

          {/* Separator — same weight as outer border for visual consistency */}
          <div className="border-t border-border w-full" />

          {/* Bottom section: risk score + alert count */}
          <div className="px-4 py-3 flex items-center justify-between gap-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <p className="text-sm cursor-default">
                  <span className="text-foreground-secondary">Risk score: </span>
                  <span className="font-medium tabular-nums text-foreground">
                    {typeof organizationRiskScore === 'number'
                      ? `${organizationRiskScore}/100`
                      : '—/100'}
                  </span>
                </p>
              </TooltipTrigger>
              <TooltipContent side="bottom" sideOffset={6}>
                Average project health score (0–100) from vulnerabilities, compliance, freshness, and code findings.
              </TooltipContent>
            </Tooltip>
            {typeof organizationAlertCount === 'number' && organizationAlertCount > 0 && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="flex items-center gap-1 text-amber-500">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="text-xs font-medium tabular-nums">{organizationAlertCount}</span>
                  </span>
                </TooltipTrigger>
                <TooltipContent side="bottom" sideOffset={6}>
                  {organizationAlertCount} action item{organizationAlertCount !== 1 ? 's' : ''} need attention
                </TooltipContent>
              </Tooltip>
            )}
          </div>
        </div>
      </div>
    );
  }

  // Team / non-org: compact row (keep slightly stronger border for non-org)
  return (
    <div className="relative">
      <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      <div
        className={`relative rounded-xl border-2 ${borderClass} shadow-lg ${shadowClass} overflow-hidden min-w-[260px] bg-background-card`}
      >
        {!useNeutralOrgStyle && <div className={`absolute inset-0 rounded-xl blur-xl opacity-20 -z-10 ${glowBgClass}`} />}
        <div className="bg-background-card px-4 pt-3.5 pb-3.5 rounded-xl">
          <div className="flex items-center gap-2.5">
            <div
              className={`flex items-center justify-center w-9 h-9 flex-shrink-0 rounded-lg overflow-hidden ${
                showAvatar ? '' : `${iconBgClass} ${iconTextClass}`
              }`}
            >
              {showAvatar ? (
                <img src={avatarUrl ?? undefined} alt={title} className="h-full w-full object-contain rounded-lg" />
              ) : (
                <Users className="w-5 h-5" />
              )}
            </div>
            <div className="min-w-0 flex-1 flex flex-col gap-1">
              <p className="text-sm font-semibold text-foreground truncate">{title}</p>
              {subtitle != null && subtitle !== '' && (
                <p className="text-xs text-muted-foreground truncate">{subtitle}</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export const GroupCenterNode = memo(GroupCenterNodeComponent);

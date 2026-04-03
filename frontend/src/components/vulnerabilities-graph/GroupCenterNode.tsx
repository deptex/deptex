import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Users } from 'lucide-react';
import { GraphScopePill } from './GraphScopePill';
import { OrgOverviewSourceHandles } from './overviewOrgFlowHandles';
import { ORG_OVERVIEW_CENTER_WIDTH, ORG_OVERVIEW_CENTER_HEIGHT } from './overviewOrgLayout';

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
  /** @deprecated Org center no longer shows risk row; kept for layout/API compat. */
  organizationRiskScore?: number | null;
  /** @deprecated Org center no longer shows alert row; kept for layout/API compat. */
  organizationAlertCount?: number | null;
  /** @deprecated Org center footer removed; kept for layout/API compat. */
  overviewStatusBadgeLabel?: string;
  overviewStatusBadgeColor?: string | null;
  overviewStatusTooltip?: string;
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
  } = (data as unknown as GroupCenterNodeData) ?? {};

  const useNeutralOrgStyle = kind === 'org';
  const borderClass = useNeutralOrgStyle ? 'border-border' : isHealthy ? 'border-primary/60' : 'border-slate-500/40';
  const shadowClass = useNeutralOrgStyle ? 'shadow-slate-500/5' : isHealthy ? 'shadow-primary/10' : 'shadow-slate-500/5';
  const glowBgClass = useNeutralOrgStyle ? 'bg-transparent' : isHealthy ? 'bg-primary' : 'bg-slate-500';
  const iconBgClass = useNeutralOrgStyle ? 'bg-[#1a1c1e]' : isHealthy ? 'bg-primary/15' : 'bg-slate-500/15';
  const iconTextClass = useNeutralOrgStyle ? 'text-muted-foreground' : isHealthy ? 'text-primary' : 'text-slate-600 dark:text-slate-400';
  const showAvatar = kind === 'org' && avatarUrl;

  // Org overview: identity card (avatar + title); status lives on team/project nodes
  if (useNeutralOrgStyle) {
    const orgConnectY = ORG_OVERVIEW_CENTER_HEIGHT / 2;
    const orgConnectX = ORG_OVERVIEW_CENTER_WIDTH / 2;
    const orgSideHandleStyle = { top: orgConnectY, transform: 'translateY(-50%)' } as const;
    const orgTBHandleStyle = { left: orgConnectX, transform: 'translateX(-50%)' } as const;

    return (
      <div className="relative h-full w-full min-h-0">
        <OrgOverviewSourceHandles />
        {/* Legacy single-point handles (org vuln graph with dep/vuln subgraphs). */}
        <Handle
          id="top"
          type="source"
          position={Position.Top}
          className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
          style={orgTBHandleStyle}
        />
        <Handle
          id="right"
          type="source"
          position={Position.Right}
          className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
          style={orgSideHandleStyle}
        />
        <Handle
          id="bottom"
          type="source"
          position={Position.Bottom}
          className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
          style={orgTBHandleStyle}
        />
        <Handle
          id="left"
          type="source"
          position={Position.Left}
          className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0"
          style={orgSideHandleStyle}
        />

        <div
          className={`relative flex h-full min-h-0 w-full max-w-[min(100vw-2rem,360px)] flex-col overflow-hidden rounded-xl border ${borderClass} bg-background-card-header shadow-lg ${shadowClass}`}
        >
          {/* Organization scope pill — pinned to corner (same as team/project), not inset by the flex row */}
          <div className="pointer-events-auto absolute top-1.5 right-1.5 z-[2]">
            <GraphScopePill type="organization" />
          </div>

          <div className="flex min-h-0 flex-1 flex-col justify-center px-5 py-5">
            <div className="flex min-h-0 items-center gap-4 min-w-0 pr-10">
              <div
                className={`flex items-center justify-center w-14 h-14 flex-shrink-0 rounded-xl overflow-hidden ${
                  showAvatar ? '' : `${iconBgClass} ${iconTextClass}`
                }`}
              >
                {showAvatar ? (
                  <img src={avatarUrl ?? undefined} alt={title} className="h-full w-full object-contain rounded-xl" />
                ) : (
                  <Users className="w-7 h-7" />
                )}
              </div>
              <div className="min-w-0 flex-1 flex items-center">
                <p className="text-xl font-semibold text-foreground truncate leading-tight tracking-tight">{title}</p>
              </div>
            </div>
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

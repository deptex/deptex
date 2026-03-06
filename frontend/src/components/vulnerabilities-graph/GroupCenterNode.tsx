import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Users, Loader2, PanelTopClose } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';

export interface GroupCenterNodeData {
  title: string;
  subtitle?: string;
  /** Optional avatar URL for org/teams; when present for org, show instead of the Users icon. */
  avatarUrl?: string | null;
  /** When true, render healthy (green) styling; otherwise neutral slate. */
  isHealthy?: boolean;
  /** Optional kind hint to distinguish org vs team. */
  kind?: 'org' | 'team';
  /** When set for org center, show as subtext under the organization name (e.g. Owner). */
  roleBadge?: string | null;
  /** Hex color for role subtext (e.g. from organization.role_color). */
  roleBadgeColor?: string | null;
  /** Org center: risk grade shown after org name (e.g. A+). */
  organizationRiskGrade?: string | null;
  /** Org overview: called when user clicks people icon to show/hide members. */
  onExpandMembers?: () => void;
  /** Org overview: whether member nodes are currently shown. */
  membersExpanded?: boolean;
  /** Org overview: true while loading members (show spinner). */
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
    organizationRiskGrade,
    onExpandMembers,
    membersExpanded,
    isExpandingMembers,
  } = (data as unknown as GroupCenterNodeData) ?? {};

  const useNeutralOrgStyle = kind === 'org';
  const borderClass = useNeutralOrgStyle ? 'border-[#22272b]' : isHealthy ? 'border-primary/60' : 'border-slate-500/40';
  const shadowClass = useNeutralOrgStyle ? 'shadow-slate-500/5' : isHealthy ? 'shadow-primary/10' : 'shadow-slate-500/5';
  const glowBgClass = useNeutralOrgStyle ? 'bg-transparent' : isHealthy ? 'bg-primary' : 'bg-slate-500';
  const iconBgClass = useNeutralOrgStyle ? 'bg-[#1a1c1e]' : isHealthy ? 'bg-primary/15' : 'bg-slate-500/15';
  const iconTextClass = useNeutralOrgStyle ? 'text-muted-foreground' : isHealthy ? 'text-primary' : 'text-slate-600 dark:text-slate-400';
  const showAvatar = kind === 'org' && avatarUrl;
  const showMembersToggle = kind === 'org' && typeof onExpandMembers === 'function';

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
                <img
                  src={avatarUrl ?? undefined}
                  alt={title}
                  className="h-full w-full object-contain rounded-lg"
                />
              ) : (
                <Users className="w-5 h-5" />
              )}
            </div>
            <div className="min-w-0 flex-1 flex flex-col gap-1">
              <p className="text-sm font-semibold text-foreground truncate">{title}</p>
              {kind === 'org' && roleBadge != null && roleBadge !== '' ? (
                <p className="text-xs text-muted-foreground truncate">{roleBadge}</p>
              ) : (
                subtitle != null && subtitle !== '' && (
                  <p className="text-xs text-muted-foreground truncate">{subtitle}</p>
                )
              )}
            </div>
            {kind === 'org' && (organizationRiskGrade ?? 'A+') && (
              <span className="flex-shrink-0 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-sm font-semibold text-emerald-400">
                {organizationRiskGrade ?? 'A+'}
              </span>
            )}
            {showMembersToggle && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onExpandMembers!();
                    }}
                    disabled={isExpandingMembers}
                    className="flex-shrink-0 flex items-center justify-center w-8 h-8 rounded-md text-muted-foreground hover:text-foreground hover:bg-background-subtle transition-colors disabled:opacity-60"
                    aria-label={membersExpanded ? 'Hide members' : 'Expand members'}
                  >
                    {isExpandingMembers ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : membersExpanded ? (
                      <PanelTopClose className="h-4 w-4" />
                    ) : (
                      <Users className="h-4 w-4" />
                    )}
                  </button>
                </TooltipTrigger>
                <TooltipContent side="bottom" sideOffset={6}>
                  {isExpandingMembers ? 'Loading…' : membersExpanded ? 'Hide members' : 'Expand members'}
                </TooltipContent>
              </Tooltip>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export const GroupCenterNode = memo(GroupCenterNodeComponent);

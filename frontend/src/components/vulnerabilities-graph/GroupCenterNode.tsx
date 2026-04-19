import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Users } from 'lucide-react';

export interface GroupCenterNodeData {
  title: string;
  subtitle?: string;
  /** Optional avatar URL for org/teams; when present for org, show instead of the Users icon. */
  avatarUrl?: string | null;
  /** When true, render healthy (green) styling; otherwise neutral slate. */
  isHealthy?: boolean;
  /** Optional kind hint to distinguish org vs team. */
  kind?: 'org' | 'team';
}

function GroupCenterNodeComponent({ data }: NodeProps) {
  const {
    title = 'Team',
    subtitle,
    avatarUrl,
    isHealthy = false,
    kind,
  } = (data as unknown as GroupCenterNodeData) ?? {};

  const borderClass = isHealthy ? 'border-primary/60' : 'border-slate-500/40';
  const shadowClass = isHealthy ? 'shadow-primary/10' : 'shadow-slate-500/5';
  const glowBgClass = isHealthy ? 'bg-primary' : 'bg-slate-500';
  const iconBgClass = isHealthy ? 'bg-primary/15' : 'bg-slate-500/15';
  const iconTextClass = isHealthy ? 'text-primary' : 'text-slate-600 dark:text-slate-400';
  const showAvatar = kind === 'org' && avatarUrl;

  return (
    <div className="relative">
      <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      <div
        className={`relative rounded-xl border-2 ${borderClass} shadow-lg ${shadowClass} overflow-hidden min-w-[260px] bg-background-card`}
      >
        <div className={`absolute inset-0 rounded-xl blur-xl opacity-20 -z-10 ${glowBgClass}`} />
        <div className="bg-background-card px-5 pt-4 pb-4 rounded-xl">
          <div className="flex items-center gap-2.5">
            <div
              className={`flex items-center justify-center w-9 h-9 rounded-lg flex-shrink-0 ${iconBgClass} ${iconTextClass}`}
            >
              {showAvatar ? (
                <img
                  src={avatarUrl ?? undefined}
                  alt={title}
                  className="w-8 h-8 rounded-full object-cover"
                />
              ) : (
                <Users className="w-5 h-5" />
              )}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-foreground truncate">{title}</p>
              {subtitle != null && subtitle !== '' && (
                <p className="text-xs text-muted-foreground truncate mt-0.5">{subtitle}</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export const GroupCenterNode = memo(GroupCenterNodeComponent);

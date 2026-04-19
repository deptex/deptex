import { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Users } from 'lucide-react';
import { GraphScopePill } from './GraphScopePill';
import { OrgOverviewSourceHandles } from './overviewOrgFlowHandles';
import { ORG_OVERVIEW_CENTER_WIDTH, ORG_OVERVIEW_CENTER_HEIGHT } from './overviewOrgLayout';
import { RoleBadge } from '../RoleBadge';

export interface GroupCenterNodeData {
  title: string;
  subtitle?: string;
  avatarUrl?: string | null;
  isHealthy?: boolean;
  kind?: 'org' | 'team';
  roleBadge?: string | null;
  roleBadgeColor?: string | null;
  organizationRole?: string | null;
  /** @deprecated */
  organizationRiskGrade?: string | null;
  /** @deprecated Org center no longer shows risk row; kept for layout/API compat. */
  organizationRiskScore?: number | null;
  /** @deprecated */
  organizationAlertCount?: number | null;
  overviewStatusBadgeLabel?: string;
  overviewStatusBadgeColor?: string | null;
  overviewStatusTooltip?: string;
  /** @deprecated */
  onExpandMembers?: () => void;
  /** @deprecated */
  membersExpanded?: boolean;
  /** @deprecated */
  isExpandingMembers?: boolean;
  /** Showcase variant (1–10). When absent, renders the production design. */
  variant?: number;
  projectCount?: number;
  teamCount?: number;
  memberCount?: number;
  plan?: string;
}

function ScoreRing({ score, size = 60 }: { score: number; size?: number }) {
  const r = (size - 10) / 2;
  const circ = 2 * Math.PI * r;
  const filled = (Math.max(0, Math.min(score, 100)) / 100) * circ;
  const color = score >= 80 ? '#22c55e' : score >= 50 ? '#f59e0b' : '#ef4444';
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ flexShrink: 0 }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="5" />
      <circle
        cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="5"
        strokeDasharray={`${filled} ${circ - filled}`} strokeLinecap="round"
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
      <text x={size / 2} y={size / 2 + 5} textAnchor="middle" fill="white" fontSize="13" fontWeight="700">{score}</text>
    </svg>
  );
}

function GroupCenterNodeComponent({ data }: NodeProps) {
  const {
    title = 'Team',
    subtitle,
    avatarUrl,
    isHealthy = false,
    kind,
    roleBadge,
    organizationRiskScore,
    overviewStatusBadgeLabel,
    overviewStatusBadgeColor,
    variant,
    projectCount = 0,
    teamCount = 0,
    memberCount = 0,
  } = (data as unknown as GroupCenterNodeData) ?? {};

  const useNeutralOrgStyle = kind === 'org';
  const borderClass = useNeutralOrgStyle ? 'border-border' : isHealthy ? 'border-primary/60' : 'border-slate-500/40';
  const shadowClass = useNeutralOrgStyle ? 'shadow-slate-500/5' : isHealthy ? 'shadow-primary/10' : 'shadow-slate-500/5';
  const glowBgClass = useNeutralOrgStyle ? 'bg-transparent' : isHealthy ? 'bg-primary' : 'bg-slate-500';
  const iconBgClass = useNeutralOrgStyle ? 'bg-[#1a1c1e]' : isHealthy ? 'bg-primary/15' : 'bg-slate-500/15';
  const iconTextClass = useNeutralOrgStyle ? 'text-muted-foreground' : isHealthy ? 'text-primary' : 'text-slate-600 dark:text-slate-400';
  const showAvatar = kind === 'org' && !!avatarUrl;

  // ─── Org overview ────────────────────────────────────────────────────────────
  if (useNeutralOrgStyle) {
    const orgConnectY = ORG_OVERVIEW_CENTER_HEIGHT / 2;
    const orgConnectX = ORG_OVERVIEW_CENTER_WIDTH / 2;
    const orgSideHandleStyle = { top: orgConnectY, transform: 'translateY(-50%)' } as const;
    const orgTBHandleStyle = { left: orgConnectX, transform: 'translateX(-50%)' } as const;

    const score = organizationRiskScore ?? 0;
    const statusLabel = overviewStatusBadgeLabel ?? '';
    const statusColor = overviewStatusBadgeColor ?? '#22c55e';
    const scoreColor = score >= 80 ? '#22c55e' : score >= 50 ? '#f59e0b' : '#ef4444';
    const roleLabel = roleBadge ?? '';
    const planLabel = (data as unknown as GroupCenterNodeData).plan ?? '';
    const planDisplay = planLabel ? planLabel.charAt(0).toUpperCase() + planLabel.slice(1).toLowerCase() : '';


    const handles = (
      <>
        <OrgOverviewSourceHandles />
        <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" style={orgTBHandleStyle} />
        <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" style={orgSideHandleStyle} />
        <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" style={orgTBHandleStyle} />
        <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" style={orgSideHandleStyle} />
      </>
    );

    const vBadge = (v: number) => (
      <span className="absolute top-1.5 left-2 z-10 text-[9px] font-mono bg-white/10 text-white/40 px-1.5 py-0.5 rounded leading-none pointer-events-none select-none">
        V{v}
      </span>
    );

    const AvatarOrIcon = ({ size = 56, rounded = 'rounded-xl' }: { size?: number; rounded?: string }) => (
      <div
        className={`flex items-center justify-center flex-shrink-0 overflow-hidden ${rounded} ${showAvatar ? '' : `${iconBgClass} ${iconTextClass}`}`}
        style={{ width: size, height: size }}
      >
        {showAvatar
          ? <img src={avatarUrl ?? undefined} alt={title} className="h-full w-full object-contain" style={{ borderRadius: 'inherit' }} />
          : <Users style={{ width: size * 0.5, height: size * 0.5 }} />}
      </div>
    );

    // ── Production design ─────────────────────────────────────────────────────
    if (!variant) {
      return (
        <div className="relative h-full w-full min-h-0">
          {handles}
          <div className="pointer-events-auto absolute top-1.5 right-1.5 z-[2]">
            <GraphScopePill type="organization" />
          </div>
          <div className={`relative flex h-full w-full flex-col justify-between overflow-hidden rounded-xl border ${borderClass} bg-background-card-header shadow-lg px-5 py-5`}>
            <div className="flex items-center gap-4 min-w-0">
              <AvatarOrIcon size={40} />
              <div className="min-w-0 flex-1">
                <p className="text-lg font-semibold text-foreground truncate leading-tight tracking-tight">{title}</p>
                {planDisplay && (
                  <p className="text-xs text-muted-foreground mt-1">{planDisplay} plan</p>
                )}
              </div>
            </div>
            <div className="flex items-center gap-1.5 pl-[4px]">
              <span className="w-2 h-2 rounded-full flex-shrink-0 bg-green-500" />
              <span className="text-xs font-medium text-green-500">Active</span>
            </div>
          </div>
        </div>
      );
    }

    // ── V2: Role Badge Centred Right ──────────────────────────────────────────
    // Avatar + name (top) / stats (bottom) on left; role badge vertically centred on right.
    if (variant === 2) {
      return (
        <div className="relative h-full w-full min-h-0">
          {handles}
          {vBadge(2)}
          <div className={`relative flex h-full w-full overflow-hidden rounded-xl border ${borderClass} bg-background-card-header shadow-lg px-5 py-6`}>
            <AvatarOrIcon size={52} />
            <div className="flex-1 min-w-0 flex flex-col justify-between ml-4">
              <p className="text-xl font-semibold text-foreground truncate leading-tight tracking-tight">{title}</p>
              <p className="text-[11px] text-muted-foreground">{projectCount} projects · {teamCount} teams</p>
            </div>
            {roleLabel && (
              <div className="flex items-center flex-shrink-0 pl-4">
                <RoleBadge
                  role={(data as unknown as GroupCenterNodeData).organizationRole ?? roleLabel}
                  roleDisplayName={roleLabel}
                  roleColor={(data as unknown as GroupCenterNodeData).roleBadgeColor ?? null}
                />
              </div>
            )}
          </div>
        </div>
      );
    }

    // ── V6: Org Monogram ──────────────────────────────────────────────────────
    // Typographic identity — initial/avatar top; role + plan middle; stats + health score bottom.
    if (variant === 6) {
      const initial = title.charAt(0).toUpperCase();
      return (
        <div className="relative h-full w-full min-h-0">
          {handles}
          {vBadge(6)}
          <div className={`relative flex h-full w-full flex-col justify-between overflow-hidden rounded-xl border ${borderClass} bg-background-card-header shadow-lg px-5 py-6`}>
            <div className="flex items-center gap-4 min-w-0">
              <div className="flex items-center justify-center w-14 h-14 rounded-xl flex-shrink-0 font-black text-2xl"
                style={{ backgroundColor: `${statusColor}18`, color: statusColor, border: `1px solid ${statusColor}30` }}>
                {showAvatar
                  ? <img src={avatarUrl ?? undefined} alt={title} className="h-full w-full object-contain rounded-xl" />
                  : initial}
              </div>
              <p className="text-xl font-semibold text-foreground truncate flex-1 min-w-0 leading-tight tracking-tight">{title}</p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              {roleLabel && (
                <RoleBadge
                  role={(data as unknown as GroupCenterNodeData).organizationRole ?? roleLabel}
                  roleDisplayName={roleLabel}
                  roleColor={(data as unknown as GroupCenterNodeData).roleBadgeColor ?? null}
                />
              )}
              {planDisplay && (
                <span className="px-2 py-0.5 rounded text-[10px] font-medium border border-white/15 bg-white/5 text-muted-foreground">{planDisplay}</span>
              )}
            </div>
            <div className="flex items-center justify-between">
              <p className="text-[11px] text-muted-foreground">{projectCount} projects · {teamCount} teams</p>
              {score > 0 && (
                <span className="text-sm font-bold tabular-nums" style={{ color: scoreColor }}>{score}</span>
              )}
            </div>
          </div>
        </div>
      );
    }

    // ── V8: Full Stack ────────────────────────────────────────────────────────
    // Name top; role badge + plan + status middle; full stats bottom.
    if (variant === 8) {
      return (
        <div className="relative h-full w-full min-h-0">
          {handles}
          {vBadge(8)}
          <div className={`relative flex h-full w-full flex-col justify-between overflow-hidden rounded-xl border ${borderClass} bg-background-card-header shadow-lg px-5 py-6`}>
            <div className="flex items-center gap-3 min-w-0">
              <AvatarOrIcon size={52} />
              <p className="text-xl font-semibold text-foreground truncate flex-1 min-w-0 leading-tight tracking-tight">{title}</p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              {roleLabel && (
                <RoleBadge
                  role={(data as unknown as GroupCenterNodeData).organizationRole ?? roleLabel}
                  roleDisplayName={roleLabel}
                  roleColor={(data as unknown as GroupCenterNodeData).roleBadgeColor ?? null}
                />
              )}
              {planDisplay && (
                <span className="px-2 py-0.5 rounded text-xs font-medium border flex-shrink-0"
                  style={{ color: '#a78bfa', backgroundColor: 'rgba(167,139,250,0.1)', borderColor: 'rgba(167,139,250,0.25)' }}>
                  {planDisplay}
                </span>
              )}
              {statusLabel && (
                <span className="flex items-center gap-1 text-[10px] font-medium flex-shrink-0" style={{ color: statusColor }}>
                  <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: statusColor }} />
                  {statusLabel}
                </span>
              )}
            </div>
            <p className="text-[11px] text-muted-foreground">
              {projectCount} projects · {teamCount} teams · {memberCount} members
            </p>
          </div>
        </div>
      );
    }

    // ── V9: Stacked + Plan ────────────────────────────────────────────────────
    // Name + plan-chip top right; role badge middle; stats bottom.
    if (variant === 9) {
      return (
        <div className="relative h-full w-full min-h-0">
          {handles}
          {vBadge(9)}
          <div className={`relative flex h-full w-full flex-col justify-between overflow-hidden rounded-xl border ${borderClass} bg-background-card-header shadow-lg px-5 py-6`}>
            <div className="flex items-start gap-3 min-w-0">
              <AvatarOrIcon size={48} />
              <div className="flex-1 min-w-0 flex items-start justify-between gap-2">
                <p className="text-xl font-semibold text-foreground truncate leading-tight tracking-tight flex-1 min-w-0">{title}</p>
                {planDisplay && (
                  <span className="flex-shrink-0 mt-0.5 px-2 py-0.5 rounded text-[10px] font-medium border border-white/15 bg-white/5 text-muted-foreground">
                    {planDisplay}
                  </span>
                )}
              </div>
            </div>
            {roleLabel && (
              <div>
                <RoleBadge
                  role={(data as unknown as GroupCenterNodeData).organizationRole ?? roleLabel}
                  roleDisplayName={roleLabel}
                  roleColor={(data as unknown as GroupCenterNodeData).roleBadgeColor ?? null}
                />
              </div>
            )}
            <p className="text-[11px] text-muted-foreground">{projectCount} projects · {teamCount} teams</p>
          </div>
        </div>
      );
    }

    // ── V10: Minimal Glow ─────────────────────────────────────────────────────
    // Status-tinted border; name top; status dot + role middle; stats + plan bottom.
    {
      return (
        <div className="relative h-full w-full min-h-0">
          {handles}
          {vBadge(10)}
          <div
            className="relative flex h-full w-full flex-col justify-between overflow-hidden rounded-xl bg-background-card-header shadow-lg px-5 py-6"
            style={{
              border: `1px solid ${statusColor ? `${statusColor}50` : 'rgba(63,63,70,1)'}`,
              boxShadow: statusColor ? `0 0 0 1px ${statusColor}15, 0 4px 24px ${statusColor}12` : undefined,
            }}
          >
            <div className="flex items-center gap-4 min-w-0">
              <AvatarOrIcon size={52} />
              <p className="text-xl font-semibold text-foreground truncate flex-1 min-w-0 leading-tight tracking-tight">{title}</p>
            </div>
            <div className="flex items-center gap-2">
              {statusLabel && (
                <span className="flex items-center gap-1.5 text-[11px] font-medium" style={{ color: statusColor }}>
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: statusColor }} />
                  {statusLabel}
                </span>
              )}
              {statusLabel && roleLabel && <span className="text-muted-foreground/30 text-xs">·</span>}
              {roleLabel && <span className="text-[11px] text-muted-foreground">{roleLabel}</span>}
            </div>
            <div className="flex items-center justify-between">
              <p className="text-[11px] text-muted-foreground">{projectCount} projects · {teamCount} teams</p>
              {planDisplay && <span className="text-[10px] text-muted-foreground/50">{planDisplay}</span>}
            </div>
          </div>
        </div>
      );
    }
  }

  // ─── Team / non-org ───────────────────────────────────────────────────────────
  return (
    <div className="relative">
      <Handle id="top" type="source" position={Position.Top} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="right" type="source" position={Position.Right} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="bottom" type="source" position={Position.Bottom} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />
      <Handle id="left" type="source" position={Position.Left} className="!opacity-0 !w-0 !h-0 !min-w-0 !min-h-0 !border-0 !p-0" />

      <div className={`relative rounded-xl border-2 ${borderClass} shadow-lg ${shadowClass} overflow-hidden min-w-[260px] bg-background-card`}>
        {!useNeutralOrgStyle && <div className={`absolute inset-0 rounded-xl blur-xl opacity-20 -z-10 ${glowBgClass}`} />}
        <div className="bg-background-card px-4 pt-3.5 pb-3.5 rounded-xl">
          <div className="flex items-center gap-2.5">
            <div className={`flex items-center justify-center w-9 h-9 flex-shrink-0 rounded-lg overflow-hidden ${showAvatar ? '' : `${iconBgClass} ${iconTextClass}`}`}>
              {showAvatar
                ? <img src={avatarUrl ?? undefined} alt={title} className="h-full w-full object-contain rounded-lg" />
                : <Users className="w-5 h-5" />}
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

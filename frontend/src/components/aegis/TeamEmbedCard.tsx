import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import { api, type TeamWithRole } from '../../lib/api';
import { cn } from '../../lib/utils';
import { TeamGroupChip, teamGroupChipFrameClass } from '../TeamIcon';

function RoleBadge({
  label,
  colorHex,
}: {
  label: string | null | undefined;
  colorHex: string | null | undefined;
}) {
  if (!label) return null;
  let border = '';
  let bg = '';
  const raw = typeof colorHex === 'string' ? colorHex.trim() : '';
  const hex =
    raw && raw.startsWith('#')
      ? raw
      : raw && /^[0-9a-fA-F]{3,8}$/.test(raw)
        ? `#${raw}`
        : '';
  if (hex && hex.length >= 4) {
    border = hex;
    const r =
      hex.length >= 7
        ? parseInt(hex.slice(1, 3), 16)
        : parseInt(hex[1] + hex[1], 16);
    const g =
      hex.length >= 7 ? parseInt(hex.slice(3, 5), 16) : parseInt(hex[2] + hex[2], 16);
    const b =
      hex.length >= 7 ? parseInt(hex.slice(5, 7), 16) : parseInt(hex[3] + hex[3], 16);
    bg = `rgba(${r}, ${g}, ${b}, 0.12)`;
  }
  return (
    <span
      title={label}
      className={cn(
        'inline-flex max-w-full shrink-0 truncate rounded px-2 py-0.5 text-xs font-medium',
        hex ? '' : 'border border-foreground-secondary/40 bg-foreground-secondary/10 text-foreground-secondary',
      )}
      style={hex ? { borderColor: border, borderWidth: 1, backgroundColor: bg, color: 'inherit' } : undefined}
    >
      {label}
    </span>
  );
}

interface TeamEmbedCardProps {
  organizationId: string;
  teamId: string;
}

/** Same shell as org overview team satellite (`VulnProjectNode` `isOverviewTeamCard`). */
const embedTeamCardShell =
  'my-2 block rounded-lg border border-border bg-background-card-header shadow-lg shadow-slate-500/5 text-left overflow-hidden transition-all hover:border-border/80';

export function TeamEmbedCard({ organizationId, teamId }: TeamEmbedCardProps) {
  const overviewTeamSidebarTo = useMemo(
    () => ({
      pathname: `/organizations/${organizationId}/overview`,
      search: new URLSearchParams({
        sidebar: 'team',
        teamId,
        tab: 'findings',
      }).toString(),
    }),
    [organizationId, teamId],
  );

  const [team, setTeam] = useState<TeamWithRole | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    setTeam(null);
    api
      .getTeam(organizationId, teamId, true)
      .then((t) => {
        if (!cancelled) setTeam(t);
      })
      .catch(() => {
        if (!cancelled) setError('Could not load this team.');
      });
    return () => {
      cancelled = true;
    };
  }, [organizationId, teamId]);

  const focusRing = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 group';

  const rowClass = 'flex items-center justify-between gap-3 px-4 py-3';

  const leftIcon = (t: TeamWithRole) =>
    t.avatar_url ? (
      <div
        className={cn(
          'flex h-8 w-8 shrink-0 overflow-hidden',
          teamGroupChipFrameClass,
        )}
      >
        <img src={t.avatar_url} alt="" className="h-full w-full object-cover" />
      </div>
    ) : (
      <TeamGroupChip />
    );

  if (error) {
    return (
      <Link to={overviewTeamSidebarTo} className={cn(embedTeamCardShell, focusRing)}>
        <div className={cn(rowClass, 'border-b border-border/60 px-4 py-2 text-xs text-foreground-muted')}>
          {error}
        </div>
      </Link>
    );
  }

  if (!team) {
    return (
      <Link to={overviewTeamSidebarTo} className={cn(embedTeamCardShell, focusRing)}>
        <div className={rowClass}>
          <div className="flex min-w-0 flex-1 items-center gap-3">
            <div className={cn('h-8 w-8 shrink-0 animate-pulse', teamGroupChipFrameClass)} />
            <div className="h-4 w-32 rounded bg-foreground/[0.08]" />
            <div className="h-5 w-20 rounded bg-foreground/[0.08]" />
          </div>
          <div className="h-5 w-5 shrink-0 rounded bg-foreground/[0.08]" />
        </div>
      </Link>
    );
  }

  return (
    <Link to={overviewTeamSidebarTo} className={cn(embedTeamCardShell, focusRing)}>
      <div className={rowClass}>
        <div className="flex min-w-0 flex-1 items-center gap-3">
          {leftIcon(team)}
          <h3 className="truncate text-base font-semibold leading-tight text-foreground" title={team.name}>
            {team.name}
          </h3>
          <RoleBadge label={team.role_display_name ?? null} colorHex={team.role_color ?? null} />
        </div>
        <ChevronRight className="ml-1 h-5 w-5 shrink-0 text-foreground-secondary transition-colors group-hover:text-foreground" />
      </div>
    </Link>
  );
}

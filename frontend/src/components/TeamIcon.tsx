import { Users, UsersRound } from 'lucide-react';

/**
 * Border / fill shell shared by org overview team satellite icon and matching chat embed avatars.
 * Contrast assumes parent row uses `bg-background-card-header`.
 */
export const overviewTeamSatelliteInsetFrameClass =
  'rounded-lg border border-[#22272b] bg-[#1a1c1e] shadow-[inset_0_1px_0_rgb(255_255_255/0.05)]';

/** Org overview team satellite chip (neutral graph): same rim/fill/icon as canvas nodes. */
export const overviewTeamSatelliteChipClass =
  'flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[#22272b] bg-[#1a1c1e] shadow-[inset_0_1px_0_rgb(255_255_255/0.05)] text-muted-foreground';

export function OverviewTeamSatelliteChip() {
  return (
    <div className={overviewTeamSatelliteChipClass}>
      <Users className="h-4 w-4 shrink-0" aria-hidden strokeWidth={1.5} />
    </div>
  );
}

/** Frame for team avatars matching org graph TeamGroupNode chip. */
export const teamGroupChipFrameClass =
  'rounded-md border border-border/70 bg-muted/40';

/** Chip used by org graph TeamGroupNode and the matching chat embed avatar fallback. */
export const teamGroupChipClass =
  'flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border/70 bg-muted/40 text-muted-foreground';

export function TeamGroupChip() {
  return (
    <div className={teamGroupChipClass} aria-hidden>
      <UsersRound className="h-4 w-4" strokeWidth={1.6} />
    </div>
  );
}

/** Smaller inset used for team lists / sidebars (not org graph satellites). */
export function TeamIcon({ className = '' }: { className?: string }) {
  return (
    <div
      className={`flex items-center justify-center w-8 h-8 rounded-lg flex-shrink-0 bg-[#1a1c1e] text-muted-foreground ${className}`.trim()}
    >
      <Users className="w-4 h-4" />
    </div>
  );
}

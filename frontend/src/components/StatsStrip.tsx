import { cn } from '../lib/utils';

export interface StatCardData {
  icon: React.ReactNode;
  iconBg: string;
  iconColor: string;
  label: string;
  value: string | number;
  sub?: string;
  badge?: React.ReactNode;
  onClick?: () => void;
}

interface StatsStripProps {
  cards: StatCardData[];
  loading?: boolean;
}

export function StatsStrip({ cards, loading }: StatsStripProps) {
  if (loading) {
    return (
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="rounded-lg border border-border bg-background-card p-4 animate-pulse">
            <div className="flex items-center justify-between mb-3">
              <div className="h-3 w-16 rounded bg-muted/60" />
              <div className="h-7 w-7 rounded-md bg-muted/40" />
            </div>
            <div className="h-7 w-12 rounded bg-muted/60 mb-1" />
            <div className="h-3 w-24 rounded bg-muted/40" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className={cn('grid gap-3', cards.length <= 4 ? 'grid-cols-2 sm:grid-cols-4' : 'grid-cols-2 sm:grid-cols-3 lg:grid-cols-5')}>
      {cards.map((card, i) => (
        <button
          key={i}
          onClick={card.onClick}
          disabled={!card.onClick}
          className={cn(
            'group text-left rounded-lg border border-border bg-background-card p-4 transition-colors',
            card.onClick && 'hover:border-border/80 hover:bg-background-card/80 cursor-pointer',
            !card.onClick && 'cursor-default',
          )}
        >
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary">{card.label}</span>
            <div className={cn('flex h-7 w-7 items-center justify-center rounded-md', card.iconBg)}>
              <span className={card.iconColor}>{card.icon}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <p className="text-2xl font-bold text-foreground tabular-nums">{card.value}</p>
            {card.badge}
          </div>
          {card.sub && <p className="text-xs text-foreground-secondary mt-0.5">{card.sub}</p>}
        </button>
      ))}
    </div>
  );
}

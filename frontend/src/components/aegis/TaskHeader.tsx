import { ChevronRight, Circle, CircleCheck, CircleX, Loader2 } from 'lucide-react';
import type { AegisTask } from '../../lib/aegis-api';

// The compact task row pinned at the top of a task chat — a single line
// ("Started task" + status glyph + chevron) that opens the task detail panel.
// It's a START marker, not a live status label — the glyph and the detail panel
// carry the actual state. Matches the app's clickable-row affordance.

// Neutral (gray) status glyph: the row stays monochrome so the conversation —
// not the header — carries any color. (Unlike the sidebar's colored TaskIcon.)
function RowGlyph({ status }: { status: AegisTask['status'] }) {
  const cls = 'h-4 w-4 shrink-0 text-foreground-secondary';
  if (status === 'working') return <Loader2 className={`${cls} animate-spin`} />;
  if (status === 'completed' || status === 'completed_with_failures')
    return <CircleCheck className={cls} />;
  // A user Stop ('cancelled') is not a failure — a neutral dot, not the X.
  if (status === 'failed' || status === 'declined') return <CircleX className={cls} />;
  return <Circle className={cls} />;
}

export function TaskHeader({ task, onOpenDetails }: { task: AegisTask; onOpenDetails?: () => void }) {
  return (
    <div className="px-4 pt-4 pb-1">
      <div className="mx-auto max-w-3xl">
        <button
          type="button"
          onClick={onOpenDetails}
          className="group flex w-full items-center gap-2.5 rounded-lg border border-border bg-background-card px-4 py-3 text-left transition-colors hover:border-foreground-secondary/30"
        >
          <RowGlyph status={task.status} />
          <span className="text-sm font-medium text-foreground">Started task</span>
          <ChevronRight className="ml-auto h-4 w-4 shrink-0 text-foreground-secondary transition-colors group-hover:text-foreground" />
        </button>
      </div>
    </div>
  );
}

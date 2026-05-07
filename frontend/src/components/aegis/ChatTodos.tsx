import { useEffect, useMemo, useState } from 'react';
import type { UIMessage } from 'ai';
import { CheckCircle2, ChevronDown, Circle, Loader2, Pause, X } from 'lucide-react';
import { cn } from '../../lib/utils';
import { deriveTodos, type Todo } from '../../lib/aegis-todos';

interface ChatTodosProps {
  messages: UIMessage[];
  streaming: boolean;
}

// Sticky strip above the composer that shows the agent's declared plan for
// the current turn. Visual shell mirrors SendQueuePanel — same rounded-2xl
// bg-background-card shadow-lg shape, same chevron-collapse header, same
// row geometry — so the two cards read as siblings stacked above the
// composer.
//
// Visibility matrix:
//   streaming + non-terminal → live: Loader2 spins on in_progress
//   streaming + terminal     → Done pill, hold 1.5s, fade
//   ended    + non-terminal  → stalled: muted rows + Dismiss-X
//   ended    + terminal      → Done pill, hold 1.5s, fade
//
// Source: only the LAST message, and only if it's an assistant. A trailing
// user message means we're between turns (the next assistant hasn't started
// yet) — todos from a prior assistant turn are stale and shouldn't render.
// This matters on resume: seed-load draws from DB where the in-flight
// assistant turn hasn't been persisted yet, so the last message is the
// user's prompt; the older assistant's set_todos would otherwise flash on
// screen for a tick before resumeStream splices in the live turn.
export function ChatTodos({ messages, streaming }: ChatTodosProps) {
  const lastAssistant = useMemo(() => {
    if (messages.length === 0) return undefined;
    const last = messages[messages.length - 1] as any;
    return last?.role === 'assistant' ? last : undefined;
  }, [messages]);

  const todos: Todo[] = useMemo(
    () => (lastAssistant ? deriveTodos(lastAssistant) : []),
    [lastAssistant],
  );
  const lastAssistantId = (lastAssistant as any)?.id as string | undefined;

  const total = todos.length;
  const doneCount = todos.filter((t) => t.status === 'done').length;
  const allTerminal = total > 0 && doneCount === total;
  const isStalled = !streaming && !allTerminal && total > 0;

  const [collapsed, setCollapsed] = useState(false);
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set());
  // Three-phase fade so the user sees the Done pill for ~1.5s before the
  // strip transitions out. After 'fading' completes we unmount.
  const [phase, setPhase] = useState<'visible' | 'fading' | 'hidden'>('visible');

  useEffect(() => {
    if (!allTerminal) {
      setPhase('visible');
      return;
    }
    const t1 = setTimeout(() => setPhase('fading'), 1500);
    const t2 = setTimeout(() => setPhase('hidden'), 1800);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, [allTerminal, lastAssistantId]);

  if (total === 0) return null;
  if (lastAssistantId && dismissedIds.has(lastAssistantId)) return null;
  if (phase === 'hidden') return null;

  const onDismiss = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!lastAssistantId) return;
    setDismissedIds((prev) => {
      const next = new Set(prev);
      next.add(lastAssistantId);
      return next;
    });
  };

  return (
    <div
      role="status"
      aria-label="Agent task progress"
      className={cn(
        'mb-2 rounded-2xl border border-border bg-background-card shadow-lg overflow-hidden transition-opacity duration-300',
        phase === 'fading' && 'opacity-0',
      )}
    >
      <div className="flex items-center gap-2 px-4 py-2 text-xs font-medium text-foreground-secondary">
        <button
          type="button"
          onClick={() => setCollapsed((c) => !c)}
          aria-expanded={!collapsed}
          className="flex flex-1 items-center gap-2 hover:text-foreground transition-colors"
        >
          <ChevronDown
            className={cn('h-3.5 w-3.5 transition-transform', collapsed && '-rotate-90')}
          />
          <span aria-live="polite">
            {allTerminal ? `Done — ${doneCount}/${total}` : `Plan ${doneCount}/${total}`}
          </span>
          {isStalled && <span className="text-foreground/40">· Stream ended</span>}
        </button>
        {isStalled && (
          <button
            type="button"
            onClick={onDismiss}
            aria-label="Dismiss plan"
            className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-foreground/50 hover:bg-background-subtle hover:text-foreground transition-colors"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      <div
        className={cn(
          'grid transition-[grid-template-rows] duration-200 ease-out',
          collapsed ? 'grid-rows-[0fr]' : 'grid-rows-[1fr]',
        )}
      >
        <div className="overflow-hidden">
          <ul className="px-2 pb-1 max-h-[40vh] overflow-y-auto">
            {todos.map((t, idx) => (
              <TodoRow key={idx} todo={t} stalled={isStalled} />
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

function TodoRow({ todo, stalled }: { todo: Todo; stalled: boolean }) {
  const iconCls = 'mt-1 h-3 w-3 shrink-0';

  let icon: JSX.Element;
  if (stalled) {
    if (todo.status === 'done') {
      icon = <CheckCircle2 className={cn(iconCls, 'text-success/60')} aria-label="Done" />;
    } else {
      icon = <Pause className={cn(iconCls, 'text-foreground/40')} aria-label="Paused" />;
    }
  } else if (todo.status === 'done') {
    icon = <CheckCircle2 className={cn(iconCls, 'text-success')} aria-label="Done" />;
  } else if (todo.status === 'in_progress') {
    icon = <Loader2 className={cn(iconCls, 'animate-spin text-foreground')} aria-label="In progress" />;
  } else {
    icon = <Circle className={cn(iconCls, 'text-foreground/40')} aria-label="Pending" />;
  }

  // Three distinct visual weights so the user can see at a glance which row
  // is active: pending = secondary (muted), in_progress = full + medium
  // weight (bright, slightly emphasized), done = /60 (dimmed). Without this
  // distinction the icon is the only signal and pending vs in_progress
  // read identically at row level.
  const titleCls = stalled
    ? 'text-foreground/40'
    : todo.status === 'done'
      ? 'text-foreground/60'
      : todo.status === 'in_progress'
        ? 'text-foreground font-medium'
        : 'text-foreground-secondary';

  return (
    <li className="flex items-start gap-3 rounded-md px-2 py-1 hover:bg-background-subtle transition-colors">
      {icon}
      <span className={cn('flex-1 min-w-0 text-sm leading-snug', titleCls)}>
        {todo.title}
      </span>
    </li>
  );
}

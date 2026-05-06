import { useEffect, useMemo, useState } from 'react';
import type { UIMessage } from 'ai';
import { CheckCircle2, Circle, ListChecks, Loader2, Pause, X } from 'lucide-react';
import { cn } from '../../lib/utils';
import { deriveTodos, type Todo } from '../../lib/aegis-todos';

interface ChatTodosProps {
  messages: UIMessage[];
  streaming: boolean;
}

// Sticky strip above the composer that shows the agent's declared plan for
// the current turn. Visibility matrix:
//   streaming + non-terminal → live: Loader2 spins on in_progress
//   streaming + terminal     → Done pill, hold 1.5s, fade
//   ended    + non-terminal  → stalled: muted rows + Dismiss-X
//   ended    + terminal      → Done pill, hold 1.5s, fade
// Reads from the most recent assistant message; reading messages[length-1]
// directly would flicker out on every user send.
export function ChatTodos({ messages, streaming }: ChatTodosProps) {
  const lastAssistant = useMemo(() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      if ((messages[i] as any).role === 'assistant') return messages[i];
    }
    return undefined;
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

  const onDismiss = () => {
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
        'mb-2 rounded-md border border-border bg-background-subtle/30 px-4 py-3 transition-opacity duration-300',
        phase === 'fading' && 'opacity-0',
      )}
    >
      <div className="flex items-center gap-1.5 mb-2 text-xs font-medium text-foreground-secondary">
        {allTerminal ? (
          <CheckCircle2 className="h-3.5 w-3.5 text-success" />
        ) : (
          <ListChecks className="h-3.5 w-3.5" />
        )}
        <span aria-live="polite">
          {allTerminal ? `Done — ${doneCount}/${total}` : `Plan ${doneCount}/${total}`}
        </span>
        {isStalled && (
          <span className="text-foreground/40">· Stream ended</span>
        )}
        {isStalled && (
          <button
            type="button"
            onClick={onDismiss}
            aria-label="Dismiss plan"
            className="ml-auto inline-flex h-5 w-5 items-center justify-center rounded text-foreground/50 hover:bg-background-card hover:text-foreground transition-colors"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      <ul className="space-y-1.5 max-h-[40vh] overflow-y-auto">
        {todos.map((t, idx) => (
          <TodoRow key={idx} todo={t} stalled={isStalled} />
        ))}
      </ul>
    </div>
  );
}

function TodoRow({ todo, stalled }: { todo: Todo; stalled: boolean }) {
  const iconCls = 'h-3.5 w-3.5 mt-0.5 shrink-0';

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

  const titleCls = stalled
    ? 'text-foreground/40'
    : todo.status === 'in_progress'
      ? 'text-foreground'
      : 'text-foreground-secondary';

  return (
    <li className="flex items-start gap-2 text-sm leading-snug">
      {icon}
      <span className={cn('flex-1 min-w-0 truncate', titleCls)}>{todo.title}</span>
    </li>
  );
}

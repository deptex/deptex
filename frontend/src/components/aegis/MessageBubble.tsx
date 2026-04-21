import type { UIMessage } from 'ai';
import { User, MessageSquare, Pencil, Check, X } from 'lucide-react';
import { useState, type KeyboardEvent } from 'react';
import { MarkdownRenderer } from './MarkdownRenderer';
import { ToolCallCard } from './ToolCallCard';
import { cn } from '../../lib/utils';

interface MessageBubbleProps {
  message: UIMessage;
  currentUserId?: string;
  participantNames?: Record<string, string>;
  onEdit?: (newText: string) => void;
  disabled?: boolean;
}

function extractText(message: UIMessage): string {
  const parts = (message as any).parts ?? [];
  return parts
    .filter((p: any) => p.type === 'text')
    .map((p: any) => p.text ?? '')
    .join('\n');
}

type ToolStateKey = 'input-streaming' | 'input-available' | 'output-available' | 'output-error';

function mapState(state: ToolStateKey | string | undefined): 'running' | 'done' | 'error' {
  if (state === 'output-available') return 'done';
  if (state === 'output-error') return 'error';
  return 'running';
}

export function MessageBubble({ message, currentUserId, participantNames, onEdit, disabled }: MessageBubbleProps) {
  const isUser = message.role === 'user';
  const parts = (message as any).parts ?? [];
  const authorId = (message as any).userId as string | null | undefined;
  const isMine = !authorId || !currentUserId || authorId === currentUserId;
  const authorName = isUser
    ? (isMine ? 'You' : (participantNames?.[authorId!] ?? 'Teammate'))
    : 'Aegis';

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');

  const text = extractText(message);

  const beginEdit = () => {
    setDraft(text);
    setEditing(true);
  };

  const commitEdit = () => {
    const trimmed = draft.trim();
    if (!trimmed || trimmed === text) { setEditing(false); return; }
    onEdit?.(trimmed);
    setEditing(false);
  };

  const onEditKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      commitEdit();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setEditing(false);
    }
  };

  return (
    <div className="px-4 py-3 group">
      <div className="mx-auto max-w-3xl flex gap-3">
        <div
          className={cn(
            'flex-shrink-0 h-7 w-7 rounded-full flex items-center justify-center border',
            isUser
              ? 'bg-background-subtle border-border text-foreground/70'
              : 'bg-background-card border-border text-foreground/80',
          )}
        >
          {isUser ? <User className="h-3.5 w-3.5" /> : <MessageSquare className="h-3.5 w-3.5" />}
        </div>
        <div className="flex-1 min-w-0 pt-0.5">
          <div className="text-xs font-medium text-foreground/70 mb-1">{authorName}</div>
          {editing ? (
            <div className="space-y-2">
              <textarea
                autoFocus
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={onEditKeyDown}
                rows={Math.min(8, Math.max(2, draft.split('\n').length))}
                className="w-full resize-y rounded-md border border-border bg-background-card px-3 py-2 text-sm text-foreground outline-none focus:border-foreground/30"
              />
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={commitEdit}
                  className="inline-flex items-center gap-1 rounded-md bg-foreground px-2.5 py-1 text-xs font-medium text-background hover:bg-foreground/90"
                >
                  <Check className="h-3 w-3" /> Save & send
                </button>
                <button
                  type="button"
                  onClick={() => setEditing(false)}
                  className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-foreground/80 hover:bg-background-subtle/60"
                >
                  <X className="h-3 w-3" /> Cancel
                </button>
                <span className="text-[11px] text-foreground/50">⌘/Ctrl+Enter to save</span>
              </div>
            </div>
          ) : (
            <>
              <div className="space-y-1">
                {parts.map((part: any, i: number) => {
                  if (part.type === 'text') {
                    return isUser ? (
                      <div key={i} className="text-sm text-foreground/90 whitespace-pre-wrap">{part.text}</div>
                    ) : (
                      <MarkdownRenderer key={i} content={part.text ?? ''} />
                    );
                  }
                  if (part.type === 'dynamic-tool' || (typeof part.type === 'string' && part.type.startsWith('tool-'))) {
                    const toolName = part.toolName ?? (part.type as string).replace(/^tool-/, '');
                    return (
                      <ToolCallCard
                        key={part.toolCallId ?? i}
                        toolName={toolName}
                        state={mapState(part.state)}
                        input={part.input}
                        output={part.output}
                        errorText={part.errorText}
                      />
                    );
                  }
                  return null;
                })}
              </div>
              {isUser && isMine && onEdit && text && (
                <div className="mt-1.5 flex items-center gap-1 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                  <button
                    type="button"
                    onClick={beginEdit}
                    disabled={disabled}
                    className="inline-flex items-center gap-1 rounded px-1.5 py-1 text-[11px] text-foreground/60 hover:text-foreground hover:bg-background-subtle/60 disabled:opacity-40 disabled:cursor-not-allowed"
                    aria-label="Edit"
                  >
                    <Pencil className="h-3 w-3" /> Edit
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

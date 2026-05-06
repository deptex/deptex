import type { ReactNode } from 'react';
import type { UIMessage } from 'ai';
import { AlertCircle, RotateCcw } from 'lucide-react';
import { MarkdownRenderer } from './MarkdownRenderer';
import { ToolCallGroup, type ToolCallEntry } from './ToolCallCard';
import { PlanCard, PlanCardSkeleton } from './PlanCard';
import { FixStatusCard } from './FixStatusCard';
import type { AegisChatError } from '../../lib/aegis-api';
import { isToolPart, toolNameFor } from '../../lib/aegis-parts';

interface MessageBubbleProps {
  message: UIMessage;
  currentUserId?: string;
  organizationId?: string;
  onRegenerate?: () => void;
  isRegenerating?: boolean;
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

export function MessageBubble({
  message,
  currentUserId: _currentUserId,
  organizationId,
  onRegenerate,
  isRegenerating,
}: MessageBubbleProps) {
  const isUser = message.role === 'user';
  const parts = (message as any).parts ?? [];
  const text = extractText(message);
  const error = (message as any).error as AegisChatError | undefined;

  if (!isUser && error) {
    return (
      <ErrorBubble
        error={error}
        organizationId={organizationId}
        onRegenerate={onRegenerate}
        isRegenerating={isRegenerating}
      />
    );
  }

  if (isUser) {
    return (
      <div className="px-4 py-1">
        <div className="mx-auto max-w-3xl flex flex-col items-end">
          <div className="max-w-[72%] rounded-2xl bg-background-card border border-border px-4 py-2.5 text-sm text-foreground/90 whitespace-pre-wrap leading-relaxed">
            {text}
          </div>
        </div>
      </div>
    );
  }

  // Group consecutive tool-call parts so the bubble shows one
  // expandable "N tool calls" block per cluster instead of a row per call.
  // request_fix and approve_fix bypass the gray pill entirely: request_fix
  // renders as a PlanCardSkeleton while running and a PlanCard once
  // resolved; approve_fix renders as FixStatusCard. Errors fall through to
  // the gray pill so the user still sees the failure.
  const elements: ReactNode[] = [];
  let toolBuffer: ToolCallEntry[] = [];
  const flushTools = () => {
    if (toolBuffer.length > 0) {
      elements.push(<ToolCallGroup key={`tools-${elements.length}`} tools={toolBuffer} />);
      toolBuffer = [];
    }
  };

  parts.forEach((part: any, i: number) => {
    if (part.type === 'text') {
      flushTools();
      elements.push(<MarkdownRenderer key={`text-${i}`} content={part.text ?? ''} organizationId={organizationId} />);
      return;
    }
    if (isToolPart(part)) {
      const toolName = toolNameFor(part);
      // set_todos is pure UI bookkeeping for the ChatTodos strip — it
      // should never render as a tool-call pill or PlanCard inline. Must
      // come BEFORE the request_fix branch so a turn ending with
      // [set_todos, request_fix(error)] still falls through to the error
      // pill cleanly.
      if (toolName === 'set_todos') return;
      const output = part.output as { fixId?: string; error?: string; revised?: boolean } | undefined;
      // Treat both runtime errors AND tool-returned `{error: "..."}` as
      // errors. Without the latter check, request_fix calls that returned
      // a handled error (missing handle, no GitHub installation, etc.)
      // would slip through with state='output-available' but no fixId,
      // leaving the chat with a permanent "Generating plan…" skeleton.
      const isError = part.state === 'output-error' || !!output?.error;
      const resolved = part.state === 'output-available' && output?.fixId;

      if ((toolName === 'request_fix' || toolName === 'revise_fix') && !isError) {
        flushTools();
        const isRevise = toolName === 'revise_fix';
        if (resolved) {
          elements.push(
            <PlanCard
              key={`plan-${i}`}
              fixId={output.fixId!}
              organizationId={organizationId}
              revised={isRevise}
            />,
          );
        } else {
          elements.push(<PlanCardSkeleton key={`plan-skel-${i}`} revised={isRevise} />);
        }
        return;
      }

      toolBuffer.push({ toolName, state: mapState(part.state) });

      if (resolved && toolName === 'approve_fix') {
        flushTools();
        elements.push(<FixStatusCard key={`status-${i}`} fixId={output.fixId!} />);
      }
    }
  });
  flushTools();

  // A turn whose only parts were set_todos calls produces zero elements; we
  // skip the wrapping bubble entirely instead of rendering empty padding.
  if (!isUser && !error && elements.length === 0) return null;

  return (
    <div className="px-4 py-2">
      <div className="mx-auto max-w-3xl">
        <div className="space-y-2">{elements}</div>
      </div>
    </div>
  );
}

interface ErrorBubbleProps {
  error: AegisChatError;
  organizationId?: string;
  onRegenerate?: () => void;
  isRegenerating?: boolean;
}

function ErrorBubble({ error, organizationId, onRegenerate, isRegenerating }: ErrorBubbleProps) {
  const isCostCap = error.type === 'cost_cap';
  const message = isCostCap
    ? error.message ?? 'Monthly AI budget reached.'
    : 'Something went wrong while generating a response.';

  return (
    <div className="px-4 py-2">
      <div className="mx-auto max-w-3xl">
        <div className="flex items-start gap-2.5 rounded-lg border border-error/30 bg-error/[0.06] px-3 py-2.5 text-sm text-foreground/90">
          <AlertCircle className="h-4 w-4 shrink-0 text-error/80 mt-0.5" />
          <div className="flex-1 min-w-0">
            <p className="leading-relaxed">{message}</p>
            <div className="mt-2 flex items-center gap-3">
              {isCostCap ? (
                organizationId && (
                  <a
                    href={`/organizations/${organizationId}/settings/ai`}
                    className="text-xs font-medium text-foreground/80 hover:text-foreground underline underline-offset-2"
                  >
                    Manage AI budget
                  </a>
                )
              ) : (
                onRegenerate && (
                  <button
                    type="button"
                    onClick={onRegenerate}
                    disabled={isRegenerating}
                    className="inline-flex items-center gap-1.5 rounded-md border border-foreground/40 bg-transparent px-2 py-1 text-xs font-medium text-foreground hover:bg-foreground/10 transition-colors disabled:opacity-60"
                  >
                    <RotateCcw className={`h-3 w-3 ${isRegenerating ? 'animate-spin' : ''}`} />
                    {isRegenerating ? 'Regenerating' : 'Regenerate'}
                  </button>
                )
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

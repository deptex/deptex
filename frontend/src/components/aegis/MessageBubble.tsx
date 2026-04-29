import type { ReactNode } from 'react';
import type { UIMessage } from 'ai';
import { MarkdownRenderer } from './MarkdownRenderer';
import { ToolCallGroup, type ToolCallEntry } from './ToolCallCard';
import { PlanCard } from './PlanCard';
import { FixStatusCard } from './FixStatusCard';

interface MessageBubbleProps {
  message: UIMessage;
  currentUserId?: string;
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

function isToolPart(part: any): boolean {
  return (
    part?.type === 'dynamic-tool' ||
    (typeof part?.type === 'string' && part.type.startsWith('tool-'))
  );
}

function toolNameFor(part: any): string {
  if (part.toolName) return part.toolName as string;
  if (typeof part.type === 'string' && part.type.startsWith('tool-')) {
    return part.type.replace(/^tool-/, '');
  }
  return 'tool';
}

export function MessageBubble({ message, currentUserId: _currentUserId }: MessageBubbleProps) {
  const isUser = message.role === 'user';
  const parts = (message as any).parts ?? [];
  const text = extractText(message);

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
  // Exception: request_fix / approve_fix tool calls render as full PlanCard /
  // FixStatusCard blocks alongside the gray pill — those write tools deserve
  // visual prominence.
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
      elements.push(<MarkdownRenderer key={`text-${i}`} content={part.text ?? ''} />);
      return;
    }
    if (isToolPart(part)) {
      const toolName = toolNameFor(part);
      toolBuffer.push({ toolName, state: mapState(part.state) });

      // When a write tool resolves with a fixId, surface a dedicated card.
      const output = part.output as { fixId?: string } | undefined;
      const resolved = part.state === 'output-available' && output?.fixId;
      if (resolved && toolName === 'request_fix') {
        flushTools();
        elements.push(<PlanCard key={`plan-${i}`} fixId={output.fixId!} />);
      } else if (resolved && toolName === 'approve_fix') {
        flushTools();
        elements.push(<FixStatusCard key={`status-${i}`} fixId={output.fixId!} />);
      }
    }
  });
  flushTools();

  return (
    <div className="px-4 py-2">
      <div className="mx-auto max-w-3xl">
        <div className="space-y-2">{elements}</div>
      </div>
    </div>
  );
}

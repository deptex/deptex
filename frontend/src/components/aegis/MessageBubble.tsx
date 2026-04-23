import type { UIMessage } from 'ai';
import { MarkdownRenderer } from './MarkdownRenderer';
import { ToolCallCard } from './ToolCallCard';

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

export function MessageBubble({ message, currentUserId }: MessageBubbleProps) {
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

  return (
    <div className="px-4 py-2">
      <div className="mx-auto max-w-3xl">
        <div className="space-y-2">
          {parts.map((part: any, i: number) => {
            if (part.type === 'text') {
              return <MarkdownRenderer key={i} content={part.text ?? ''} />;
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
      </div>
    </div>
  );
}

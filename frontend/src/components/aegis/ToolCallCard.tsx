import { useState } from 'react';
import { ChevronDown, ChevronRight, Wrench, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';

type ToolState = 'running' | 'done' | 'error';

interface ToolCallCardProps {
  toolName: string;
  state: ToolState;
  input?: unknown;
  output?: unknown;
  errorText?: string;
}

function formatJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function prettyToolName(raw: string): string {
  return raw.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export function ToolCallCard({ toolName, state, input, output, errorText }: ToolCallCardProps) {
  const [expanded, setExpanded] = useState(false);

  const Icon = state === 'running' ? Loader2 : state === 'error' ? AlertCircle : CheckCircle2;
  const iconClass = cn(
    'h-3.5 w-3.5',
    state === 'running' && 'animate-spin text-foreground/60',
    state === 'done' && 'text-emerald-500',
    state === 'error' && 'text-red-500',
  );

  return (
    <div className="my-2 rounded-lg border border-border bg-background-card/50 overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-background-subtle/40 transition-colors"
      >
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5 text-foreground/50" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-foreground/50" />
        )}
        <Wrench className="h-3.5 w-3.5 text-foreground/50" />
        <span className="flex-1 text-xs text-foreground/80 font-medium">{prettyToolName(toolName)}</span>
        <Icon className={iconClass} />
      </button>
      {expanded && (
        <div className="border-t border-border px-3 py-2 space-y-2">
          {input !== undefined && (
            <div>
              <div className="text-[11px] uppercase tracking-wide text-foreground/50 mb-1">Input</div>
              <pre className="text-[12px] text-foreground/80 bg-background-subtle/60 rounded p-2 overflow-x-auto">
                {formatJson(input)}
              </pre>
            </div>
          )}
          {state === 'error' && errorText && (
            <div>
              <div className="text-[11px] uppercase tracking-wide text-red-500/80 mb-1">Error</div>
              <pre className="text-[12px] text-red-400 bg-background-subtle/60 rounded p-2 overflow-x-auto">
                {errorText}
              </pre>
            </div>
          )}
          {state === 'done' && output !== undefined && (
            <div>
              <div className="text-[11px] uppercase tracking-wide text-foreground/50 mb-1">Result</div>
              <pre className="text-[12px] text-foreground/80 bg-background-subtle/60 rounded p-2 overflow-x-auto max-h-64">
                {formatJson(output)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

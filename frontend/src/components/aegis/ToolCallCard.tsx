import { useState } from 'react';
import { ChevronDown, ChevronRight, AlertCircle, Loader2 } from 'lucide-react';
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
  const Chevron = expanded ? ChevronDown : ChevronRight;

  return (
    <div className="my-1">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className={cn(
          'inline-flex items-center gap-1.5 text-xs transition-colors',
          state === 'error'
            ? 'text-destructive/90 hover:text-destructive'
            : 'text-foreground-secondary hover:text-foreground',
        )}
      >
        <Chevron className="h-3 w-3" />
        <span>{prettyToolName(toolName)}</span>
        {state === 'running' && <Loader2 className="h-3 w-3 animate-spin" />}
        {state === 'error' && <AlertCircle className="h-3 w-3" />}
      </button>
      {expanded && (
        <div className="mt-1.5 ml-3 border-l border-border pl-3 space-y-2">
          {input !== undefined && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-foreground-secondary/80 mb-1">Input</div>
              <pre className="text-[11px] text-foreground-secondary font-mono whitespace-pre-wrap break-words">
                {formatJson(input)}
              </pre>
            </div>
          )}
          {state === 'error' && errorText && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-destructive/80 mb-1">Error</div>
              <pre className="text-[11px] text-destructive font-mono whitespace-pre-wrap break-words">
                {errorText}
              </pre>
            </div>
          )}
          {state === 'done' && output !== undefined && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-foreground-secondary/80 mb-1">Result</div>
              <pre className="text-[11px] text-foreground-secondary font-mono whitespace-pre-wrap break-words max-h-64 overflow-auto">
                {formatJson(output)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

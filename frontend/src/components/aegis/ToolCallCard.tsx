import { useState } from 'react';
import { ChevronDown, ChevronRight, AlertCircle, Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';

type ToolState = 'running' | 'done' | 'error';

export interface ToolCallEntry {
  toolName: string;
  state: ToolState;
}

interface ToolCallGroupProps {
  tools: ToolCallEntry[];
}

function prettyToolName(raw: string): string {
  return raw.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export function ToolCallGroup({ tools }: ToolCallGroupProps) {
  const [expanded, setExpanded] = useState(false);
  if (tools.length === 0) return null;

  const Chevron = expanded ? ChevronDown : ChevronRight;
  const hasError = tools.some((t) => t.state === 'error');
  const anyRunning = tools.some((t) => t.state === 'running');
  const label = `${tools.length} tool call${tools.length === 1 ? '' : 's'}`;

  return (
    <div className="my-1">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className={cn(
          'inline-flex items-center gap-1.5 text-xs transition-colors',
          hasError
            ? 'text-destructive/90 hover:text-destructive'
            : 'text-foreground-secondary hover:text-foreground',
        )}
      >
        <Chevron className="h-3 w-3" />
        <span>{label}</span>
        {anyRunning && <Loader2 className="h-3 w-3 animate-spin" />}
        {hasError && <AlertCircle className="h-3 w-3" />}
      </button>
      <div
        className={cn(
          'grid transition-all duration-200 ease-out',
          expanded ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0',
        )}
      >
        <div className="overflow-hidden">
          <div className="pt-1.5 pl-4 space-y-1">
            {tools.map((t, i) => (
              <div
                key={i}
                className={cn(
                  'flex items-center gap-1.5 text-xs',
                  t.state === 'error' ? 'text-destructive/90' : 'text-foreground-secondary',
                )}
              >
                <span>{prettyToolName(t.toolName)}</span>
                {t.state === 'running' && <Loader2 className="h-3 w-3 animate-spin" />}
                {t.state === 'error' && <AlertCircle className="h-3 w-3" />}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

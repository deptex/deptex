import { useState, type ReactNode } from 'react';
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

function prettyToolName(raw: string): string {
  return raw.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function renderInlineValue(v: unknown): ReactNode {
  if (v === null || v === undefined) {
    return <span className="text-foreground-muted">—</span>;
  }
  if (typeof v === 'string') {
    if (v.length === 0) return <span className="text-foreground-muted">""</span>;
    return v;
  }
  if (typeof v === 'number' || typeof v === 'boolean') {
    return String(v);
  }
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="text-foreground-muted">empty</span>;
    const allPrimitive = v.every((x) => typeof x !== 'object' || x === null);
    if (allPrimitive) return v.map((x) => String(x)).join(', ');
    return (
      <span className="text-foreground-secondary">
        {v.length} {v.length === 1 ? 'item' : 'items'}
      </span>
    );
  }
  if (typeof v === 'object') {
    const keys = Object.keys(v as object);
    return <span className="text-foreground-secondary">{keys.length === 0 ? 'empty' : `{ ${keys.length} keys }`}</span>;
  }
  return String(v);
}

function DataCard({ data }: { data: unknown }) {
  if (data === null || data === undefined) {
    return (
      <div className="rounded-md border border-border bg-background-card/60 px-3 py-1.5 text-xs text-foreground-muted">
        —
      </div>
    );
  }

  // Top-level object: render keys as rows
  if (typeof data === 'object' && !Array.isArray(data)) {
    const entries = Object.entries(data as Record<string, unknown>);
    if (entries.length === 0) {
      return (
        <div className="rounded-md border border-border bg-background-card/60 px-3 py-1.5 text-xs text-foreground-muted">
          empty
        </div>
      );
    }
    return (
      <div className="rounded-md border border-border bg-background-card/60 overflow-hidden">
        <div className="divide-y divide-border">
          {entries.map(([key, value]) => (
            <div key={key} className="flex items-baseline gap-3 px-3 py-1.5 text-xs">
              <span className="text-foreground-secondary font-mono shrink-0">{key}</span>
              <span className="text-foreground flex-1 break-words text-right font-mono">
                {renderInlineValue(value)}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // Top-level array: render rows of items
  if (Array.isArray(data)) {
    if (data.length === 0) {
      return (
        <div className="rounded-md border border-border bg-background-card/60 px-3 py-1.5 text-xs text-foreground-muted">
          empty
        </div>
      );
    }
    const visible = data.slice(0, 10);
    return (
      <div className="rounded-md border border-border bg-background-card/60 overflow-hidden">
        <div className="divide-y divide-border">
          {visible.map((item, i) => (
            <div key={i} className="px-3 py-1.5 text-xs text-foreground font-mono break-words">
              {renderInlineValue(item)}
            </div>
          ))}
          {data.length > visible.length && (
            <div className="px-3 py-1.5 text-xs text-foreground-muted">+ {data.length - visible.length} more</div>
          )}
        </div>
      </div>
    );
  }

  // Primitive at top level
  return (
    <div className="rounded-md border border-border bg-background-card/60 px-3 py-1.5 text-xs text-foreground font-mono break-words">
      {String(data)}
    </div>
  );
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
      <div
        className={cn(
          'grid transition-all duration-200 ease-out',
          expanded ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0',
        )}
      >
        <div className="overflow-hidden">
          <div className="pt-2 pl-4">
            {state === 'error' && errorText ? (
              <pre className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-[11px] text-destructive font-mono whitespace-pre-wrap break-words">
                {errorText}
              </pre>
            ) : state === 'done' && output !== undefined ? (
              <DataCard data={output} />
            ) : input !== undefined ? (
              <DataCard data={input} />
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}

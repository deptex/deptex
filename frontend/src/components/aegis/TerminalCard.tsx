import { useState } from 'react';
import { SquareTerminal, ChevronRight } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

// A command step in a task chat, rendered as a lightweight tool-call row rather
// than a heavy terminal box — a run of many commands should read like a compact
// list of tool calls, not a stack of cards. Collapsed: an icon + the command (or
// the step's friendly label for milestones like clone / PR). Hovering reveals a
// chevron; clicking expands the echoed `$ command` and its output in an indented
// sub-panel. Milestone rows (a friendly label) show in normal text; a raw shell
// command shows in monospace, so it reads as what it is.

export function TerminalCard({
  title,
  command,
  output,
  Icon = SquareTerminal,
}: {
  title: string;
  command: string;
  output?: string;
  Icon?: LucideIcon;
}) {
  const [open, setOpen] = useState(false);
  const outLines = output ? output.split('\n') : [];
  // The label equals the command for a plain verify step; a milestone (clone/PR)
  // carries a friendlier sentence, and there's still the raw command to reveal.
  const isRawCommand = title === command;
  const canExpand = !!output || !isRawCommand;

  return (
    <div className="my-0.5">
      <button
        type="button"
        onClick={() => canExpand && setOpen((v) => !v)}
        className={`group/cmd flex w-full items-center gap-2 rounded-md px-1.5 py-0.5 text-left text-foreground-secondary transition-colors ${
          canExpand ? 'hover:bg-background-card-header/60' : 'cursor-default'
        }`}
      >
        <Icon className="h-3.5 w-3.5 shrink-0" />
        <span
          className={`truncate ${isRawCommand ? 'font-mono text-xs text-foreground/70' : 'text-sm'}`}
        >
          {title}
        </span>
        {canExpand && (
          <ChevronRight
            className={`ml-auto h-3.5 w-3.5 shrink-0 opacity-0 transition-all duration-200 group-hover/cmd:opacity-100 ${
              open ? 'rotate-90' : ''
            }`}
          />
        )}
      </button>

      {/* Output panel — indented under the row, hidden until expanded. */}
      {canExpand && (
        <div className={`grid transition-all duration-200 ease-out ${open ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'}`}>
          <div className="overflow-hidden">
            <div className="mt-1 overflow-x-auto rounded-md border border-border bg-background-card-header px-3 py-2 font-mono text-[12px] leading-relaxed">
              <div className="flex gap-2">
                <span className="shrink-0 select-none text-foreground-secondary">$</span>
                <span className="whitespace-pre-wrap break-all text-foreground/90">{command}</span>
              </div>
              {outLines.map((text, i) => (
                <div key={i} className="whitespace-pre-wrap break-all text-foreground/50">
                  {text || ' '}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

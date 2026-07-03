import { useState } from 'react';
import { SquareTerminal, ChevronDown } from 'lucide-react';

// A Cursor-style terminal card for a task chat's command steps. Same chrome as
// the file diff card: a header describing the action (the step's label) + a
// terminal icon, and a console body — the `$ command` line followed by its
// output. The command counts as the body's first line, so clicking the header
// collapses down to the last 2 lines (the command hides first). The hidden lines
// animate open/closed, a soft fade sits over the top while collapsed (a "more
// above" cue), and the chevron only appears on hover. Expanded by default.

const PEEK_LINES = 2;

export function TerminalCard({
  title,
  command,
  output,
}: {
  title: string;
  command: string;
  output?: string;
}) {
  const [open, setOpen] = useState(false);

  const outLines = output ? output.split('\n') : [];
  const lines: Array<{ cmd: boolean; text: string }> = [
    { cmd: true, text: command },
    ...outLines.map((text) => ({ cmd: false, text })),
  ];
  const hasHidden = lines.length > PEEK_LINES;
  const hiddenLines = hasHidden ? lines.slice(0, lines.length - PEEK_LINES) : [];
  const peekLines = hasHidden ? lines.slice(-PEEK_LINES) : lines;

  const renderLine = (ln: { cmd: boolean; text: string }, key: string) =>
    ln.cmd ? (
      <div key={key} className="flex gap-2">
        <span className="shrink-0 select-none text-foreground-secondary">$</span>
        <span className="whitespace-pre-wrap break-all text-foreground/90">{ln.text}</span>
      </div>
    ) : (
      <div key={key} className="whitespace-pre-wrap break-all text-foreground/50">
        {ln.text || ' '}
      </div>
    );

  return (
    <div className="group my-1 overflow-hidden rounded-lg border border-border bg-background-card-header">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 bg-background-card-header px-3 py-2 text-left transition-colors hover:bg-background-card-header/70"
      >
        <SquareTerminal className="h-3.5 w-3.5 shrink-0 text-foreground-secondary" />
        <span className="truncate text-xs text-foreground/90">{title}</span>
        <ChevronDown
          className={`ml-auto h-3.5 w-3.5 shrink-0 text-foreground-secondary opacity-0 transition-all duration-200 group-hover:opacity-100 ${open ? '' : '-rotate-90'}`}
        />
      </button>

      <div className="relative overflow-x-auto border-t border-border px-3 py-2 font-mono text-[12px] leading-relaxed">
        {/* Lines above the peek — animate open/closed. */}
        {hasHidden && (
          <div
            className={`grid transition-all duration-200 ease-out ${
              open ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
            }`}
          >
            <div className="overflow-hidden">{hiddenLines.map((ln, i) => renderLine(ln, `h${i}`))}</div>
          </div>
        )}

        {/* The last 2 lines — always shown. */}
        {peekLines.map((ln, i) => renderLine(ln, `p${i}`))}

        {/* Soft fade over the top while collapsed — hints at hidden lines above. */}
        {hasHidden && (
          <div
            className={`pointer-events-none absolute inset-x-0 top-0 h-6 bg-gradient-to-b from-background-card-header to-transparent transition-opacity duration-200 ${
              open ? 'opacity-0' : 'opacity-100'
            }`}
          />
        )}
      </div>
    </div>
  );
}

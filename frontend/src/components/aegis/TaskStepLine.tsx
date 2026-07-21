import { FilePen, CircleAlert, Moon } from 'lucide-react';
import { FileDiffCard } from './FileDiffCard';
import { TerminalCard } from './TerminalCard';

// A completed tool-use step in a task chat. Shapes, by what the step was:
//   • A real terminal command (clone / install / push) → a Cursor-style terminal
//     card: the action as a title, then `$ command` and its output.
//   • A file edit → a GitHub/Cursor-style file diff card (filename + ±stat, the
//     change as a real unified diff).
//   • Any other action (explore, a verify that soft-passed to CI) → a plain
//     labeled line: it isn't a command and has nothing to show.
// The `failed` step is a quiet, muted line (amber glyph). Emitted by the
// fix-worker as a `step` part; `command` / `diff` / `output` set where they apply.

export function TaskStepLine({
  icon,
  label,
  command,
  diff,
  output,
}: {
  icon?: string;
  label: string;
  command?: string;
  diff?: string;
  output?: string;
}) {
  // A genuine fault on our side (system_error) is the ONE terminal worth a red
  // glyph + red text — it's not an expected/resumable stop (paused / cancelled /
  // interrupted) but an actual break. Still just a line, never a card.
  if (icon === 'error') {
    return (
      <div className="flex items-center gap-2 text-sm text-destructive">
        <CircleAlert className="h-3.5 w-3.5 shrink-0 text-destructive" />
        <span>{label}</span>
      </div>
    );
  }

  // The 30-min timeout ("Aegis got tired") is the calmest terminal — an expected,
  // resume-on-reply stop, not a failure. Fully gray (glyph + text), a sleepy Moon.
  if (icon === 'tired') {
    return (
      <div className="flex items-center gap-2 text-sm text-foreground-secondary">
        <Moon className="h-3.5 w-3.5 shrink-0 text-foreground-secondary" />
        <span>{label}</span>
      </div>
    );
  }

  // Every other stop/failure is a quiet, muted line with a restrained amber glyph
  // — never the aggressive red-error look.
  if (icon === 'failed') {
    return (
      <div className="flex items-center gap-2 text-sm text-foreground-secondary">
        <CircleAlert className="h-3.5 w-3.5 shrink-0 text-amber-500/70" />
        <span>{label}</span>
      </div>
    );
  }

  // A file edit → a GitHub/Cursor-style file diff card.
  if (diff) {
    return <FileDiffCard diff={diff} />;
  }

  // A file edit with NO diff — only secret fixes do this (rendering the removed
  // lines would re-leak the credential). Still show it as a compact file card,
  // not a stray status line, so a redacted change reads as a real change.
  if (icon === 'edit') {
    return (
      <div className="my-1 flex items-center gap-2 overflow-hidden rounded-lg border border-border bg-background-card-header px-3 py-2">
        <FilePen className="h-4 w-4 shrink-0 text-foreground-secondary" />
        <span className="truncate font-mono text-xs text-foreground/90">{label}</span>
        <span className="ml-auto shrink-0 text-[11px] text-foreground-secondary">contents hidden (secret)</span>
      </div>
    );
  }

  // A real terminal command → a lightweight tool-call row. Every command uses the
  // same CLI icon (from TerminalCard's default), and its label is the descriptive
  // name the agent gave it — clone / verify / PR all read uniformly.
  if (command) {
    return <TerminalCard title={label} command={command} output={output} />;
  }

  // Investigation / status lines (read, search, …) — no icon; only the CLI
  // command rows carry a glyph, so these read as quiet annotations.
  return (
    <div className="text-sm text-foreground-secondary">
      <span>{label}</span>
    </div>
  );
}

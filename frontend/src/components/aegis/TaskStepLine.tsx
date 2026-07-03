import { GitBranch, FilePen, PackageCheck, GitPullRequest, Telescope, CircleX, Check } from 'lucide-react';
import { FileDiffCard } from './FileDiffCard';
import { TerminalCard } from './TerminalCard';

// A completed tool-use step in a task chat. Shapes, by what the step was:
//   • A real terminal command (clone / install / push) → a Cursor-style terminal
//     card: the action as a title, then `$ command` and its output.
//   • A file edit → a GitHub/Cursor-style file diff card (filename + ±stat, the
//     change as a real unified diff).
//   • Any other action (explore, a verify that soft-passed to CI) → a plain
//     labeled line: it isn't a command and has nothing to show.
// The `failed` step is a prominent red line. Emitted by the fix-worker as a
// `step` part; `command` / `diff` / `output` are set only where they apply.

const STEP_ICONS = {
  clone: GitBranch,
  explore: Telescope,
  edit: FilePen,
  verify: PackageCheck,
  pr: GitPullRequest,
  failed: CircleX,
} as const;

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
  const Icon = STEP_ICONS[icon as keyof typeof STEP_ICONS] ?? Check;

  // A failure is always shown plainly, in red.
  if (icon === 'failed') {
    return (
      <div className="flex items-center gap-2 text-sm text-destructive/90">
        <Icon className="h-3.5 w-3.5 shrink-0" />
        <span>{label}</span>
      </div>
    );
  }

  // A file edit → a GitHub/Cursor-style file diff card.
  if (diff) {
    return <FileDiffCard diff={diff} />;
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

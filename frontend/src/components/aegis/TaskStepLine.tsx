import { GitBranch, FilePen, PackageCheck, GitPullRequest, Check } from 'lucide-react';

// A completed tool-use step in a task chat — a gray icon + label line ("Cloned
// the repository") that reads as an action the agent performed, distinct from
// its first-person prose beats. Emitted by the fix-worker as a `step` part.

const STEP_ICONS = {
  clone: GitBranch,
  edit: FilePen,
  verify: PackageCheck,
  pr: GitPullRequest,
} as const;

export function TaskStepLine({ icon, label }: { icon?: string; label: string }) {
  const Icon = STEP_ICONS[icon as keyof typeof STEP_ICONS] ?? Check;
  return (
    <div className="flex items-center gap-2 text-sm text-foreground-secondary">
      <Icon className="h-3.5 w-3.5 shrink-0" />
      <span>{label}</span>
    </div>
  );
}

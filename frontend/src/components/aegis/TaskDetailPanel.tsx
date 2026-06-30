import { useEffect, useState } from 'react';
import { PanelRight } from 'lucide-react';
import { api, type VulnerabilityDetail } from '../../lib/api';
import type { AegisTask, AegisTaskTarget } from '../../lib/aegis-api';
import { VulnerabilityExpandedCard } from '../security/VulnerabilityExpandedCard';

// The task detail slide-in, opened from the compact task row. Mirrors the plan
// sidebar (FixPanel): bg-background panel behind a border-l aside, px-6 pt-5 pb-6
// body, text-lg semibold title, ESC + a PanelRight toggle to close. Shows the
// task title, a description, and the actual finding card(s) for its targets —
// the same VulnerabilityExpandedCard the fix panel renders.

const TYPE_LABEL: Record<string, string> = {
  vulnerability: 'Vulnerability',
  semgrep: 'Semgrep',
  secret: 'Secret',
};

function describeTask(task: AegisTask): string {
  // The runner writes a true, finding-grounded description onto the task; this
  // is only the backstop before that lands — goal-oriented, not a recital of
  // Aegis's process.
  const desc = task.description?.trim();
  if (desc && desc !== task.title.trim()) return desc;
  const n = task.targets.length || task.totalFixes || 0;
  if (n === 0) return 'Aegis is working this task.';
  if (n === 1) return `Resolve ${task.targets[0]?.label ?? 'this finding'} and open a pull request.`;
  return `Resolve ${n} findings and open a pull request for each.`;
}

function panelWidth(): number {
  // Up to 2/5 of the viewport, capped at 800px.
  if (typeof window === 'undefined') return 800;
  return Math.max(360, Math.min(800, Math.floor(window.innerWidth * 0.4)));
}

// One finding's card. Vulnerabilities fetch the full scanner detail and render
// the same expanded card as the fix panel / findings table; semgrep/secret (or
// a reaped finding) fall back to a compact label card.
function TaskFindingCard({ orgId, target }: { orgId: string; target: AegisTaskTarget }) {
  const canFetch = target.findingType === 'vulnerability' && !!target.osvId;
  const [detail, setDetail] = useState<VulnerabilityDetail | null>(null);
  const [state, setState] = useState<'loading' | 'loaded' | 'fallback'>(
    canFetch ? 'loading' : 'fallback',
  );

  useEffect(() => {
    if (!canFetch) return;
    let cancelled = false;
    api
      .getVulnerabilityDetail(orgId, target.projectId, target.osvId!)
      .then((d) => {
        if (!cancelled) {
          setDetail(d);
          setState('loaded');
        }
      })
      .catch(() => {
        if (!cancelled) setState('fallback');
      });
    return () => {
      cancelled = true;
    };
  }, [canFetch, orgId, target.projectId, target.osvId]);

  if (state === 'loaded' && detail) {
    return (
      <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3.5">
        <VulnerabilityExpandedCard
          vuln={detail.vulnerability}
          detail={detail}
          organizationId={orgId}
          projectId={target.projectId}
        />
      </div>
    );
  }

  if (state === 'loading') {
    return (
      <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3.5">
        <div className="h-4 w-2/3 rounded bg-muted/40 animate-pulse" />
        <div className="mt-2 h-3 w-1/2 rounded bg-muted/30 animate-pulse" />
      </div>
    );
  }

  return (
    <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3">
      <div className="mb-1 text-xs font-medium uppercase tracking-wider text-foreground-secondary">
        {TYPE_LABEL[target.findingType] ?? target.findingType}
      </div>
      <div className="text-sm text-foreground break-words">{target.label}</div>
      {target.findingHandle && (
        <div className="mt-1 font-mono text-xs text-foreground-secondary break-all">
          {target.findingHandle}
        </div>
      )}
    </div>
  );
}

export function TaskDetailPanel({
  task,
  open,
  onClose,
}: {
  task: AegisTask | null;
  open: boolean;
  onClose: () => void;
}) {
  const [width] = useState(panelWidth);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  return (
    <div
      className="flex flex-shrink-0 relative transition-[width] duration-[220ms] ease-out"
      style={{ width: open ? width : 0 }}
      aria-hidden={!open}
    >
      {open && (
        <button
          type="button"
          onClick={onClose}
          aria-label="Close panel"
          className="absolute top-3 -left-8 h-6 w-6 rounded-md text-foreground-secondary hover:bg-background-subtle hover:text-foreground inline-flex items-center justify-center transition-colors z-20"
        >
          <PanelRight className="h-4 w-4" />
        </button>
      )}
      <aside className="flex-1 border-l border-border overflow-hidden">
        {task && (
          <div className="h-full flex flex-col bg-background overflow-hidden">
            <div className="flex-1 overflow-y-auto custom-scrollbar">
              <div className="px-6 pt-5 pb-6">
                <div className="text-lg font-semibold text-foreground leading-snug">
                  {task.title}
                </div>
                <p className="mt-3 text-sm leading-relaxed text-foreground/80">
                  {describeTask(task)}
                </p>

                {task.targets.length > 0 && (
                  <div className="mt-6 space-y-3">
                    {task.targets.map((t, i) => (
                      <TaskFindingCard key={i} orgId={task.organizationId} target={t} />
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </aside>
    </div>
  );
}

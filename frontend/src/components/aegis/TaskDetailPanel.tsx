import { useEffect, useState } from 'react';
import { PanelRight, Loader2 } from 'lucide-react';
import { api, type VulnerabilityDetail } from '../../lib/api';
import { aegisApi, type AegisTask, type AegisTaskTarget } from '../../lib/aegis-api';
import { VulnerabilityExpandedCard } from '../security/VulnerabilityExpandedCard';
import { FileDiffCard } from './FileDiffCard';
import { Button } from '../ui/button';

// The task sidebar: the chat's own header (task title) + tabs. `Task` shows the
// goal + the finding card(s); `Changes` shows the file diffs Aegis made with a
// "View pull request" action. Mirrors the fix panel chrome (bg-background aside
// behind a border-l, PanelRight toggle, ESC to close, width up to 2/5 vw).

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

function TaskTab({ task }: { task: AegisTask }) {
  return (
    <div className="px-6 pb-6 pt-5">
      <p className="text-sm leading-relaxed text-foreground/80">{describeTask(task)}</p>
      {task.targets.length > 0 && (
        <div className="mt-5 space-y-3">
          {task.targets.map((t, i) => (
            <TaskFindingCard key={i} orgId={task.organizationId} target={t} />
          ))}
        </div>
      )}
    </div>
  );
}

// The Changes tab body — just the diffs (the +/− stat and View PR button live in
// the sidebar header). Reads like a PR's "Files changed".
function ChangesTab({
  diffs,
  prUrl,
  loading,
}: {
  diffs: string[];
  prUrl: string | null;
  loading: boolean;
}) {
  if (loading) {
    return (
      <div className="flex items-center gap-2 px-6 py-8 text-sm text-foreground-secondary">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading changes…
      </div>
    );
  }

  const hasChanges = diffs.length > 0;
  if (!hasChanges && !prUrl) {
    return (
      <div className="px-6 py-8 text-sm leading-relaxed text-foreground-secondary">
        No changes yet — Aegis is still working this task.
      </div>
    );
  }

  return (
    <div className="space-y-4 px-6 pb-6 pt-5">
      {hasChanges ? (
        diffs.map((d, i) => <FileDiffCard key={i} diff={d} />)
      ) : (
        <div className="text-sm leading-relaxed text-foreground-secondary">
          The change is in the pull request.
        </div>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`relative pb-2.5 text-sm transition-colors ${
        active ? 'font-medium text-foreground' : 'text-foreground-secondary hover:text-foreground'
      }`}
    >
      {children}
      {active && <span className="absolute inset-x-0 -bottom-px h-0.5 rounded-full bg-foreground" />}
    </button>
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
  const [tab, setTab] = useState<'task' | 'changes'>('task');
  const [diffs, setDiffs] = useState<string[]>([]);
  const [prUrl, setPrUrl] = useState<string | null>(null);
  const [changesLoading, setChangesLoading] = useState(true);

  // Start each task on the Task tab.
  useEffect(() => {
    setTab('task');
  }, [task?.id]);

  // Pull the change set out of the task's chat: the edit-step diffs + the fix's
  // PR. Drives both the Changes tab and the header stat/button.
  useEffect(() => {
    const threadId = task?.threadId;
    if (!threadId) {
      setDiffs([]);
      setPrUrl(null);
      setChangesLoading(false);
      return;
    }
    let cancelled = false;
    setChangesLoading(true);
    (async () => {
      try {
        const msgs = await aegisApi.getMessages(threadId);
        const editDiffs: string[] = [];
        let fixId: string | undefined;
        for (const m of msgs) {
          for (const p of (m.metadata?.parts ?? []) as any[]) {
            if (p?.type === 'step' && p.icon === 'edit' && p.diff) editDiffs.push(p.diff);
            if (p?.type === 'tool-result' && p.result?.fixId) fixId = p.result.fixId;
          }
        }
        let url: string | null = null;
        if (fixId) {
          const { fix } = await api.getFix(fixId);
          url = fix?.prUrl ?? null;
        }
        if (!cancelled) {
          setDiffs(editDiffs);
          setPrUrl(url);
          setChangesLoading(false);
        }
      } catch {
        if (!cancelled) {
          setDiffs([]);
          setPrUrl(null);
          setChangesLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [task?.threadId]);

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
          <div className="flex h-full flex-col overflow-hidden bg-background">
            <div className="border-b border-border px-6 pt-4">
              <div className="flex items-start justify-between gap-3 pb-3">
                <div className="min-w-0 flex-1 text-base font-semibold leading-snug text-foreground">
                  {task.title}
                </div>
                {prUrl && (
                  <Button asChild variant="white" className="shrink-0">
                    <a href={prUrl} target="_blank" rel="noreferrer">
                      View pull request
                    </a>
                  </Button>
                )}
              </div>
              <div className="flex gap-5">
                <TabButton active={tab === 'task'} onClick={() => setTab('task')}>
                  Task
                </TabButton>
                <TabButton active={tab === 'changes'} onClick={() => setTab('changes')}>
                  Changes
                </TabButton>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto custom-scrollbar">
              {tab === 'task' ? (
                <TaskTab task={task} />
              ) : (
                <ChangesTab diffs={diffs} prUrl={prUrl} loading={changesLoading} />
              )}
            </div>
          </div>
        )}
      </aside>
    </div>
  );
}

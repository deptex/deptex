import { useEffect, useRef, useState } from 'react';
import { PanelRight, Loader2 } from 'lucide-react';
import { api, type FixChangeFile, type VulnerabilityDetail } from '../../lib/api';
import { aegisApi, type AegisTask, type AegisTaskTarget } from '../../lib/aegis-api';
import { supabase } from '../../lib/supabase';
import { VulnerabilityExpandedCard } from '../security/VulnerabilityExpandedCard';
import { FileDiffCard } from './FileDiffCard';
import { VscodeFileIcon } from './VscodeFileIcon';
import { Button } from '../ui/button';
import { Skeleton } from '../ui/skeleton';

// The task sidebar: the chat's own header (task title) + tabs. `Task` shows the
// goal + the finding card(s); `Changes` is the PR's cumulative "Files changed"
// view — the NET diff per file (initial vs now), with the chat's chronological
// edit-step diffs as the fallback before a PR exists. "View pull request" in
// the header. Mirrors the fix panel chrome (bg-background aside behind a
// border-l, PanelRight toggle, ESC to close, width up to 2/5 vw).

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

// FileDiffCard parses full `git diff` output and reads the filename from the
// `+++ b/…` header; the PR-files API returns only the hunk body (`patch`).
// Synthesize the minimal header so the card renders unchanged.
function toUnifiedDiff(path: string, patch: string): string {
  return `diff --git a/${path} b/${path}\n--- a/${path}\n+++ b/${path}\n${patch}`;
}

// A diff-less net-change row (patch: null = large/binary/lockfile). Mirrors
// FileDiffCard's header chrome — icon + name + counts — so the list reads
// uniformly; just no diff body underneath.
function FileSummaryRow({ file }: { file: FixChangeFile }) {
  return (
    <div className="my-1 overflow-hidden rounded-lg border border-border bg-background-card-header">
      <div className="flex items-center gap-2 px-3 py-2">
        <VscodeFileIcon file={file.path} size={16} />
        <span className="truncate font-mono text-xs text-foreground/90">{file.path}</span>
        <span className="ml-1 shrink-0 font-mono text-[11px] text-success">+{file.additions}</span>
        <span className="shrink-0 font-mono text-[11px] text-destructive">−{file.deletions}</span>
        <span className="ml-auto shrink-0 text-[11px] text-foreground-secondary">diff not shown</span>
      </div>
    </div>
  );
}

// Faded placeholder shaped like a FileDiffCard — same border + header chrome,
// pulsing bars where the icon, filename, +/− counts, and diff lines land, so
// the loading state previews the layout instead of announcing itself.
function FileDiffCardSkeleton({ bodyWidths }: { bodyWidths: string[] }) {
  return (
    <div className="my-1 overflow-hidden rounded-lg border border-border bg-background-card-header opacity-60">
      <div className="flex items-center gap-2 px-3 py-2">
        <Skeleton className="h-4 w-4 rounded" />
        <Skeleton className="h-3 w-40" />
        <Skeleton className="ml-1 h-3 w-6" />
        <Skeleton className="h-3 w-6" />
      </div>
      <div className="space-y-2 border-t border-border px-3 py-3">
        {bodyWidths.map((w, i) => (
          <Skeleton key={i} className={`h-3 ${w}`} />
        ))}
      </div>
    </div>
  );
}

// The Changes tab body. Preferred view: the NET change per file (initial vs
// now, one card per file — the PR's "Files changed") so a stage-by-stage run
// (edit → mistake → revert → fix) reads as one cumulative diff instead of 3-4
// cards for the same file. Before a PR exists (netFiles === null) it falls
// back to the chronological edit-step diffs from the chat so live work still
// shows; the first refresh after the PR lands flips to the net view. The chat
// timeline keeps the stages either way.
function ChangesTab({
  netFiles,
  diffs,
  prUrl,
  loading,
}: {
  netFiles: FixChangeFile[] | null;
  diffs: string[];
  prUrl: string | null;
  loading: boolean;
}) {
  if (loading) {
    return (
      <div aria-label="Loading changes" className="space-y-4 px-6 pb-6 pt-5">
        <FileDiffCardSkeleton bodyWidths={['w-3/4', 'w-1/2', 'w-5/6', 'w-2/3']} />
        <FileDiffCardSkeleton bodyWidths={['w-2/3', 'w-4/5', 'w-1/2']} />
      </div>
    );
  }

  if (netFiles !== null) {
    if (netFiles.length === 0) {
      return (
        <div className="px-6 py-8 text-sm leading-relaxed text-foreground-secondary">
          {prUrl ? 'The change is in the pull request.' : 'No changes yet — Aegis is still working this task.'}
        </div>
      );
    }
    // Lockfiles are machine-regenerated fallout of a manifest edit, not a
    // change Aegis made — hide them. Unless the PR is lockfile-ONLY (a pure
    // transitive bump), in which case they ARE the change and stay visible.
    const authored = netFiles.filter((f) => !f.lockfile);
    const shown = authored.length > 0 ? authored : netFiles;
    // Diffable files (manifests/source) first; diff-less rows (binaries,
    // oversize) last. Stable sort keeps the API's order within each group.
    const sorted = shown
      .slice()
      .sort((a, b) => Number(a.patch === null) - Number(b.patch === null));
    return (
      <div className="space-y-4 px-6 pb-6 pt-5">
        {sorted.map((f) =>
          f.patch !== null ? (
            <FileDiffCard key={f.path} diff={toUnifiedDiff(f.path, f.patch)} collapsible />
          ) : (
            <FileSummaryRow key={f.path} file={f} />
          ),
        )}
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
  onOpen,
}: {
  task: AegisTask | null;
  open: boolean;
  onClose: () => void;
  // Reopen the collapsed panel (the persistent PanelRight toggle). Optional so
  // existing call sites without it just lose the reopen affordance.
  onOpen?: () => void;
}) {
  const [width] = useState(panelWidth);
  const [tab, setTab] = useState<'task' | 'changes'>('task');
  const [diffs, setDiffs] = useState<string[]>([]);
  // The PR's net per-file change set. null = no PR yet (or endpoint unavailable)
  // → the Changes tab falls back to the message-derived stage diffs above.
  const [netFiles, setNetFiles] = useState<FixChangeFile[] | null>(null);
  const [prUrl, setPrUrl] = useState<string | null>(null);
  const [changesLoading, setChangesLoading] = useState(true);
  const [cancelling, setCancelling] = useState(false);

  // Stop a running task — the kill switch for an autonomous agent that writes
  // files and opens PRs. Rejects its in-flight fix so the worker aborts.
  const onStop = async () => {
    if (!task || cancelling) return;
    setCancelling(true);
    try {
      await aegisApi.cancelTask(task.id, task.organizationId);
    } catch {
      /* best-effort — the worker also aborts on its own budget/stall */
    } finally {
      setCancelling(false);
    }
  };

  // Start each task on the Task tab.
  useEffect(() => {
    setTab('task');
  }, [task?.id]);

  // Load the change set. Two sources, one winner:
  //   1. The chat's edit-step diffs (chronological stages) — the pre-PR
  //      fallback, and where the fixId is discovered.
  //   2. `GET /api/aegis/fix/:fixId/changes` — the PR's NET per-file view
  //      (initial vs now). Once `prNumber` is non-null this is what renders;
  //      it also supplies the header's prUrl.
  //
  // Re-runs on `refreshTick` (bumped by the realtime subscription below when an
  // amend/resume run lands new messages on the same thread — keyed on threadId
  // alone this could never update) and on `open` (reopening the panel refetches).
  // The spinner only shows for a thread's FIRST load; refreshes of the same
  // thread update in place so the tab doesn't flash empty mid-run.
  const [refreshTick, setRefreshTick] = useState(0);
  const loadedThreadRef = useRef<string | null>(null);
  useEffect(() => {
    const threadId = task?.threadId;
    if (!threadId) {
      setDiffs([]);
      setNetFiles(null);
      setPrUrl(null);
      setChangesLoading(false);
      return;
    }
    let cancelled = false;
    if (loadedThreadRef.current !== threadId) setChangesLoading(true);
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
        // `undefined` = the changes fetch failed → keep the previous net view
        // and prUrl instead of flashing back to stage diffs on a refresh blip.
        let net: { prUrl: string | null; files: FixChangeFile[] | null } | undefined;
        if (fixId) {
          try {
            const changes = await api.getFixChanges(fixId);
            net = {
              prUrl: changes.prUrl ?? null,
              // prNumber null = no PR yet → stage-diff fallback stays active.
              files: changes.prNumber != null ? changes.files ?? [] : null,
            };
          } catch {
            /* endpoint unavailable — keep the previous net view */
          }
        } else {
          net = { prUrl: null, files: null };
        }
        if (!cancelled) {
          setDiffs(editDiffs);
          if (net !== undefined) {
            setNetFiles(net.files);
            setPrUrl(net.prUrl);
          }
          setChangesLoading(false);
          loadedThreadRef.current = threadId;
        }
      } catch {
        if (!cancelled) {
          // First load falls back to empty; a failed REFRESH keeps what's on
          // screen (the next insert retriggers anyway).
          if (loadedThreadRef.current !== threadId) {
            setDiffs([]);
            setNetFiles(null);
            setPrUrl(null);
          }
          setChangesLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [task?.threadId, refreshTick, open]);

  // Live refresh for the change set — mirrors ChatPane's narration reload: the
  // worker persists each beat to aegis_chat_messages (in the realtime
  // publication), so each INSERT on this thread schedules a refetch. Trailing
  // 300ms debounce because steps land in bursts.
  useEffect(() => {
    const threadId = task?.threadId;
    if (!threadId) return;
    let timer: number | undefined;
    const channel = supabase
      .channel(`task-panel-msgs-${threadId}`)
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'aegis_chat_messages', filter: `thread_id=eq.${threadId}` },
        () => {
          if (timer !== undefined) window.clearTimeout(timer);
          timer = window.setTimeout(() => setRefreshTick((t) => t + 1), 300);
        },
      )
      .subscribe();
    return () => {
      if (timer !== undefined) window.clearTimeout(timer);
      supabase.removeChannel(channel);
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
      className="flex-shrink-0 relative transition-[width] duration-[220ms] ease-out"
      style={{ width: open ? width : 0 }}
    >
      {/* Persistent toggle: the TaskHeader row (the only other way in) scrolls
          away with the conversation, so the panel must stay reachable from a
          fixed spot. The button sits just left of the panel edge (-left-8), so
          when the panel is collapsed to width 0 it rests at the top-right edge
          of the chat — same place it occupies while open. Kept OUTSIDE the
          aria-hidden aside so it stays in the a11y tree when collapsed. (A
          call site without onOpen falls back to the old open-only button —
          never a visible dead control.) */}
      {(open || onOpen) && (
        <button
          type="button"
          onClick={open ? onClose : onOpen}
          aria-label={open ? 'Close panel' : 'Open task details'}
          className="absolute top-3 -left-8 h-6 w-6 rounded-md text-foreground-secondary hover:bg-background-subtle hover:text-foreground inline-flex items-center justify-center transition-colors z-20"
        >
          <PanelRight className="h-4 w-4" />
        </button>
      )}
      {/* Clip layer fills the (width-animated) wrapper; the panel inside is a
          FIXED-width slide-over so its content never squishes as it opens or
          closes — the wrapper reserves space (chat re-centers smoothly) while
          the panel just slides in/out over that space and gets clipped. */}
      <div className="relative h-full overflow-hidden">
        <aside
          className="absolute inset-y-0 right-0 border-l border-border overflow-hidden bg-background transition-transform duration-[220ms] ease-out"
          style={{ width, transform: open ? 'translateX(0)' : 'translateX(100%)' }}
          aria-hidden={!open}
        >
        {task && (
          <div className="flex h-full flex-col overflow-hidden bg-background">
            <div className="border-b border-border px-6 pt-4">
              <div className="flex items-start justify-between gap-3 pb-3">
                <div className="min-w-0 flex-1 text-base font-semibold leading-snug text-foreground">
                  {task.title}
                </div>
                {prUrl ? (
                  <Button asChild variant="white" className="shrink-0">
                    <a href={prUrl} target="_blank" rel="noreferrer">
                      View pull request
                    </a>
                  </Button>
                ) : task.status === 'working' ? (
                  <Button
                    variant="outline"
                    className="shrink-0"
                    onClick={onStop}
                    disabled={cancelling}
                  >
                    {cancelling ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Stop'}
                  </Button>
                ) : null}
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
                <ChangesTab netFiles={netFiles} diffs={diffs} prUrl={prUrl} loading={changesLoading} />
              )}
            </div>
          </div>
        )}
        </aside>
      </div>
    </div>
  );
}

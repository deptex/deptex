import { useEffect, useState } from 'react';
import { FileCode2, GitBranch, GitPullRequest, Loader2 } from 'lucide-react';
import { api, type FixRecord } from '../../lib/api';
import { supabase } from '../../lib/supabase';
import { Button } from '../ui/button';

// A change Aegis made, rendered inline in a task chat. apply_fix returns the
// real fixId; this subscribes to that fix row (same pattern as PlanCard) and
// shows live state: compact "Updated <file>" / "Opening pull request…" lines
// while the worker runs, then a full "Ready for review" PR card once the PR is
// open — styled like the settings cards.

interface ChangeCardData {
  fixId?: string;
  file?: string;
  summary?: string;
}

function parseStats(diff: string | null): { files?: number; additions?: number; deletions?: number } {
  if (!diff) return {};
  const files = diff.match(/(\d+)\s+files?\s+changed/)?.[1];
  const add = diff.match(/(\d+)\s+insertions?\(\+\)/)?.[1];
  const del = diff.match(/(\d+)\s+deletions?\(-\)/)?.[1];
  return {
    files: files ? Number(files) : undefined,
    additions: add ? Number(add) : undefined,
    deletions: del ? Number(del) : undefined,
  };
}

export function ChangeCard({ data }: { data?: ChangeCardData }) {
  const fixId = data?.fixId;
  const [fix, setFix] = useState<FixRecord | null>(null);

  useEffect(() => {
    if (!fixId) return;
    let cancelled = false;
    let channel: ReturnType<typeof supabase.channel> | null = null;
    const refresh = async () => {
      try {
        const { fix: refreshed } = await api.getFix(fixId);
        if (!cancelled) setFix(refreshed);
      } catch {
        /* realtime catches up */
      }
    };
    (async () => {
      const {
        data: { session },
      } = await supabase.auth.getSession();
      await (supabase.realtime as any).setAuth(session?.access_token ?? null);
      if (cancelled) return;
      await refresh();
      channel = supabase
        .channel(`change-card-${fixId}`)
        .on(
          'postgres_changes',
          { event: 'UPDATE', schema: 'public', table: 'project_security_fixes', filter: `id=eq.${fixId}` },
          () => void refresh(),
        )
        .subscribe();
    })();
    return () => {
      cancelled = true;
      if (channel) supabase.removeChannel(channel);
    };
  }, [fixId]);

  if (!data) return null;
  const status = fix?.status;
  const prUrl = fix?.prUrl ?? null;
  const prNumber = fix?.prNumber ?? null;
  const failed = status === 'failed' || status === 'rejected';

  // Completed with a PR → the rich "Ready for review" card.
  if (prUrl) {
    const title = fix?.plan?.summary ?? data.summary ?? 'Fix';
    const description = fix?.plan?.description ?? null;
    const branch = fix?.prBranch ?? null;
    const { files, additions, deletions } = parseStats(fix?.diffSummary ?? null);

    return (
      <div className="my-2 overflow-hidden rounded-lg border border-border bg-background-card">
        <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <GitPullRequest className="h-4 w-4 text-foreground-secondary" />
            <span className="text-sm font-semibold text-foreground">Ready for review</span>
          </div>
          {(additions != null || deletions != null) && (
            <div className="flex items-center gap-1.5 text-xs font-medium tabular-nums">
              {additions != null && (
                <span className="rounded bg-success/10 px-1.5 py-0.5 text-success">+{additions}</span>
              )}
              {deletions != null && (
                <span className="rounded bg-destructive/10 px-1.5 py-0.5 text-destructive">−{deletions}</span>
              )}
            </div>
          )}
        </div>

        <div className="space-y-3 px-4 py-3">
          {branch && (
            <div className="flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2 font-mono text-xs">
              <GitBranch className="h-3.5 w-3.5 shrink-0 text-foreground-secondary" />
              <span className="truncate text-foreground">{branch}</span>
            </div>
          )}
          <div className="text-sm font-medium leading-snug text-foreground">{title}</div>
          {description && (
            <div className="whitespace-pre-wrap text-sm leading-relaxed text-foreground-secondary">
              {description}
            </div>
          )}
        </div>

        <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-3">
          <span className="text-xs text-foreground-secondary">
            {files != null ? `${files} file${files === 1 ? '' : 's'} changed` : `PR #${prNumber}`}
          </span>
          <Button asChild variant="outline" size="sm">
            <a href={prUrl} target="_blank" rel="noreferrer">
              <GitPullRequest />
              View pull request{prNumber ? ` #${prNumber}` : ''}
            </a>
          </Button>
        </div>
      </div>
    );
  }

  // Failed / still working → compact lines.
  return (
    <div className="my-1 space-y-1.5 text-sm">
      {data.file && (
        <div className="flex items-center gap-2 text-foreground-secondary">
          <FileCode2 className="h-3.5 w-3.5 shrink-0" />
          <span>Updated</span>
          <code className="rounded bg-background-subtle px-1.5 py-0.5 font-mono text-[12px] text-foreground">
            {data.file}
          </code>
        </div>
      )}
      {failed ? (
        <div className="inline-flex items-center gap-1.5 text-foreground-secondary">
          <GitPullRequest className="h-3.5 w-3.5 shrink-0" />
          <span>Couldn&apos;t open a pull request</span>
        </div>
      ) : fixId ? (
        <div className="inline-flex items-center gap-1.5 text-foreground-secondary">
          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
          <span>Opening pull request…</span>
        </div>
      ) : null}
    </div>
  );
}

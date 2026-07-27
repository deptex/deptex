import { useEffect, useState } from 'react';
import { FileCode2, GitPullRequest, Loader2 } from 'lucide-react';
import { api, type FixRecord } from '../../lib/api';
import { supabase } from '../../lib/supabase';

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
  const failed = status === 'failed' || status === 'rejected';

  // A completed PR no longer renders inline — it lives in the task sidebar
  // (Changes / Pull request). The chat keeps only its closing text beat.
  if (prUrl) return null;

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

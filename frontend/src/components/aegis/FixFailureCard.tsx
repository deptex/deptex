import { useEffect, useState, type ReactNode } from 'react';
import { CircleAlert, ChevronDown, FileDiff, TerminalSquare } from 'lucide-react';
import { api, type FixRecord } from '../../lib/api';
import { supabase } from '../../lib/supabase';

// Rendered inline in a task chat when a fix FAILS. Subscribes to the fix row
// (same pattern as ChangeCard) and shows Aegis's work instead of a shrug: an
// honest, category-specific headline + explanation, an expandable "What I tried"
// (the diff it produced, even if it didn't apply) and "The error" (the real
// output), and a concrete next step. Backed by project_security_fixes.failure_details.

interface FixFailureCardData {
  fixId?: string;
}

// A raw udiff, line-coloured so the attempt is skimmable.
function DiffView({ diff }: { diff: string }) {
  const lines = diff.split('\n');
  return (
    <pre className="max-h-72 overflow-auto rounded-md border border-border bg-background px-3 py-2 text-[12px] leading-relaxed">
      {lines.map((ln, i) => {
        const cls = ln.startsWith('+') && !ln.startsWith('+++')
          ? 'text-success'
          : ln.startsWith('-') && !ln.startsWith('---')
            ? 'text-destructive'
            : ln.startsWith('@@')
              ? 'text-foreground-secondary'
              : 'text-foreground/80';
        return (
          <div key={i} className={`whitespace-pre-wrap break-all font-mono ${cls}`}>
            {ln || ' '}
          </div>
        );
      })}
    </pre>
  );
}

function Section({
  icon: Icon,
  title,
  defaultOpen,
  children,
}: {
  icon: typeof FileDiff;
  title: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(!!defaultOpen);
  return (
    <div className="rounded-md border border-border">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs font-medium text-foreground-secondary hover:text-foreground"
      >
        <Icon className="h-3.5 w-3.5 shrink-0" />
        <span className="flex-1">{title}</span>
        <ChevronDown className={`h-3.5 w-3.5 shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && <div className="px-3 pb-3">{children}</div>}
    </div>
  );
}

export function FixFailureCard({ data }: { data?: FixFailureCardData }) {
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
        .channel(`fail-card-${fixId}`)
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

  const d = fix?.failureDetails ?? null;
  const headline = d?.headline ?? "I couldn't complete this fix";
  const explanation = d?.explanation ?? fix?.errorMessage ?? null;
  const nextStep = d?.nextStep ?? null;
  const attemptedDiff = d?.attemptedDiff ?? null;
  const errorOutput = d?.errorOutput ?? null;

  return (
    <div className="my-2 overflow-hidden rounded-lg border border-border bg-background-card">
      {/* Neutral, shadcn-style card — a restrained amber glyph signals "didn't
          finish" without the aggressive red-error box. */}
      <div className="flex items-start gap-2.5 px-4 py-3">
        <CircleAlert className="mt-px h-4 w-4 shrink-0 text-amber-500/70" />
        <div className="min-w-0 flex-1 space-y-1">
          <div className="text-sm font-medium text-foreground">{headline}</div>
          {explanation && (
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-foreground-secondary">{explanation}</p>
          )}
        </div>
      </div>

      {(attemptedDiff || errorOutput) && (
        <div className="space-y-2 px-4 pb-3">
          {attemptedDiff && (
            <Section icon={FileDiff} title="What I tried" defaultOpen>
              <DiffView diff={attemptedDiff} />
            </Section>
          )}

          {errorOutput && (
            <Section icon={TerminalSquare} title="The error">
              <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background px-3 py-2 font-mono text-[12px] leading-relaxed text-foreground/80">
                {errorOutput}
              </pre>
            </Section>
          )}
        </div>
      )}

      {nextStep && (
        <div className="border-t border-border px-4 py-2.5 text-xs leading-relaxed text-foreground-secondary">
          {nextStep}
        </div>
      )}
    </div>
  );
}

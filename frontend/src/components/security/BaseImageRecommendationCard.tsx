import { useState } from 'react';
import { ArrowRight, ChevronDown, Loader2, ShieldCheck, ShieldAlert, HelpCircle } from 'lucide-react';
import { api, type BaseImageRecommendation } from '../../lib/api';
import { Button } from '../ui/button';
import { cn } from '../../lib/utils';

interface Props {
  organizationId: string;
  projectId: string;
  recommendation: BaseImageRecommendation;
  canManage: boolean;
  /** Called after a successful dismiss so the parent can drop the card. */
  onDismissed: (id: string) => void;
}

const VERDICT_STYLE: Record<
  BaseImageRecommendation['shell_compat_verdict'],
  { label: string; tone: string; Icon: typeof ShieldCheck }
> = {
  no_shell_required: {
    label: 'Likely safe drop-in',
    tone: 'bg-green-500/10 text-green-400 border-green-500/20',
    Icon: ShieldCheck,
  },
  shell_required: {
    label: 'Needs a shell — verify',
    tone: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    Icon: ShieldAlert,
  },
  unknown: {
    label: 'Compatibility unknown',
    tone: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20',
    Icon: HelpCircle,
  },
};

/**
 * One base-image upgrade recommendation. Renders either a real recommendation
 * (current image -> hardened alternative, CVE delta, shell-compat verdict,
 * runner-up alternatives) or an empty-state with a "suggest this family" CTA.
 */
export default function BaseImageRecommendationCard({
  organizationId,
  projectId,
  recommendation: rec,
  canManage,
  onDismissed,
}: Props) {
  const [busy, setBusy] = useState(false);
  const [suggested, setSuggested] = useState(false);
  const [showAlternatives, setShowAlternatives] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const isEmptyState = rec.recommended_image === null;
  // The verdict is "safe" only when the advisor's evidence says so explicitly.
  const verdictKey =
    rec.shell_compat_evidence?.likely_safe === true
      ? 'no_shell_required'
      : rec.shell_compat_verdict;
  const verdict = VERDICT_STYLE[verdictKey] ?? VERDICT_STYLE.unknown;

  async function handleDismiss() {
    setBusy(true);
    setActionError(null);
    try {
      await api.dismissBaseImageRecommendation(organizationId, projectId, rec.id);
      onDismissed(rec.id);
    } catch {
      setActionError('Could not dismiss this recommendation.');
      setBusy(false);
    }
  }

  async function handleSuggest() {
    setBusy(true);
    setActionError(null);
    try {
      await api.suggestBaseImage(organizationId, projectId, rec.current_image);
      setSuggested(true);
    } catch {
      setActionError('Could not send the suggestion.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-lg border border-border bg-background-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">
            {rec.dockerfile_path}
          </div>
          {isEmptyState ? (
            <div className="text-sm text-foreground-secondary">
              No hardened alternative for{' '}
              <code className="text-foreground">{rec.current_image}</code> in the catalog yet.
            </div>
          ) : (
            <div className="flex items-center gap-2 text-sm flex-wrap">
              <code className="text-foreground-secondary">{rec.current_image}</code>
              <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              <code className="text-foreground font-medium">{rec.recommended_image}</code>
            </div>
          )}
        </div>
        {!isEmptyState && canManage && (
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={handleDismiss}
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            Dismiss
          </Button>
        )}
      </div>

      {!isEmptyState && (
        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span
            className={cn(
              'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border',
              verdict.tone
            )}
          >
            <verdict.Icon className="h-3 w-3" />
            {verdict.label}
          </span>
          {typeof rec.cve_delta === 'number' && rec.cve_delta > 0 && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold border bg-green-500/10 text-green-400 border-green-500/20">
              −{rec.cve_delta} CVEs
            </span>
          )}
          {typeof rec.cve_delta === 'number' && rec.cve_delta <= 0 && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium border bg-foreground/5 text-foreground-secondary border-border">
              No CVE reduction
            </span>
          )}
          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium border bg-foreground/5 text-foreground-secondary border-border">
            Drop-in score {rec.drop_in_score}
          </span>
        </div>
      )}

      {!isEmptyState && rec.alternatives.length > 0 && (
        <div className="mt-3">
          <button
            type="button"
            className="inline-flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground transition-colors"
            onClick={() => setShowAlternatives((v) => !v)}
          >
            <ChevronDown
              className={cn('h-3.5 w-3.5 transition-transform', showAlternatives && 'rotate-180')}
            />
            {showAlternatives ? 'Hide' : 'See'} {rec.alternatives.length} other option
            {rec.alternatives.length === 1 ? '' : 's'}
          </button>
          {showAlternatives && (
            <ul className="mt-2 space-y-1.5 border-l border-border pl-3">
              {rec.alternatives.map((alt) => (
                <li key={alt.image} className="text-xs flex items-center gap-2 flex-wrap">
                  <code className="text-foreground-secondary">{alt.image}</code>
                  <span className="text-muted-foreground">{alt.provider}</span>
                  <span className="text-muted-foreground">· score {alt.drop_in_score}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {isEmptyState && canManage && (
        <div className="mt-3">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={busy || suggested}
            onClick={handleSuggest}
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {suggested ? 'Suggestion sent' : 'Suggest this image family'}
          </Button>
        </div>
      )}

      {actionError && (
        <div className="mt-2 text-xs text-destructive">{actionError}</div>
      )}
    </div>
  );
}

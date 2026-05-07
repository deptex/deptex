/**
 * Phase 6.5 — per-hop sanitizer badge. Renders the AI's sanitization verdict
 * for one taint flow as a sub-row beneath the chain. Mirrors EntryPointBadge
 * (button + Tooltip + cn + memo) so the two read consistently in the sidebar.
 *
 * Confidence-ladder rendering (OD-5 + OD-10 — single-source-of-truth via
 * `frontend/src/lib/security/confidence-thresholds.ts`, byte-equal-asserted
 * against the worker's MAX-vote threshold so users never see "uncertain"
 * while depscore moves anyway):
 *
 *   - confidence < HIDE_BELOW (0.5)        → returns null (hide entirely)
 *   - HIDE_BELOW <= c < UNCERTAIN_UPPER    → "AI uncertain — review" (amber)
 *   - confidence >= UNCERTAIN_UPPER (0.75) → confident (green / red)
 *   - is_sanitized === null                → "AI couldn't verify" (amber)
 *
 * The sanitizer_line citation is only rendered when confidence is in the
 * confident band (server-side validates the line per M4 task 24.5; UI
 * suppresses it for the uncertain band even if a line came back).
 */
import { memo } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { cn } from '../../lib/utils';
import { HIDE_BELOW, UNCERTAIN_UPPER } from '../../lib/security/confidence-thresholds';

type Variant = 'sanitized' | 'leak' | 'uncertain' | 'unverifiable';

const STYLES: Record<Variant, { label: string; cls: string; emoji: string }> = {
  sanitized:    { label: 'Sanitized',         cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',                 emoji: '\u{2713}' },
  leak:         { label: 'Unsanitized',       cls: 'bg-red-500/10 text-red-400 border-red-500/20',                              emoji: '\u{26A0}\u{FE0F}' },
  uncertain:    { label: 'AI uncertain — review', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/20',                    emoji: '?' },
  unverifiable: { label: "AI couldn't verify",    cls: 'bg-amber-500/10 text-amber-400 border-amber-500/20',                    emoji: '?' },
};

const TOOLTIP_HINT: Record<Variant, string> = {
  sanitized:    'AI verified a sanitizer call between source and sink for this flow.',
  leak:         'AI did not find a sanitizer between source and sink — review this flow.',
  uncertain:    "AI is not confident on this verdict — review the chain manually.",
  unverifiable: "AI didn't have a verifiable sanitizer candidate for this flow.",
};

interface SanitizerBadgeProps {
  /** AI sanitization verdict. `null` means AI couldn't pick a candidate. */
  isSanitized: boolean | null | undefined;
  /** Confidence in [0,1]. Drives the ladder above. */
  confidence: number | null | undefined;
  /** Validated sanitizer line, server-validated. Only rendered in the confident band. */
  sanitizerLine?: number | null;
  /** Visually smaller badge for dense rows. Default false. */
  compact?: boolean;
}

function SanitizerBadgeBase({ isSanitized, confidence, sanitizerLine, compact = false }: SanitizerBadgeProps) {
  // Treat missing inputs the same as "AI couldn't verify" — the row stays
  // visible (ambient amber) instead of disappearing without explanation.
  if (isSanitized === null) {
    return renderBadge('unverifiable', null, compact);
  }
  if (isSanitized === undefined || confidence == null) {
    return null;
  }

  if (confidence < HIDE_BELOW) return null;
  if (confidence < UNCERTAIN_UPPER) {
    return renderBadge('uncertain', null, compact);
  }
  return renderBadge(isSanitized ? 'sanitized' : 'leak', sanitizerLine ?? null, compact);
}

function renderBadge(variant: Variant, sanitizerLine: number | null, compact: boolean) {
  const style = STYLES[variant];
  const hint = TOOLTIP_HINT[variant];
  const lineSuffix = sanitizerLine != null ? ` (line ${sanitizerLine})` : '';
  const ariaLabel = `${style.label}${lineSuffix}. ${hint}`;

  return (
    <Tooltip delayDuration={150}>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={ariaLabel}
          className={cn(
            'inline-flex items-center gap-1 rounded border font-medium text-[10px]',
            compact ? 'px-1 py-0' : 'px-1.5 py-0.5',
            'outline-none focus-visible:ring-2 focus-visible:ring-primary/60',
            style.cls,
          )}
        >
          <span aria-hidden>{style.emoji}</span>
          {style.label}
          {sanitizerLine != null && (
            <span className="text-foreground-secondary">:{sanitizerLine}</span>
          )}
        </button>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs space-y-1">
        <p className="font-medium">{style.label}</p>
        <p className="text-foreground-secondary">{hint}</p>
      </TooltipContent>
    </Tooltip>
  );
}

export const SanitizerBadge = memo(SanitizerBadgeBase);

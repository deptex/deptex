/**
 * EPD entry-point badge. Renders next to the depscore badge on every
 * reachable vuln row so users see at a glance whether the vulnerable
 * code is reached from a public unauthenticated endpoint (red), an
 * authenticated path (amber), or a background worker (gray).
 *
 * Pattern borrowed from Endor Labs — name the entry point inline on
 * the vuln row rather than burying the EPD multiplier as a number.
 *
 * Returns null when the classification is missing or UNKNOWN so the
 * UI quietly absents the badge instead of rendering a placeholder.
 *
 * Wrapped in a <button> rather than a <span> so the Radix tooltip is
 * keyboard-reachable (a non-focusable trigger leaves the disambiguating
 * tooltip text invisible to keyboard-only and screen-reader users —
 * WCAG 2.1 SC 2.1.1 / SC 1.4.13). The TooltipProvider lives at the app
 * root (main.tsx); we don't re-mount one per badge instance.
 */
import { memo } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip';
import { cn } from '../../lib/utils';
import type { EpdEntryPointClassification, EpdStatus } from '../../lib/api';

type StyleDef = { label: string; cls: string; emoji: string };

const STYLES: Record<Exclude<EpdEntryPointClassification, 'UNKNOWN'>, StyleDef> = {
  PUBLIC_UNAUTH:  { label: 'Public',        cls: 'bg-red-500/10 text-red-400 border-red-500/20',                                     emoji: '\u{1F513}' },
  AUTH_INTERNAL:  { label: 'Authenticated', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/20',                               emoji: '\u{1F510}' },
  OFFLINE_WORKER: { label: 'Background',    cls: 'bg-foreground-secondary/10 text-foreground-secondary border-border',               emoji: '⚙️' },
};

const STATUS_HINT: Record<EpdStatus, string> = {
  // legacy (Phase 4)
  ai_verified:       'Verified by AI against your repository source.',
  fallback_no_ai:    'AI verification skipped for this reachability level.',
  ai_error_fallback: 'AI call failed; heuristic classification applied.',
  budget_exceeded:   'AI verification budget reached this extraction; heuristic classification applied for the rest.',
  pending:           'EPD evaluation has not run yet for this vulnerability.',
  // Phase 6.5 — flow aggregator (M5)
  flow_aggregated:        'EPD computed from worst-case of per-flow AI verdicts on this dependency.',
  no_flows_evaluated:     'No reachable flows met the confidence + suppression filters.',
  all_flows_suppressed:   'All flows for this vulnerability have been user-suppressed.',
  ai_truncated:           'AI response exceeded max tokens; verdict skipped from depscore aggregation.',
  // Phase 6.5 — gated Anthropic fallback (OD-6)
  ai_verified_anthropic_fallback:                  'Triple verdict was degraded; verified by Anthropic fallback.',
  ai_verified_anthropic_fallback_failed:           'Anthropic fallback errored; depscore from Qwen aggregator only — review manually.',
  ai_verified_anthropic_fallback_skipped_cost_cap: 'Anthropic fallback skipped because the monthly cost cap was reached; depscore from Qwen aggregator only.',
  ai_verified_anthropic_fallback_skipped_burn_breaker: 'Anthropic fallback skipped because this extraction hit the per-extraction cost-burn breaker; depscore from Qwen aggregator only.',
};

interface EntryPointBadgeProps {
  classification: EpdEntryPointClassification | null | undefined;
  status: EpdStatus | null | undefined;
  /** Visually smaller badge for dense rows. Default false. */
  compact?: boolean;
}

function EntryPointBadgeBase({ classification, status, compact = false }: EntryPointBadgeProps) {
  if (!classification || classification === 'UNKNOWN') return null;
  const style = STYLES[classification];
  if (!style) return null;
  const hint = status ? STATUS_HINT[status] : null;
  const ariaLabel = `Entry point: ${style.label}${hint ? '. ' + hint : ''}`;

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
        </button>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs space-y-1">
        <p className="font-medium">Entry point: {style.label}</p>
        {hint && <p className="text-foreground-secondary">{hint}</p>}
      </TooltipContent>
    </Tooltip>
  );
}

export const EntryPointBadge = memo(EntryPointBadgeBase);

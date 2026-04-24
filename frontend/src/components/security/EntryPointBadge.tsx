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
 */
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../ui/tooltip';
import { cn } from '../../lib/utils';
import type { EpdEntryPointClassification, EpdStatus } from '../../lib/api';

type StyleDef = { label: string; cls: string; emoji: string };

const STYLES: Record<Exclude<EpdEntryPointClassification, 'UNKNOWN'>, StyleDef> = {
  PUBLIC_UNAUTH:  { label: 'Public',        cls: 'bg-red-500/10 text-red-400 border-red-500/20',                                     emoji: '\u{1F513}' },
  AUTH_INTERNAL:  { label: 'Authenticated', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/20',                               emoji: '\u{1F510}' },
  OFFLINE_WORKER: { label: 'Background',    cls: 'bg-foreground-secondary/10 text-foreground-secondary border-border',               emoji: '⚙️' },
};

const STATUS_HINT: Record<EpdStatus, string> = {
  ai_verified:       'Verified by AI against your repository source.',
  byok_missing:      'Heuristic classification — configure Anthropic BYOK in AI Configuration to enable AI verification.',
  fallback_no_ai:    'AI verification skipped for this reachability level.',
  ai_error_fallback: 'AI call failed; heuristic classification applied.',
  budget_exceeded:   'AI verification budget reached this extraction; heuristic classification applied for the rest.',
};

interface EntryPointBadgeProps {
  classification: EpdEntryPointClassification | null | undefined;
  status: EpdStatus | null | undefined;
  /** Visually smaller badge for dense rows. Default false. */
  compact?: boolean;
}

export function EntryPointBadge({ classification, status, compact = false }: EntryPointBadgeProps) {
  if (!classification || classification === 'UNKNOWN') return null;
  const style = STYLES[classification];
  if (!style) return null;
  const hint = status ? STATUS_HINT[status] : null;

  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className={cn(
              'inline-flex items-center gap-1 rounded border font-medium',
              compact ? 'px-1 py-0 text-[9px]' : 'px-1.5 py-0.5 text-[10px]',
              style.cls,
            )}
          >
            <span aria-hidden>{style.emoji}</span>
            {style.label}
          </span>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs space-y-1">
          <p className="font-medium">Entry point: {style.label}</p>
          {hint && <p className="text-foreground-secondary">{hint}</p>}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

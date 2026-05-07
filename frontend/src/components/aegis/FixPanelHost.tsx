import { useCallback, useEffect, useState, type MouseEvent as ReactMouseEvent } from 'react';
import { PanelRight } from 'lucide-react';
import { cn } from '../../lib/utils';
import { useFixPanel } from './FixPanelContext';
import { FixPanel } from './FixPanel';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '../ui/tooltip';

const PANEL_MIN = 360;
const PANEL_MAX_RATIO = 0.7;
const PANEL_DEFAULT_RATIO = 1 / 3;
// Bumped to v3 (~one-third viewport) so prior saves don't pin people to
// the older defaults. Once a user resizes, the new key takes over.
const PANEL_KEY = 'aegis-plan-panel-width-v3';
const ANIMATION_MS = 220;
const DIVIDER_WIDTH = 4;

function defaultWidth(): number {
  if (typeof window === 'undefined') return 480;
  const half = Math.floor(window.innerWidth * PANEL_DEFAULT_RATIO);
  const max = Math.floor(window.innerWidth * PANEL_MAX_RATIO);
  return Math.max(PANEL_MIN, Math.min(half, max));
}

function readStoredWidth() {
  if (typeof window === 'undefined') return defaultWidth();
  const stored = window.localStorage.getItem(PANEL_KEY);
  const parsed = stored ? parseInt(stored, 10) : NaN;
  return Number.isFinite(parsed) ? Math.max(parsed, PANEL_MIN) : defaultWidth();
}

export function FixPanelHost() {
  const { activeFixId, view, fixes, openFix, closeFix, showList } = useFixPanel();
  const [panelWidth, setPanelWidth] = useState<number>(readStoredWidth);
  const [isDragging, setIsDragging] = useState(false);
  // Holds the fixId currently visible in the panel — including during the
  // closing animation. When activeFixId flips to null, we keep this set for
  // ANIMATION_MS so FixPanel doesn't unmount and pop the content out before
  // the panel has finished collapsing.
  const [renderedFixId, setRenderedFixId] = useState<string | null>(activeFixId);

  useEffect(() => {
    if (activeFixId) {
      setRenderedFixId(activeFixId);
      return;
    }
    const t = setTimeout(() => setRenderedFixId(null), ANIMATION_MS);
    return () => clearTimeout(t);
  }, [activeFixId]);

  const startResize = useCallback((e: ReactMouseEvent) => {
    e.preventDefault();
    setIsDragging(true);
    const startX = e.clientX;
    const startWidth = panelWidth;
    const maxWidth = Math.floor(window.innerWidth * PANEL_MAX_RATIO);
    const clamp = (n: number) => Math.min(Math.max(n, PANEL_MIN), maxWidth);
    const onMove = (ev: globalThis.MouseEvent) => {
      setPanelWidth(clamp(startWidth - (ev.clientX - startX)));
    };
    const onUp = (ev: globalThis.MouseEvent) => {
      const next = clamp(startWidth - (ev.clientX - startX));
      window.localStorage.setItem(PANEL_KEY, String(next));
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      setIsDragging(false);
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, [panelWidth]);

  // The panel is "open" when there's a fix to render in detail OR when the
  // user is browsing the list. Both modes share the same width animation.
  const isOpen = activeFixId !== null || view === 'list';
  const wrapperWidth = isOpen ? panelWidth + DIVIDER_WIDTH : 0;

  // The toggle button is visible whenever the panel is open OR the thread
  // has at least one fix (so the user can re-open the panel after
  // dismissing). Hidden entirely when no fixes exist so it doesn't clutter
  // regular Aegis chats.
  const showToggle = isOpen || fixes.length > 0;
  const togglePanel = useCallback(() => {
    if (isOpen) {
      closeFix();
      return;
    }
    // Re-open: list view if multiple plans, single fix detail if one.
    if (fixes.length >= 2) {
      showList();
    } else if (fixes.length === 1) {
      openFix(fixes[0].id);
    }
  }, [isOpen, fixes, openFix, showList, closeFix]);

  return (
    <div
      className={cn(
        'flex flex-shrink-0 relative',
        !isDragging && 'transition-[width] duration-[220ms] ease-out',
      )}
      style={{ width: wrapperWidth }}
      aria-hidden={!isOpen}
    >
      {/* Resize divider — narrow vertical strip at the panel's left edge. */}
      <div className="relative flex-shrink-0 w-1">
        <div
          onMouseDown={startResize}
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize fix panel"
          className="absolute inset-0 cursor-col-resize hover:bg-foreground/15 active:bg-foreground/25 transition-colors"
        />
      </div>
      {/* Panel toggle — always visible at the top, sitting OUTSIDE the
          panel on the chat side. Stays visible after the user dismisses
          (so they can re-open) as long as the thread has any registered
          fixes; hidden on a fresh Aegis chat with no fixes yet. */}
      {showToggle && (
        <TooltipProvider delayDuration={200}>
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                type="button"
                onClick={togglePanel}
                aria-label={isOpen ? 'Close panel' : 'Open panel'}
                className="absolute top-3 -left-8 h-6 w-6 rounded-md text-foreground-secondary hover:bg-background-subtle hover:text-foreground inline-flex items-center justify-center transition-colors z-20"
              >
                <PanelRight className="h-4 w-4" />
              </button>
            </TooltipTrigger>
            <TooltipContent side="left" sideOffset={6}>
              {isOpen ? 'Close panel' : 'Open panel'}
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      )}
      <aside className="flex-1 border-l border-border overflow-hidden">
        {(renderedFixId || view === 'list') && (
          <FixPanel fixId={renderedFixId} onClose={closeFix} />
        )}
      </aside>
    </div>
  );
}

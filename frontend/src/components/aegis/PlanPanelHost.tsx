import { useCallback, useEffect, useState, type MouseEvent as ReactMouseEvent } from 'react';
import { cn } from '../../lib/utils';
import { usePlanPanel } from './PlanPanelContext';
import { PlanPanel } from './PlanPanel';

const PANEL_MIN = 360;
const PANEL_MAX_RATIO = 0.7;
const PANEL_DEFAULT = 480;
const PANEL_KEY = 'aegis-plan-panel-width';
const ANIMATION_MS = 220;
const DIVIDER_WIDTH = 4;

function readStoredWidth() {
  if (typeof window === 'undefined') return PANEL_DEFAULT;
  const stored = window.localStorage.getItem(PANEL_KEY);
  const parsed = stored ? parseInt(stored, 10) : NaN;
  return Number.isFinite(parsed) ? Math.max(parsed, PANEL_MIN) : PANEL_DEFAULT;
}

export function PlanPanelHost() {
  const { activeFixId, closePlan } = usePlanPanel();
  const [panelWidth, setPanelWidth] = useState<number>(readStoredWidth);
  const [isDragging, setIsDragging] = useState(false);
  // Holds the fixId currently visible in the panel — including during the
  // closing animation. When activeFixId flips to null, we keep this set for
  // ANIMATION_MS so PlanPanel doesn't unmount and pop the content out before
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

  const isOpen = activeFixId !== null;
  const wrapperWidth = isOpen ? panelWidth + DIVIDER_WIDTH : 0;

  return (
    <div
      className={cn(
        'flex flex-shrink-0 overflow-hidden',
        !isDragging && 'transition-[width] duration-[220ms] ease-out',
      )}
      style={{ width: wrapperWidth }}
      aria-hidden={!isOpen}
    >
      <div
        onMouseDown={startResize}
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize plan panel"
        className="w-1 cursor-col-resize hover:bg-foreground/15 active:bg-foreground/25 transition-colors flex-shrink-0"
      />
      <aside className="flex-1 border-l border-border overflow-hidden">
        {renderedFixId && <PlanPanel fixId={renderedFixId} onClose={closePlan} />}
      </aside>
    </div>
  );
}

import { useEffect, useRef } from 'react';
import { useStoreApi } from '@xyflow/react';
import { isCanvasDragging } from './canvasDragSignal';

const GRID_SPACING = 20;
const MIN_SCREEN_SPACING = 10;
const DOT_BASE_RADIUS = 0.7;
const DOT_MAX_RADIUS = 1.1;
const DOT_BASE_OPACITY = 0.18;
const DOT_MAX_OPACITY = 0.28;
const INFLUENCE_RADIUS = 130;

export function ReactiveDotGrid() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const storeApi = useStoreApi();
  const viewportRef = useRef({ x: 0, y: 0, zoom: 1 });
  const cursorRef = useRef<{ x: number; y: number } | null>(null);
  const dirtyRef = useRef(true);

  // Imperative store subscription — no React re-renders on pan/zoom.
  useEffect(() => {
    const { transform } = storeApi.getState();
    viewportRef.current = { x: transform[0], y: transform[1], zoom: transform[2] };
    return storeApi.subscribe((state) => {
      const [x, y, zoom] = state.transform;
      viewportRef.current = { x, y, zoom };
      dirtyRef.current = true;
    });
  }, [storeApi]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const pane = canvas.parentElement;
    if (!pane) return;

    const handleMove = (e: PointerEvent) => {
      const rect = pane.getBoundingClientRect();
      cursorRef.current = { x: e.clientX - rect.left, y: e.clientY - rect.top };
      if (!isCanvasDragging()) dirtyRef.current = true;
    };
    const handleLeave = () => {
      cursorRef.current = null;
      dirtyRef.current = true;
    };

    pane.addEventListener('pointermove', handleMove);
    pane.addEventListener('pointerleave', handleLeave);
    return () => {
      pane.removeEventListener('pointermove', handleMove);
      pane.removeEventListener('pointerleave', handleLeave);
    };
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const pane = canvas.parentElement;
    if (!pane) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const resize = () => {
      const rect = pane.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      canvas.width = Math.max(1, Math.floor(rect.width * dpr));
      canvas.height = Math.max(1, Math.floor(rect.height * dpr));
      canvas.style.width = `${rect.width}px`;
      canvas.style.height = `${rect.height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      dirtyRef.current = true;
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(pane);

    let raf = 0;
    const draw = () => {
      if (dirtyRef.current) {
        const w = canvas.clientWidth;
        const h = canvas.clientHeight;
        ctx.clearRect(0, 0, w, h);

        const vp = viewportRef.current;
        const zoom = vp.zoom || 1;

        let stepMultiplier = 1;
        while (GRID_SPACING * zoom * stepMultiplier < MIN_SCREEN_SPACING) {
          stepMultiplier *= 2;
        }
        const flowStep = GRID_SPACING * stepMultiplier;

        const startFlowX = Math.floor((-vp.x / zoom) / flowStep) * flowStep;
        const endFlowX = (w - vp.x) / zoom + flowStep;
        const startFlowY = Math.floor((-vp.y / zoom) / flowStep) * flowStep;
        const endFlowY = (h - vp.y) / zoom + flowStep;

        const cursor = cursorRef.current;
        const sigma = INFLUENCE_RADIUS / 2;
        const twoSigmaSq = 2 * sigma * sigma;
        const influenceSq = INFLUENCE_RADIUS * INFLUENCE_RADIUS;

        ctx.fillStyle = '#ffffff';
        for (let fx = startFlowX; fx <= endFlowX; fx += flowStep) {
          for (let fy = startFlowY; fy <= endFlowY; fy += flowStep) {
            const sx = fx * zoom + vp.x;
            const sy = fy * zoom + vp.y;
            if (sx < -4 || sy < -4 || sx > w + 4 || sy > h + 4) continue;

            let t = 0;
            if (cursor) {
              const dx = sx - cursor.x;
              const dy = sy - cursor.y;
              const distSq = dx * dx + dy * dy;
              if (distSq < influenceSq) t = Math.exp(-distSq / twoSigmaSq);
            }
            const r = DOT_BASE_RADIUS + (DOT_MAX_RADIUS - DOT_BASE_RADIUS) * t;
            const a = DOT_BASE_OPACITY + (DOT_MAX_OPACITY - DOT_BASE_OPACITY) * t;
            ctx.globalAlpha = a;
            ctx.beginPath();
            ctx.arc(sx, sy, r, 0, Math.PI * 2);
            ctx.fill();
          }
        }
        ctx.globalAlpha = 1;
        dirtyRef.current = false;
      }
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none absolute inset-0"
      style={{ zIndex: 0 }}
      aria-hidden
    />
  );
}

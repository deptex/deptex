import { useEffect, useRef } from "react";

/**
 * DotSheet — a perspective-projected, folded sheet of halftone dots
 * (Snyk-hero treatment, in brand green). Meant to sit UNDER a floating
 * panel: the sheet recedes toward a horizon hidden behind the panel, and
 * rolling folds sweep across it.
 *
 * Why canvas + projection: the reference look is not a flat dot grid —
 * the rows compress toward the horizon (perspective), the surface
 * undulates (the grid itself warps), and wave crests "catch light"
 * (bigger, brighter dots) while troughs nearly vanish. None of that is
 * expressible as a CSS background.
 *
 * Etiquette: ~30fps clamp, pauses offscreen + on tab hide,
 * prefers-reduced-motion renders one static frame, DPR capped at 2.
 */
export default function DotSheet({ className = "" }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return; // jsdom / very old browsers

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const COLS = 130;
    const ROWS = 30;
    const PERSP = 2.6; // perspective strength — row compression toward horizon
    const HORIZON = 0.0; // horizon at the canvas top (tucked under the panel edge)
    const LIFT = 20; // fold height in px at the near edge

    let w = 0;
    let h = 0;

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = rect.width;
      h = rect.height;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const draw = (t: number) => {
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = "#34d08a";
      const cx = w / 2;
      for (let row = 0; row < ROWS; row++) {
        const pv = row / (ROWS - 1); // 0 = near (bottom), 1 = far (horizon)
        const s = 1 / (1 + pv * PERSP); // perspective scale for this row
        const yBase = (HORIZON + (1 - HORIZON) * ((1 - pv) / (1 + pv * PERSP))) * h;
        const spread = 0.6 + 0.4 * s; // far rows narrow toward the panel width
        for (let col = 0; col < COLS; col++) {
          const u = col / (COLS - 1) - 0.5; // -0.5 .. 0.5 across the sheet
          // The fold field: three slow interfering waves over the surface
          const z =
            0.5 * Math.sin(u * 6.5 + t) +
            0.3 * Math.sin(u * 11.0 - pv * 7.0 + t * 0.55) +
            0.35 * Math.sin(pv * 9.0 + u * 2.0 - t * 0.35);
          const x = cx + u * w * spread;
          const y = yBase - z * LIFT * s;
          // Crest lighting: high z = big bright dots, troughs vanish entirely
          // (the missing-dot gaps are what make it read as folded fabric)
          const b = Math.max(0, 0.5 + 0.55 * z);
          const r = (0.3 + 1.1 * b) * 3.6 * s;
          if (r < 0.35) continue;
          // Edge dissolves: sides, the emergence line under the panel, bottom
          const yn = y / h;
          const fadeX = Math.min(1, (0.5 - Math.abs(u)) / 0.13);
          // Long top fade: the chapter-rail text lives in the sheet's first
          // ~third, so density blooms only below it
          const fadeT = Math.min(1, yn / 0.34);
          const fadeB = Math.min(1, (1 - yn) / 0.16);
          const a =
            (0.06 + 0.6 * b) *
            Math.max(0, fadeX) *
            Math.max(0, fadeT) *
            Math.max(0, Math.min(1, fadeB));
          if (a < 0.02) continue;
          ctx.globalAlpha = Math.min(0.75, a);
          ctx.beginPath();
          ctx.arc(x, y, r, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      ctx.globalAlpha = 1;
    };

    let raf = 0;
    let last = 0;
    let inView = true;
    const FRAME_MS = 33;

    const tick = (now: number) => {
      raf = requestAnimationFrame(tick);
      if (now - last < FRAME_MS) return;
      last = now;
      draw(now * 0.0004);
    };

    const start = () => {
      if (!raf && !reduced) raf = requestAnimationFrame(tick);
    };
    const stop = () => {
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
    };
    const sync = () => {
      if (inView && !document.hidden) start();
      else stop();
    };

    resize();
    draw(0);
    sync();

    const io = new IntersectionObserver(
      ([entry]) => {
        inView = entry.isIntersecting;
        sync();
      },
      { threshold: 0 }
    );
    io.observe(canvas);

    const onVis = () => sync();
    document.addEventListener("visibilitychange", onVis);

    const ro =
      typeof ResizeObserver !== "undefined"
        ? new ResizeObserver(() => {
            resize();
            draw(0);
          })
        : null;
    ro?.observe(canvas);

    return () => {
      stop();
      io.disconnect();
      ro?.disconnect();
      document.removeEventListener("visibilitychange", onVis);
    };
  }, []);

  return <canvas ref={canvasRef} className={className} aria-hidden />;
}

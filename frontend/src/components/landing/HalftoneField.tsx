import { useEffect, useRef } from "react";

/**
 * HalftoneField — Snyk-style halftone dot atmosphere, in brand green.
 *
 * The difference from a CSS dot grid (which reads as speckle noise): this is
 * a true halftone — every dot's RADIUS is modulated by a slowly-flowing wave
 * field, so the dots form organic contour bands that swell and shrink, dense
 * and large near the anchor corners, dissolving to nothing toward the middle.
 * That per-dot size variation needs a canvas; CSS background dots are all
 * identical by construction.
 *
 * Perf/etiquette: ~30fps clamp, pauses offscreen (IntersectionObserver) and
 * on tab hide; prefers-reduced-motion renders one static frame; DPR capped
 * at 2; the wave field is two interfering sines (no noise lib).
 */
export default function HalftoneField({ className = "" }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return; // jsdom / very old browsers

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const SPACING = 19; // grid pitch in CSS px
    const MAX_R = 5.2; // largest dot radius — halftone reads via size ratio, so be bold

    let w = 0;
    let h = 0;
    let pts: { x: number; y: number; m: number }[] = [];

    const rebuild = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = rect.width;
      h = rect.height;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      // Precompute the static density mask: two big elliptical lobes anchored
      // at the top corners, sweeping down the page edges. The headline zone
      // in the middle stays clear.
      pts = [];
      for (let y = SPACING / 2; y < h; y += SPACING) {
        for (let x = SPACING / 2; x < w; x += SPACING) {
          const dl = Math.hypot(x / (w * 0.34), y / (h * 1.05));
          const dr = Math.hypot((w - x) / (w * 0.34), y / (h * 1.05));
          const m = Math.max(0, Math.max(1 - dl, 1 - dr));
          if (m > 0.03) pts.push({ x, y, m: Math.pow(m, 1.4) });
        }
      }
    };

    const draw = (t: number) => {
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = "#34d08a";
      for (const p of pts) {
        // Two slow interfering waves → flowing halftone contour bands.
        // Base floor keeps the lobe body present; the bands modulate on top.
        const w1 = Math.sin(p.x * 0.0085 + p.y * 0.014 + t);
        const w2 = Math.sin(p.x * 0.013 - p.y * 0.008 - t * 0.62);
        const band = 0.35 + 0.65 * (0.5 + 0.25 * w1 + 0.25 * w2);
        const i = p.m * band;
        const r = Math.pow(i, 0.8) * MAX_R;
        if (r < 0.4) continue;
        ctx.globalAlpha = Math.min(0.85, 0.15 + i * 1.1);
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalAlpha = 1;
    };

    let raf = 0;
    let last = 0;
    let inView = true;
    const FRAME_MS = 33; // ~30fps is plenty for this drift speed

    const tick = (now: number) => {
      raf = requestAnimationFrame(tick);
      if (now - last < FRAME_MS) return;
      last = now;
      draw(now * 0.00028);
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

    rebuild();
    draw(0); // static first frame (also the only frame under reduced motion)
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
            rebuild();
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

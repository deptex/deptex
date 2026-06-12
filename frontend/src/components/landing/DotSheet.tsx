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
export default function DotSheet({
  className = "",
  fadeTop = 0.34,
  fadeBottom = 0.16,
  fadeSides = 0.13,
  clearCenter,
}: {
  className?: string;
  /** Edge dissolve lengths as fractions of the canvas (top default is long
   * for the under-panel mount, where the chapter rail needs legibility). */
  fadeTop?: number;
  fadeBottom?: number;
  fadeSides?: number;
  /** Elliptical clearance pocket (all values are fractions of the canvas) —
   * used when text sits on top of the sheet, e.g. the hero headline. */
  clearCenter?: { cx: number; cy: number; rx: number; ry: number };
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return; // jsdom / very old browsers

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const COLS = 140;
    const ROWS = 36; // row pitch vs LIFT is the fold ratio: amplitude ~1.5× the
    // mid-field row gap folds the surface without occluding most of it
    const PERSP = 2.6; // perspective strength — row compression toward horizon
    const HORIZON = 0.0; // horizon at the canvas top (tucked under the panel edge)
    const LIFT = 34; // fold amplitude in px at the near edge — must exceed the
    // local row gap to fold, but not by so much that the whole surface
    // becomes silhouette (occluded/stretched = dark)

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

    // Per-row projection constants (no displacement): pv, scale, base y,
    // nominal gap to the previous (farther) row, spread. Far → near order.
    type Row = { pv: number; s: number; yBase: number; g0: number; spread: number };
    const rows: Row[] = [];
    for (let i = 0; i < ROWS; i++) {
      const pv = 1 - i / (ROWS - 1); // i=0 far (horizon) → i=ROWS-1 near
      const s = 1 / (1 + pv * PERSP);
      const yBase = (HORIZON + (1 - HORIZON) * ((1 - pv) / (1 + pv * PERSP))) * 1; // ×h at draw
      rows.push({ pv, s, yBase, g0: 0, spread: 0.6 + 0.4 * s });
    }
    for (let i = 1; i < ROWS; i++) rows[i].g0 = rows[i].yBase - rows[i - 1].yBase;
    rows[0].g0 = rows[1]?.g0 ?? 0.01;

    // The fold field — two big diagonal drape folds + finer ripple. Static
    // phase offsets keep the composition asymmetric/organic; t only drifts
    // it very slowly (the 3D reading must come from geometry, not motion).
    const fold = (u: number, pv: number, t: number) =>
      Math.sin(u * 3.1 + pv * 1.4 + 0.7 + t) +
      0.55 * Math.sin(u * 7.3 - pv * 3.8 + 2.1 + t * 0.55) +
      0.35 * Math.sin(u * 12.7 + pv * 8.5 + 4.2 - t * 0.35);

    const draw = (t: number) => {
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = "#34d08a";
      const cx = w / 2;
      // Column-major walk, far → near per column, so we can (a) shade by row
      // COMPRESSION — the fabric cue: rows bunch into bright creases where a
      // fold faces the camera, stretch dim where it falls away — and (b) hide
      // dots tucked behind a fold front (the occlusion gaps).
      for (let col = 0; col < COLS; col++) {
        const u = col / (COLS - 1) - 0.5; // -0.5 .. 0.5 across the sheet
        let prevY: number | null = null;
        let maxY = -Infinity; // silhouette: the nearest surface drawn so far
        for (let i = 0; i < ROWS; i++) {
          const row = rows[i];
          const z = fold(u, row.pv, t);
          const x = cx + u * w * row.spread;
          const y = row.yBase * h - z * LIFT * row.s;
          // Row compression vs the undisplaced gap → slope shading
          const comp = prevY === null ? 1 : (y - prevY) / Math.max(1, row.g0 * h);
          prevY = y;
          // Behind an already-drawn fold front → occluded (this gap IS the fold)
          if (y < maxY - 1.5) continue;
          maxY = Math.max(maxY, y);
          // High dynamic range is what makes the creases pop: neutral rows
          // stay small and dim, bunched rows blow up bright
          const light = Math.max(0.06, Math.min(1.8, 1.6 - 1.1 * comp));
          const r = (0.25 + 1.05 * light) * 3.8 * row.s;
          if (r < 0.35) continue;
          // Edge dissolves: sides / top emergence line / bottom
          const yn = y / h;
          const fadeX = Math.min(1, (0.5 - Math.abs(u)) / fadeSides);
          const fadeT = Math.min(1, yn / fadeTop);
          const fadeB = Math.min(1, (1 - yn) / fadeBottom);
          // Clearance pocket for overlaid text: fade to zero inside the
          // ellipse, ramp back to full just past its rim
          let fadeC = 1;
          if (clearCenter) {
            const d = Math.hypot(
              (x / w - clearCenter.cx) / clearCenter.rx,
              (yn - clearCenter.cy) / clearCenter.ry
            );
            fadeC = Math.max(0, Math.min(1, (d - 1) / 0.35));
          }
          const a =
            (0.04 + 0.5 * light) *
            Math.max(0, fadeX) *
            Math.max(0, fadeT) *
            Math.max(0, Math.min(1, fadeB)) *
            fadeC;
          if (a < 0.02) continue;
          ctx.globalAlpha = Math.min(0.9, a);
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
      draw(now * 0.00022); // barely-drifting — Snyk's is static; ours just breathes
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fadeTop, fadeBottom, fadeSides, clearCenter?.cx, clearCenter?.cy, clearCenter?.rx, clearCenter?.ry]);

  return <canvas ref={canvasRef} className={className} aria-hidden />;
}

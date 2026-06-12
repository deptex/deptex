import { useEffect, useRef } from "react";

/**
 * DotDrape — static halftone drapery anchored off the top-left corner
 * (the Snyk-hero treatment, in brand green).
 *
 * What the reference actually is: a halftone sampling of rendered cloth
 * PINCHED at a point — radial pleats fan out from the pinch, each pleat a
 * curved band of bright bunched dots with dark valleys between. So this
 * draws exactly that: dots on a regular grid whose radius samples a
 * procedural drapery intensity field (angular pleats around an off-screen
 * anchor, bent with distance, with a secondary ripple), dissolving with
 * distance from the corner.
 *
 * Fully static by design — the reference doesn't animate; the 3D reading
 * comes from the pleat geometry. Draws once + on resize.
 */
export default function DotDrape({ className = "" }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return; // jsdom / very old browsers

    const draw = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = rect.width;
      const h = rect.height;
      if (!w || !h) return;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const STEP = 16; // halftone grid pitch

      // The fold pattern = contour lines (level sets) of a smooth 2D
      // terrain. The linear ramp is the key: it makes the contours run
      // diagonally (perpendicular to the gradient), and the wave terms
      // bend them into the S-curves/switchbacks the reference has.
      // Pixel-scaled coordinates so contours stay isotropic.
      const terrain = (x: number, y: number) => {
        const X = x / 340;
        const Y = y / 340;
        return (
          (x * 0.8 + y * 1.0) / 300 +
          0.8 * Math.sin(X * 2.0 + 0.8) * Math.cos(Y * 2.6 - 0.3) +
          0.4 * Math.sin(X * 4.1 - Y * 2.7 + 2.0)
        );
      };
      // Patchy macro-brightness: some ridge segments run hot, others faint
      const patch = (x: number, y: number) => {
        const X = x / 340;
        const Y = y / 340;
        return 0.35 + 0.65 * Math.pow(0.5 + 0.5 * Math.sin(X * 1.3 - Y * 0.9 + 1.2), 1.3);
      };
      // Deterministic per-cell hash for the stray-scatter dots
      const hash = (x: number, y: number) => {
        const s = Math.sin(x * 12.9898 + y * 78.233) * 43758.5453;
        return s - Math.floor(s);
      };

      // Phase-shift so a ridge crest passes exactly through the corner —
      // the anchor point should be the hottest spot, never a valley
      const f00 = terrain(0, 0);

      for (let y = STEP / 2; y < h; y += STEP) {
        for (let x = STEP / 2; x < w; x += STEP) {
          // Reach: anchored to the top-left corner, dissolving toward the
          // headline column and the hero bottom
          const d = Math.hypot(x / (w * 0.55), y / (h * 1.35));
          if (d >= 1.08) continue;
          const fall = Math.pow(Math.max(0, 1 - d), 1.1);
          // Ridge profile: sharp bright contour lines, wide dark valleys
          const f = terrain(x, y);
          const c = Math.cos((f - f00) * 11);
          const i = Math.pow(0.5 + 0.5 * c, 2.6);
          const pt = patch(x, y);
          const v = i * fall * pt;
          const rad = 0.3 + 6.2 * v;
          if (rad < 0.55) {
            // Valleys keep a faint micro-dot floor inside the field body;
            // past the edge, occasional strays make the ragged dissolve
            if (fall * pt > 0.3) {
              ctx.fillStyle = "#2fae79";
              ctx.globalAlpha = 0.22;
              ctx.beginPath();
              ctx.arc(x, y, 0.8, 0, Math.PI * 2);
              ctx.fill();
            } else if (hash(x, y) > 0.986 && d < 1.08) {
              ctx.fillStyle = "#2fae79";
              ctx.globalAlpha = 0.3;
              ctx.beginPath();
              ctx.arc(x, y, 1.1, 0, Math.PI * 2);
              ctx.fill();
            }
            continue;
          }
          // Ridge crests get the hot mint, the body a deeper green
          ctx.fillStyle = v > 0.5 ? "#46e6a3" : "#2fae79";
          ctx.globalAlpha = Math.min(0.95, 0.2 + 1.0 * v);
          ctx.beginPath();
          ctx.arc(x, y, rad, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      ctx.globalAlpha = 1;
    };

    draw();
    const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(draw) : null;
    ro?.observe(canvas);
    return () => ro?.disconnect();
  }, []);

  return <canvas ref={canvasRef} className={className} aria-hidden />;
}

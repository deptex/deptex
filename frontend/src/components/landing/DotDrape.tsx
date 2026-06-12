import { useEffect, useRef } from "react";

/**
 * DotDrape — static 3D folded-cloth halftone, anchored top-left.
 *
 * This is the "replica" winner of the 2026-06-12 four-way bake-off
 * (lab files: frontend/tmp-captures/3d-lab/). Unlike the failed flat
 * attempts, this is a real software-3D pipeline, which is what makes the
 * dot net visibly wrap a 3D form:
 *   heightfield cloth (sharpened sine folds) → perspective camera →
 *   per-screen-column horizon buffer for fold occlusion (3× fine march) →
 *   Lambert + specular + rim lighting → dots drawn as surface-oriented
 *   ellipses (foreshortening squash) → top-left anchor mask with
 *   stochastic stray-dot dissolve.
 *
 * Static by design (the reference artwork doesn't animate). Renders once
 * per size into a fixed 1700×850 design space scaled to the canvas width,
 * plus a bottom dissolve tied to the actual canvas height so the cloth
 * never hard-clips at the hero's edge.
 */

const DESIGN_W = 1700;
const DESIGN_H = 850;

function renderCloth(ctx: CanvasRenderingContext2D, w: number, h: number, dpr: number) {
  // Fit the full 1700×850 composition by HEIGHT — the hero is much shorter
  // than the design space, so the whole artwork shrinks into the corner
  // (the way the approved bake-off render is framed) instead of showing a
  // blown-up crop of its top band.
  const scale = Math.min(w / DESIGN_W, (h / DESIGN_H) * 0.97);
  ctx.setTransform(dpr * scale, 0, 0, dpr * scale, 0, 0);
  ctx.clearRect(0, 0, w / scale + 50, h / scale + 50);
  const hLog = h / scale; // canvas height in design units

  const hash = (n: number) => {
    const s = Math.sin(n * 127.1 + 311.7) * 43758.5453;
    return s - Math.floor(s);
  };

  // ---------- heightfield (cloth folds) ----------
  const height = (x: number, y: number) => {
    let z = 0;
    const p1 = 0.008 * x + 0.015 * y + 2.4;
    z += 32 * (Math.sin(p1) + 0.33 * Math.sin(2 * p1 + 1.1)); // sharpened cloth fold
    z += 15 * Math.sin(-0.0055 * x + 0.022 * y + 4.6);
    z += 7.0 * Math.sin(0.023 * x + 0.007 * y + 2.3);
    z += 3.5 * Math.sin(0.008 * x + 0.03 * y + 0.6) * Math.sin(0.024 * x - 0.009 * y + 2.8);
    return z;
  };
  const normalAt = (x: number, y: number): [number, number, number] => {
    const e = 2.0;
    const dzdx = (height(x + e, y) - height(x - e, y)) / (2 * e);
    const dzdy = (height(x, y + e) - height(x, y - e)) / (2 * e);
    const inv = 1 / Math.hypot(dzdx, dzdy, 1);
    return [-dzdx * inv, -dzdy * inv, inv];
  };

  // ---------- camera ----------
  const eye = [260, -150, 130];
  let f = [0.13, 1.0, -0.85];
  const fl = Math.hypot(f[0], f[1], f[2]);
  f = f.map((v) => v / fl);
  let r = [f[1], -f[0], 0]; // f × up(0,0,1), normalized below
  const rl = Math.hypot(r[0], r[1], r[2]);
  r = r.map((v) => v / rl);
  const u = [
    r[1] * f[2] - r[2] * f[1],
    r[2] * f[0] - r[0] * f[2],
    r[0] * f[1] - r[1] * f[0],
  ];
  const FOCAL = 820;
  const CX = DESIGN_W * 0.3; // the bake-off's own framing
  const CY = 0;

  const project = (p: [number, number, number]): [number, number, number] | null => {
    const d = [p[0] - eye[0], p[1] - eye[1], p[2] - eye[2]];
    const zc = d[0] * f[0] + d[1] * f[1] + d[2] * f[2];
    if (zc < 30) return null;
    const xc = d[0] * r[0] + d[1] * r[1] + d[2] * r[2];
    const yc = d[0] * u[0] + d[1] * u[1] + d[2] * u[2];
    return [CX + (FOCAL * xc) / zc, CY - (FOCAL * yc) / zc, zc];
  };

  // ---------- light ----------
  let L = [-0.25, -0.48, 0.84];
  const Ll = Math.hypot(L[0], L[1], L[2]);
  L = L.map((v) => v / Ll);

  // ---------- grid + horizon-buffer occlusion ----------
  const PITCH = 13;
  const DOTR = 4.3;
  const COLS = 220;
  const ROWS = 260;
  const X0 = -950;
  const Y0 = -60;

  const BUCKET = 2;
  const XOFF = DESIGN_W * 0.2;
  const NB = Math.ceil((DESIGN_W * 1.4) / BUCKET);
  const horizon = new Float32Array(NB).fill(1e9);

  type Dot = {
    sx: number;
    sy: number;
    syp: number;
    zc: number;
    rad: number;
    squash: number;
    ang: number;
    bright: number;
    seed: number;
  };
  const dots: Dot[] = [];
  const FINE = 3;

  for (let j = 0; j < ROWS * FINE; j++) {
    const vy = Y0 + (j / FINE) * PITCH;
    const isDotRow = j % FINE === 0;
    const rowIdx = j / FINE;
    for (let i = 0; i < COLS * FINE; i++) {
      const vx = X0 + (i / FINE) * PITCH;
      const z = height(vx, vy);
      const pr = project([vx, vy, z]);
      if (!pr) continue;
      const [sx, sy] = pr;
      if (sx < -XOFF || sx > DESIGN_W * 1.2) continue;
      const b = Math.max(0, Math.min(NB - 1, Math.round((sx + XOFF) / BUCKET)));
      if (sy < horizon[b]) horizon[b] = sy;
      if (!isDotRow || i % FINE !== 0) continue;

      let dx = vx;
      let dsx = sx;
      let dsy = sy;
      let dzc = pr[2];
      if (rowIdx % 2 === 1) {
        dx = vx + PITCH * 0.5;
        const pr2 = project([dx, vy, height(dx, vy)]);
        if (!pr2) continue;
        [dsx, dsy, dzc] = pr2;
      }
      const b2 = Math.max(0, Math.min(NB - 1, Math.round((dsx + XOFF) / BUCKET)));
      if (dsy > horizon[b2] + 0.8) continue; // hidden behind a nearer fold

      const zz = height(dx, vy);
      const n = normalAt(dx, vy);
      let v = [eye[0] - dx, eye[1] - vy, eye[2] - zz];
      const vl = Math.hypot(v[0], v[1], v[2]);
      v = v.map((q) => q / vl);
      const ndotv = n[0] * v[0] + n[1] * v[1] + n[2] * v[2];
      if (ndotv < 0.045) continue;

      const diff = Math.max(0, n[0] * L[0] + n[1] * L[1] + n[2] * L[2]);
      let hv = [v[0] + L[0], v[1] + L[1], v[2] + L[2]];
      const hl = Math.hypot(hv[0], hv[1], hv[2]);
      hv = hv.map((q) => q / hl);
      const spec = Math.pow(Math.max(0, n[0] * hv[0] + n[1] * hv[1] + n[2] * hv[2]), 10);

      const distFade = Math.max(0.13, Math.min(1, 1.34 - dzc / 1300));
      const nearBoost = 1 + 0.55 * Math.exp(-Math.max(0, dzc - 150) / 200);
      // lit fold-edge slivers
      const rim = 0.55 * Math.pow(1 - Math.min(1, ndotv), 2.2) * Math.min(1, diff * 1.5);
      let bright = (0.1 + 0.8 * Math.pow(diff, 1.45) + 0.42 * spec + rim) * distFade * nearBoost;

      // world-space far dissolve: rows thin out, lattice stays coherent
      const farT = Math.max(0, Math.min(1, (vy - 950) / 600));
      if (farT > 0 && hash(i * 3.91 + rowIdx * 9.27) < farT * farT) continue;
      bright *= 1 - 0.55 * farT;

      // shrink dots slightly with depth so far rows stay separated
      const shrink = 1 - 0.3 * Math.min(1, Math.max(0, dzc - 300) / 1100);
      const rad = (DOTR * shrink * FOCAL) / dzc;
      if (rad < 0.55) continue;
      const squash = Math.pow(Math.max(0.1, Math.min(1, ndotv)), 0.8);

      const pn = project([dx + n[0] * 4, vy + n[1] * 4, zz + n[2] * 4]);
      let ang = 0;
      if (pn) ang = Math.atan2(-(pn[1] - dsy), pn[0] - dsx);

      dots.push({
        sx: dsx,
        sy: 0,
        syp: dsy,
        zc: dzc,
        rad,
        squash,
        ang,
        bright,
        seed: hash(i * 7.13 + rowIdx * 3.71),
      });
    }
  }

  // ---------- auto-frame: nearest rows bleed off the top ----------
  let syMax = -1e9;
  for (const d of dots) if (d.syp > syMax) syMax = d.syp;
  const FLIPY = syMax - 36;
  for (const d of dots) d.sy = FLIPY - d.syp;

  // ---------- top-left anchor mask / dissolve ----------
  // Extra bottom edge tied to the REAL canvas height so the cloth
  // dissolves before the hero's lower boundary instead of hard-clipping.
  const maskAt = (x: number, y: number, seed: number) => {
    const tx = x / DESIGN_W;
    const ty = y / DESIGN_H;
    const t = tx * 1.0 + ty * 0.26;
    const edge = (t - 0.42) / 0.4;
    const yEdge = (ty - 0.66) / 0.28;
    const bEdge = (y - hLog * 0.72) / (hLog * 0.24);
    const e = Math.max(edge, yEdge, bEdge);
    if (e <= 0) return 1;
    if (e >= 1.3) return 0;
    const ec = Math.min(1, e);
    const keepP = 1 - ec * ec * (3 - 2 * ec);
    if (seed > keepP + 0.08) return 0;
    return Math.max(0.05, Math.pow(1 - 0.85 * ec, 1.8));
  };

  // ---------- palette ----------
  const stops: [number, number, number, number][] = [
    [0.0, 0x07, 0x21, 0x18],
    [0.18, 0x12, 0x47, 0x33],
    [0.4, 0x1f, 0x7a, 0x55],
    [0.62, 0x2f, 0xae, 0x79],
    [0.82, 0x34, 0xd0, 0x8a],
    [1.0, 0x46, 0xe6, 0xa3],
  ];
  const colorFor = (t: number) => {
    let c0 = stops[0];
    let c1 = stops[stops.length - 1];
    for (let k = 0; k < stops.length - 1; k++) {
      if (t >= stops[k][0] && t <= stops[k + 1][0]) {
        c0 = stops[k];
        c1 = stops[k + 1];
        break;
      }
    }
    const f2 = (t - c0[0]) / Math.max(1e-5, c1[0] - c0[0]);
    const r3 = Math.round(c0[1] + (c1[1] - c0[1]) * f2);
    const g3 = Math.round(c0[2] + (c1[2] - c0[2]) * f2);
    const b3 = Math.round(c0[3] + (c1[3] - c0[3]) * f2);
    return `rgb(${r3},${g3},${b3})`;
  };

  dots.sort((a, b) => b.zc - a.zc);

  for (const d of dots) {
    if (d.sy < -25 || d.sy > hLog + 25 || d.sx < -20 || d.sx > DESIGN_W + 20) continue;
    const m = maskAt(d.sx, d.sy, d.seed);
    if (m <= 0) continue;
    const t = Math.max(0, Math.min(1, d.bright * m));
    if (t < 0.018) continue;
    ctx.fillStyle = colorFor(t);
    ctx.beginPath();
    ctx.save();
    ctx.translate(d.sx, d.sy);
    ctx.rotate(d.ang);
    ctx.scale(d.squash, 1);
    ctx.arc(0, 0, Math.min(d.rad, (PITCH * 0.46 * FOCAL) / d.zc), 0, Math.PI * 2);
    ctx.restore();
    ctx.fill();
  }
}

export default function DotDrape({ className = "" }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return; // jsdom / very old browsers

    let timer: ReturnType<typeof setTimeout> | null = null;
    const draw = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = rect.width;
      const h = rect.height;
      if (!w || !h) return;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      renderCloth(ctx, w, h, dpr);
    };

    draw();
    // The render walks ~0.5M samples — debounce resize re-renders
    const ro =
      typeof ResizeObserver !== "undefined"
        ? new ResizeObserver(() => {
            if (timer) clearTimeout(timer);
            timer = setTimeout(draw, 150);
          })
        : null;
    ro?.observe(canvas);
    return () => {
      if (timer) clearTimeout(timer);
      ro?.disconnect();
    };
  }, []);

  return <canvas ref={canvasRef} className={className} aria-hidden />;
}

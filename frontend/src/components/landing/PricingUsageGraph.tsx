/**
 * Animated step-usage graph for the pricing hero (Railway-style). Pure SVG +
 * CSS keyframes, no deps: the line draws left-to-right via a pathLength dash
 * trick, the area fades in under it, and a mono callout pops in at the end.
 *
 * Every 5s it cycles to a different usage shape (repo scans → Aegis chats →
 * auto-fix PRs → worker-seconds) and redraws — keyed elements remount so the
 * draw/fade/pop keyframes replay. The staircase shape reads as "metered
 * usage": you're billed for the area under the curve, nothing more.
 */
import { useEffect, useState } from 'react';

const W = 480;
const H = 220;
const PAD_X = 10;
const PAD_Y = 18;
// Reserve a right gutter so the metered line ends before the edge and the
// callout sits beside it (in empty space), not on top of the data.
const GUTTER = 110;
const INNER_W = W - PAD_X - GUTTER;
const INNER_H = H - PAD_Y * 2;
const CYCLE_MS = 8000;

type Graph = { label: string; samples: number[] };

// Normalized usage samples (0..1), held flat then stepping — metered look.
const GRAPHS: Graph[] = [
  { label: 'repo scan', samples: [0.16, 0.16, 0.32, 0.32, 0.24, 0.24, 0.55, 0.55, 0.4, 0.4, 0.72, 0.72, 0.5, 0.5, 0.6, 0.6] },
  { label: 'Aegis chat', samples: [0.1, 0.1, 0.2, 0.2, 0.3, 0.3, 0.42, 0.42, 0.5, 0.5, 0.62, 0.62, 0.78, 0.78, 0.7, 0.7] },
  { label: 'auto-fix PR', samples: [0.3, 0.3, 0.55, 0.55, 0.2, 0.2, 0.66, 0.66, 0.35, 0.35, 0.8, 0.8, 0.46, 0.46, 0.58, 0.58] },
  { label: 'worker-second', samples: [0.22, 0.22, 0.18, 0.18, 0.5, 0.5, 0.44, 0.44, 0.3, 0.3, 0.36, 0.36, 0.68, 0.68, 0.6, 0.6] },
];

function buildPaths(samples: number[]) {
  const n = samples.length;
  const stepW = INNER_W / n;
  const xOf = (i: number) => PAD_X + i * stepW;
  const yOf = (v: number) => PAD_Y + (1 - v) * INNER_H;

  let line = `M ${xOf(0)} ${yOf(samples[0])}`;
  for (let i = 0; i < n; i++) {
    line += ` L ${xOf(i + 1)} ${yOf(samples[i])}`;
    if (i < n - 1) line += ` L ${xOf(i + 1)} ${yOf(samples[i + 1])}`;
  }
  const baseY = PAD_Y + INNER_H;
  const area = `${line} L ${xOf(n)} ${baseY} L ${xOf(0)} ${baseY} Z`;
  return { line, area, endX: xOf(n), endY: yOf(samples[n - 1]) };
}

export function PricingUsageGraph() {
  const [idx, setIdx] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setIdx((p) => (p + 1) % GRAPHS.length), CYCLE_MS);
    return () => clearInterval(id);
  }, []);

  const graph = GRAPHS[idx];
  const { line, area, endX, endY } = buildPaths(graph.samples);

  return (
    <div className="relative w-full">
      <style>{`
        @keyframes pug-draw { from { stroke-dashoffset: 1; } to { stroke-dashoffset: 0; } }
        @keyframes pug-fade { from { opacity: 0; } to { opacity: 1; } }
        @keyframes pug-pop  { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
      `}</style>

      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full"
        fill="none"
        role="img"
        aria-label="Usage-based billing, metered over time"
      >
        <defs>
          <linearGradient id="pug-area-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#34d08a" stopOpacity="0.2" />
            <stop offset="100%" stopColor="#34d08a" stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* gridlines */}
        {[0.25, 0.5, 0.75].map((g) => (
          <line
            key={g}
            x1={PAD_X}
            x2={W - PAD_X}
            y1={PAD_Y + g * INNER_H}
            y2={PAD_Y + g * INNER_H}
            stroke="#ffffff"
            strokeOpacity="0.04"
          />
        ))}
        {/* baseline */}
        <line x1={PAD_X} x2={W - PAD_X} y1={PAD_Y + INNER_H} y2={PAD_Y + INNER_H} stroke="#ffffff" strokeOpacity="0.1" />

        {/* area under the curve — what you're billed for */}
        <path
          key={`area-${idx}`}
          d={area}
          fill="url(#pug-area-fill)"
          style={{ opacity: 0, animation: 'pug-fade 0.8s ease-out 0.5s forwards' }}
        />

        {/* the metered line */}
        <path
          key={`line-${idx}`}
          d={line}
          stroke="#34d08a"
          strokeWidth="2"
          strokeLinejoin="round"
          pathLength={1}
          strokeDasharray={1}
          style={{ strokeDashoffset: 1, animation: 'pug-draw 1.6s ease-out forwards' }}
        />

        {/* endpoint marker */}
        <circle
          key={`dot-${idx}`}
          cx={endX}
          cy={endY}
          r="3.5"
          fill="#34d08a"
          style={{ opacity: 0, animation: 'pug-fade 0.4s ease-out 1.5s forwards' }}
        />
      </svg>

      {/* callout, anchored near the endpoint — label cycles with the graph.
          Outer div centers on the endpoint; inner runs the pop keyframe so its
          transform doesn't fight the centering translate. */}
      <div
        className="absolute right-1 hidden -translate-y-1/2 sm:block"
        style={{ top: `${(endY / H) * 100}%` }}
      >
        <div
          key={`call-${idx}`}
          className="rounded-lg border border-accent-text/30 bg-accent-text/10 px-3 py-2 font-mono text-xs leading-snug text-accent-text"
          style={{ opacity: 0, animation: 'pug-pop 0.5s ease-out 1.5s forwards' }}
        >
          billed per
          <br />
          {graph.label}
        </div>
      </div>
    </div>
  );
}

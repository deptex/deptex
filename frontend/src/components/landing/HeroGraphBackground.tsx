/**
 * HeroGraphBackground — structured hero atmosphere.
 *
 * Geometry, not blur: the reference sites all carry *structured* fields
 * (Endor's chevron, Snyk's perspective dot wave, Socket's pixel blocks).
 * Ours is the product's own shape: a dependency/taint-flow constellation.
 * Hand-composed, not random — two clusters flank the headline column
 * (center stays clean for text), edges flow downward toward the trace
 * panel, and a single packet travels a source→sink chain every 12s.
 *
 * Motion budget: 3 slow node pulses + the packet. Reduced-motion freezes
 * pulses and hides the packet (CSS in Main.css).
 */

type Tone = "bright" | "mid" | "dim";

interface GNode {
  x: number;
  y: number;
  r: number;
  tone: Tone;
  /** soft halo ring behind the node */
  halo?: boolean;
  /** slow opacity pulse; delay staggers them */
  pulse?: boolean;
  delay?: number;
}

const TONE_FILL: Record<Tone, { fill: string; opacity: number }> = {
  bright: { fill: "#34d08a", opacity: 0.85 },
  mid: { fill: "#2eb37c", opacity: 0.45 },
  dim: { fill: "#34d08a", opacity: 0.2 },
};

/* Left cluster — flows down-right toward the trace panel. */
const LEFT: GNode[] = [
  { x: 150, y: 110, r: 3, tone: "bright", halo: true, pulse: true, delay: 0 },
  { x: 265, y: 205, r: 2.5, tone: "mid" },
  { x: 185, y: 330, r: 4, tone: "bright", halo: true, pulse: true, delay: 2.2 },
  { x: 340, y: 305, r: 2, tone: "dim" },
  { x: 95, y: 470, r: 2.5, tone: "mid" },
  { x: 305, y: 485, r: 3, tone: "mid" },
  { x: 445, y: 575, r: 2, tone: "dim" },
];

/* Right cluster — mirrored weight, slightly lower. */
const RIGHT: GNode[] = [
  { x: 1300, y: 140, r: 2.5, tone: "mid" },
  { x: 1185, y: 245, r: 3.5, tone: "bright", halo: true, pulse: true, delay: 1.1 },
  { x: 1355, y: 345, r: 2, tone: "dim" },
  { x: 1245, y: 440, r: 3, tone: "mid" },
  { x: 1105, y: 530, r: 2.5, tone: "mid" },
  { x: 1385, y: 525, r: 2, tone: "dim" },
];

/* Sparse dim points high above the headline + bottom corners — texture only. */
const SPARSE: GNode[] = [
  { x: 575, y: 135, r: 1.5, tone: "dim" },
  { x: 745, y: 85, r: 1.5, tone: "dim" },
  { x: 905, y: 155, r: 1.5, tone: "dim" },
  { x: 215, y: 715, r: 2, tone: "dim" },
  { x: 1230, y: 700, r: 2.5, tone: "dim" },
];

const NODES: GNode[] = [...LEFT, ...RIGHT, ...SPARSE];

/* Edges as coordinate pairs (indices into the cluster arrays kept inline
   for readability — these are design decisions, not data). */
const EDGES: Array<[number, number, number, number]> = [
  // left cluster
  [150, 110, 265, 205],
  [265, 205, 185, 330],
  [265, 205, 340, 305],
  [185, 330, 95, 470],
  [185, 330, 305, 485],
  [340, 305, 305, 485],
  [305, 485, 445, 575],
  // right cluster
  [1300, 140, 1185, 245],
  [1300, 140, 1355, 345],
  [1185, 245, 1245, 440],
  [1245, 440, 1105, 530],
  [1355, 345, 1385, 525],
];

/** The packet's source→sink chain (left cluster: A → B → D → F → G). */
const PACKET_PATH = "M150,110 L265,205 L340,305 L305,485 L445,575";

/* Out-of-focus depth nodes — the only intentional blur, used as bokeh. */
const DEPTH: Array<{ x: number; y: number; r: number }> = [
  { x: 70, y: 260, r: 9 },
  { x: 1335, y: 465, r: 10 },
];

export default function HeroGraphBackground() {
  return (
    <div className="hero-graph absolute inset-x-0 top-0 h-[780px]" aria-hidden>
      <svg
        className="h-full w-full"
        viewBox="0 0 1440 800"
        preserveAspectRatio="xMidYMin slice"
        fill="none"
      >
        {/* edges under nodes */}
        <g stroke="#34d08a" strokeOpacity={0.13} strokeWidth={1}>
          {EDGES.map(([x1, y1, x2, y2]) => (
            <line key={`${x1}-${y1}-${x2}-${y2}`} x1={x1} y1={y1} x2={x2} y2={y2} />
          ))}
        </g>

        {/* depth bokeh */}
        {DEPTH.map((d) => (
          <circle
            key={`d-${d.x}`}
            cx={d.x}
            cy={d.y}
            r={d.r}
            fill="#025230"
            opacity={0.5}
            style={{ filter: "blur(6px)" }}
          />
        ))}

        {/* nodes (+ halos) */}
        {NODES.map((n) => {
          const tone = TONE_FILL[n.tone];
          return (
            <g key={`${n.x}-${n.y}`}>
              {n.halo && (
                <circle cx={n.x} cy={n.y} r={n.r * 3.2} fill="#34d08a" opacity={0.1} />
              )}
              <circle
                cx={n.x}
                cy={n.y}
                r={n.r}
                fill={tone.fill}
                opacity={tone.opacity}
                className={n.pulse ? "node-pulse" : undefined}
                style={n.pulse && n.delay ? { animationDelay: `${n.delay}s` } : undefined}
              />
            </g>
          );
        })}

        {/* the traveling packet: source→sink, ~3.6s of travel every 12s */}
        <circle className="graph-packet" r={2.5} fill="#34d08a" opacity={0}>
          <animateMotion
            dur="12s"
            repeatCount="indefinite"
            calcMode="linear"
            keyPoints="0;1;1"
            keyTimes="0;0.3;1"
            path={PACKET_PATH}
          />
          <animate
            attributeName="opacity"
            values="0;0.9;0.9;0;0"
            keyTimes="0;0.04;0.26;0.3;1"
            dur="12s"
            repeatCount="indefinite"
          />
        </circle>
      </svg>
    </div>
  );
}

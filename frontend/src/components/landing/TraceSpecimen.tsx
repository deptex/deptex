/**
 * TraceSpecimen — the hero's DOM-rendered taint-flow trace panel
 * (landing-page-redesign.plan.md §3.2, asset A1).
 *
 * Renders the real component structure with OBVIOUSLY-SAMPLE data; the
 * capture from a real express dogfood scan replaces the `HOPS` const.
 * Semantic HTML: header row, <ol> of hops with node dots + connecting
 * left rail, verdict footer.
 *
 * Motion: paints fully drawn; after `load`, one CSS-only draw-on pass —
 * node dots fill top-to-bottom via `trace-node-in` (250ms stagger).
 * Runs once, never loops. The `trace-animate` class hooks the existing
 * prefers-reduced-motion kill switch in Main.css.
 */
import { useEffect, useState } from "react";
import { TriangleAlert } from "lucide-react";
import { TierPill } from "./primitives";

type HopRole = "source" | "propagated" | "sink";

interface Hop {
  /** Full path:line (desktop). */
  path: string;
  /** Basename:line (mobile condensed variant — no h-scroll). */
  basename: string;
  /** Tainted symbol at this hop. */
  symbol: string;
  role: HopRole;
  /** One code line, pre-highlighted at build time once A1 lands. */
  code: string;
}

/* Sample data — plan wireframe placeholders, never invented CVE ids. */
const HOPS: Hop[] = [
  {
    path: "src/routes/users.js:14",
    basename: "users.js:14",
    symbol: "req.query.id",
    role: "source",
    code: "const id = req.query.id",
  },
  {
    path: "src/services/db.js:31",
    basename: "db.js:31",
    symbol: "buildQuery(id)",
    role: "propagated",
    code: "return db.raw(`… ${id}`)",
  },
  {
    path: "node_modules/package/lib/query.js:88",
    basename: "query.js:88",
    symbol: "vulnerableFn(input)",
    role: "sink",
    code: "function vulnerableFn(input) { … }",
  },
];

function RoleTag({ role }: { role: HopRole }) {
  if (role === "sink") {
    return (
      <span className="inline-flex shrink-0 items-center gap-1 rounded border border-warning/30 bg-warning/10 px-1.5 py-0.5 font-mono text-[11px] leading-none text-warning">
        sink
        <TriangleAlert className="h-3 w-3" aria-hidden />
      </span>
    );
  }
  return (
    <span className="inline-flex shrink-0 items-center rounded border border-border bg-[#171717] px-1.5 py-0.5 font-mono text-[11px] leading-none text-foreground-secondary">
      {role}
    </span>
  );
}

export default function TraceSpecimen() {
  const [animate, setAnimate] = useState(false);

  useEffect(() => {
    let raf = 0;
    const start = () => {
      raf = requestAnimationFrame(() => setAnimate(true));
    };
    if (document.readyState === "complete") {
      start();
    } else {
      window.addEventListener("load", start, { once: true });
    }
    return () => {
      window.removeEventListener("load", start);
      cancelAnimationFrame(raf);
    };
  }, []);

  return (
    <div className={animate ? "trace-animate" : undefined}>
      {/* Header: CVE · package, tier pill, depscore */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-border px-4 py-3 sm:px-5">
        <div className="flex min-w-0 items-center gap-2 font-mono text-[13px] tabular-nums">
          <span className="text-foreground">CVE-XXXX-XXXXX</span>
          <span className="text-foreground-muted" aria-hidden>
            ·
          </span>
          <span className="truncate text-foreground-secondary">package@1.2.3</span>
        </div>
        <div className="ml-auto flex shrink-0 items-center gap-3">
          <TierPill tier="confirmed" />
          <span className="font-mono text-[13px] tabular-nums text-foreground-secondary">
            depscore <span className="text-foreground">92</span>
          </span>
        </div>
      </div>

      {/* Hops: node dots on a connecting left rail */}
      <ol className="px-4 py-4 sm:px-5">
        {HOPS.map((hop, i) => {
          const isLast = i === HOPS.length - 1;
          return (
            <li key={hop.path} className={`relative pl-6 ${isLast ? "" : "pb-4"}`}>
              {/* node dot — fills top-to-bottom after load, 250ms stagger */}
              <span
                aria-hidden
                className={`absolute left-0 top-[5px] h-2.5 w-2.5 rounded-full ${
                  hop.role === "sink" ? "bg-warning" : "bg-foreground-secondary"
                }`}
                style={
                  animate
                    ? {
                        animation: `trace-node-in 300ms cubic-bezier(0.16, 1, 0.3, 1) ${i * 250}ms both`,
                      }
                    : undefined
                }
              />
              {/* connecting rail segment */}
              {!isLast && (
                <span
                  aria-hidden
                  className="absolute bottom-0 left-[4px] top-[19px] w-px bg-border"
                />
              )}

              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[13px] leading-5 tabular-nums">
                <span className="text-foreground">
                  <span className="sm:hidden">{hop.basename}</span>
                  <span className="hidden sm:inline">{hop.path}</span>
                </span>
                <span className="hidden text-foreground-secondary sm:inline">{hop.symbol}</span>
                <span className="ml-auto">
                  <RoleTag role={hop.role} />
                </span>
              </div>
              {/* code snippet line; h-scroll fallback lives here only */}
              <div className="mt-1 overflow-x-auto">
                <code className="block whitespace-pre font-mono text-[13px] leading-5 text-foreground-secondary">
                  {hop.code}
                </code>
              </div>
            </li>
          );
        })}
      </ol>

      {/* Verdict footer */}
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-t border-border px-4 py-3 font-mono text-xs sm:px-5">
        <span className="text-foreground-secondary">
          verdict: <span className="text-foreground">confirmed</span> · taint flow verified
        </span>
        <span className="text-foreground-secondary">view flow →</span>
      </div>
    </div>
  );
}

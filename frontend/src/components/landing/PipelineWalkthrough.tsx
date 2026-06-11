/**
 * §3.5 How it works — the pipeline (01 → 05).
 * Five rows on a continuous 2px left spine; one sticky artifact card on the
 * right cross-fades per active row. Active-row detection: ONE
 * IntersectionObserver with rootMargin "-45% 0px -45% 0px" (midline rule,
 * tie-break to the lower row). No parallax, no pinning.
 * See landing-page-redesign.plan.md §3.5.
 */
import { ReactNode, useEffect, useRef, useState } from "react";
import { PlaceholderCanvas, Reveal, TierPill } from "./primitives";

/* ------------------------------------------------------------------ */
/* Copy — verbatim from the plan's §3.5 draft copy.                    */
/* ------------------------------------------------------------------ */
const STEPS = [
  {
    label: "01 ▸ scan",
    headline: "One pipeline, nine scanner categories.",
    subhead:
      "Clone, CycloneDX SBOM, dependency matching, taint engine, Semgrep, TruffleHog, IaC, containers: one streamed pipeline. DAST attacks your deployed app as its own scan.",
  },
  {
    label: "02 ▸ trace",
    headline: "Follow untrusted input to the sink.",
    subhead:
      "34 framework detectors find your real entry points; the cross-file taint engine walks the path into the vulnerable function.",
  },
  {
    label: "03 ▸ score",
    headline: "Score by proof, not severity alone.",
    subhead:
      "Depscore multiplies CVSS by the reachability tier, exploit signals (EPSS, CISA KEV) and your project's importance. Unreachable scores zero.",
  },
  {
    label: "04 ▸ confirm",
    headline: "Attack it. Keep the receipt.",
    subhead:
      "Two DAST engines attack the running app; a CVE-tagged Nuclei hit flips the finding to runtime-confirmed.",
  },
  {
    label: "05 ▸ fix",
    headline: "Approve the plan. Get a draft PR.",
    subhead:
      "Aegis proposes a fix plan in chat; once you approve, a sandboxed worker writes the patch, runs your tests, and opens a draft PR.",
  },
] as const;

/* ------------------------------------------------------------------ */
/* Artifacts — obviously-sample DOM crops; real captures replace them. */
/* ------------------------------------------------------------------ */

function SampleCaption({ text }: { text: string }) {
  return (
    <p className="mt-auto pt-4 font-mono text-[11px] leading-relaxed text-foreground-secondary">
      {text}
    </p>
  );
}

const LOG_DOT: Record<string, string> = {
  info: "bg-[#71717a]",
  ok: "bg-accent-text",
  warn: "bg-warning",
};

const LOG_LINES = [
  { level: "info", t: "[00:00.4]", stage: "clone", msg: "repo cloned · 1.2 MB" },
  { level: "ok", t: "[00:03.1]", stage: "sbom", msg: "cdxgen: 184 components" },
  { level: "info", t: "[00:06.2]", stage: "deps", msg: "42 direct · 142 transitive" },
  { level: "info", t: "[00:09.7]", stage: "taint", msg: "34 detectors → 6 entry points" },
  { level: "warn", t: "[00:13.5]", stage: "reach", msg: "CVE-XXXX-XXXXX → confirmed" },
  { level: "ok", t: "[00:14.8]", stage: "sast", msg: "semgrep: 3 findings" },
];

/** Step 01 — six-line sample extraction-log fragment. */
function LogFragmentArtifact() {
  return (
    <>
      <div className="flex flex-1 flex-col justify-center gap-2.5 font-mono text-xs leading-relaxed">
        {LOG_LINES.map((line) => (
          <div key={line.t} className="flex items-center gap-2.5">
            <span
              className={`h-1.5 w-1.5 shrink-0 rounded-full ${LOG_DOT[line.level]}`}
              aria-hidden
            />
            <span className="shrink-0 tabular-nums text-[#71717a]">{line.t}</span>
            <span className="w-12 shrink-0 text-foreground-secondary">{line.stage}</span>
            <span className="truncate tabular-nums text-foreground">{line.msg}</span>
          </div>
        ))}
      </div>
      <SampleCaption text="sample data — real extraction-log capture replaces this (asset A3)" />
    </>
  );
}

/** Step 02 — one-hop sample trace line. */
function TraceHopArtifact() {
  return (
    <>
      <div className="flex flex-1 flex-col justify-center font-mono text-xs leading-relaxed">
        <div className="flex items-baseline gap-3">
          <span className="h-1.5 w-1.5 shrink-0 translate-y-px rounded-full bg-accent-text" aria-hidden />
          <span className="truncate text-foreground">src/routes/users.js:14</span>
          <span className="ml-auto shrink-0 text-foreground-secondary">source</span>
        </div>
        <div className="ml-[2.5px] border-l-2 border-[#262626] py-2 pl-4 text-foreground-secondary">
          const id = req.query.id
        </div>
        <div className="flex items-baseline gap-3">
          <span className="h-1.5 w-1.5 shrink-0 translate-y-px rounded-full bg-warning" aria-hidden />
          <span className="truncate text-foreground">node_modules/package/index.js:88</span>
          <span className="ml-auto shrink-0 text-foreground-secondary">sink ⚠</span>
        </div>
        <div className="mt-3 pl-4 text-foreground-secondary">vulnFn(id)</div>
      </div>
      <SampleCaption text="sample data — real trace hop replaces this (asset A1 crop)" />
    </>
  );
}

/** Step 03 — sample depscore formula line. */
function ScoreFormulaArtifact() {
  return (
    <>
      <div className="flex flex-1 flex-col justify-center gap-3 font-mono tabular-nums">
        <div className="flex items-baseline gap-2.5">
          <span className="text-3xl text-foreground">92</span>
          <span className="text-xs text-foreground-secondary">depscore</span>
          <TierPill tier="confirmed" />
        </div>
        <p className="text-xs leading-relaxed text-foreground-secondary">
          = 9.8 cvss × 1.0 confirmed × 1.2 exploit (EPSS · KEV) × 1.0 importance
        </p>
      </div>
      <SampleCaption text="sample data — real score breakdown replaces this (asset A2 crop)" />
    </>
  );
}

/** Step 04 — before/after tier-pill pair. */
function BadgeFlipArtifact() {
  return (
    <>
      <div className="flex flex-1 flex-col items-center justify-center gap-4">
        <span className="font-mono text-xs tabular-nums text-foreground-secondary">
          CVE-XXXX-XXXXX · package@1.2.3
        </span>
        <div className="flex items-center gap-3">
          <TierPill tier="data_flow" />
          <span className="font-mono text-sm text-foreground-secondary" aria-hidden>
            →
          </span>
          <TierPill tier="confirmed" label="confirmed · runtime" />
        </div>
      </div>
      <SampleCaption text="sample data — real badge flip replaces this (asset A8)" />
    </>
  );
}

/** Step 05 — placeholder for the Aegis plan-card crop (asset A4). */
function PlanCardArtifact() {
  return (
    <div className="flex flex-1 items-center justify-center">
      <PlaceholderCanvas
        assetId="A4-crop"
        description="Aegis plan-card poster frame — crop from the chat → plan → approve → draft PR recording"
        aspect="16/10"
        className="w-full"
      />
    </div>
  );
}

const ARTIFACTS: ReactNode[] = [
  <LogFragmentArtifact key="scan" />,
  <TraceHopArtifact key="trace" />,
  <ScoreFormulaArtifact key="score" />,
  <BadgeFlipArtifact key="confirm" />,
  <PlanCardArtifact key="fix" />,
];

/** Rows that keep an inline artifact crop on mobile (01, 02, 05). */
const MOBILE_CROP_ROWS = new Set([0, 1, 4]);

function getPrefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

/* ------------------------------------------------------------------ */
/* Section                                                             */
/* ------------------------------------------------------------------ */
export default function PipelineWalkthrough() {
  const [active, setActive] = useState(0);
  const [reducedMotion] = useState(getPrefersReducedMotion);
  const rowRefs = useRef<(HTMLLIElement | null)[]>([]);
  const visibleRows = useRef<Set<number>>(new Set());

  useEffect(() => {
    // Reduced motion: rows render full-contrast, artifact stays on step 01.
    if (reducedMotion) return;
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          const idx = Number((entry.target as HTMLElement).dataset.step);
          if (Number.isNaN(idx)) continue;
          if (entry.isIntersecting) visibleRows.current.add(idx);
          else visibleRows.current.delete(idx);
        }
        if (visibleRows.current.size > 0) {
          // Midline rule; tie-break to the lower row.
          setActive(Math.max(...Array.from(visibleRows.current)));
        }
      },
      { rootMargin: "-45% 0px -45% 0px" }
    );
    rowRefs.current.forEach((el) => el && observer.observe(el));
    return () => observer.disconnect();
  }, [reducedMotion]);

  return (
    <section className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-24 md:py-28">
        <Reveal>
          <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-[40px]">
            How a finding earns its score.
          </h2>
        </Reveal>

        <div className="mt-10 grid gap-12 md:mt-14 lg:grid-cols-[minmax(0,1fr)_400px] lg:gap-16">
          {/* Left: five rows on a continuous 2px spine */}
          <Reveal>
            <ol className="relative">
              {STEPS.map((step, i) => {
                const isActive = !reducedMotion && i === active;
                return (
                  <li
                    key={step.label}
                    ref={(el) => {
                      rowRefs.current[i] = el;
                    }}
                    data-step={i}
                    className="relative py-8 lg:py-10 lg:pl-10"
                  >
                    {/* Spine dot (desktop only — spine collapses on mobile) */}
                    <span
                      className={`absolute left-0 top-[46px] hidden h-2 w-2 rounded-full border transition-colors duration-150 lg:block ${
                        isActive
                          ? "border-accent-text bg-accent-text"
                          : "border-[#404040] bg-[#171717]"
                      }`}
                      aria-hidden
                    />
                    {/* Spine segment to the next row's dot */}
                    {i < STEPS.length - 1 && (
                      <span
                        className="absolute bottom-[-46px] left-[3px] top-[54px] hidden w-[2px] bg-[#262626] lg:block"
                        aria-hidden
                      />
                    )}

                    <div className="font-mono text-sm tracking-wide text-foreground-secondary">
                      {step.label}
                    </div>
                    <h3
                      className={`mt-2 text-lg font-medium tracking-[-0.01em] transition-colors duration-150 ${
                        reducedMotion || isActive
                          ? "text-foreground"
                          : "text-foreground lg:text-foreground-secondary"
                      }`}
                    >
                      {step.headline}
                    </h3>
                    <p className="mt-2 max-w-md text-[15px] leading-relaxed text-foreground-secondary">
                      {step.subhead}
                    </p>

                    {/* Mobile: keep artifact crops on rows 01 / 02 / 05 */}
                    {MOBILE_CROP_ROWS.has(i) && (
                      <div className="mt-5 flex flex-col rounded-xl border border-border bg-[#0a0a0a] p-4 lg:hidden">
                        {ARTIFACTS[i]}
                      </div>
                    )}
                  </li>
                );
              })}
            </ol>
          </Reveal>

          {/* Right: ONE sticky artifact card, cross-fading per active row */}
          <div className="hidden lg:block">
            <div className="sticky top-[96px]">
              <div className="relative h-[340px] overflow-hidden rounded-xl border border-border bg-[#0a0a0a]">
                {ARTIFACTS.map((artifact, i) => {
                  const shown = reducedMotion ? i === 0 : i === active;
                  return (
                    <div
                      key={STEPS[i].label}
                      aria-hidden={!shown}
                      className={`absolute inset-0 flex flex-col p-5 transition-opacity duration-200 ${
                        shown ? "opacity-100" : "pointer-events-none opacity-0"
                      }`}
                    >
                      {artifact}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

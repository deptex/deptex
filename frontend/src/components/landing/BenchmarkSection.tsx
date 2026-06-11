/**
 * §3.7 Benchmark — "we show our numbers".
 * landing-page-redesign.plan.md: GATED on the fresh corpus re-run (pre-flight
 * blocker #4 / asset A9) — every figure below is a placeholder until then, and
 * the section says so in a visible mono notice. All numbers/captions/gate lines
 * live in one const so the re-run updates a single object.
 * Motion: shared reveal only; the ✓ marks never animate in sequence.
 */
import { Reveal, RepoLink } from "./primitives";

const BENCHMARK = {
  headline: "79.6%*",
  statCaption:
    "weighted noise reduction on our published 49-CVE corpus — 4 real OSS apps, hand-labeled ground truth, scoring formula in the repo.",
  methodologyPath: "depscanner/docs/reachability-benchmark.md",
  footnote:
    "* Gate-1 formula: (unreachable + 0.5 × module) / observed = (34 + 5)/49. 4 repos, 49 CVEs, 3 ecosystems. Corpus-specific — read the caveats.",
  promptLine: "$ npm run test:reachability-corpus",
  gateLines: [
    "Gate 1 — noise ≥60%",
    "Gate 2 — eco floor",
    "Gate 3 — zero false negatives:",
  ],
  ceilingLine:
    "The honest ceiling for this metric is ~85–92%. Numbers above that are unverifiable, which is why ours ships with the corpus.",
} as const;

export default function BenchmarkSection() {
  return (
    <section className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-24">
        <Reveal>
          <h2 className="text-[32px] font-semibold leading-tight tracking-[-0.02em] text-foreground md:text-[40px]">
            Our noise number comes with a corpus.
          </h2>
          <p className="mt-4 inline-block rounded-md border border-dashed border-[#404040] bg-[#0a0a0a] px-3 py-1.5 font-mono text-xs text-foreground-secondary">
            placeholder figures — pending fresh corpus re-run (A9)
          </p>
        </Reveal>

        <div className="mt-10 grid items-stretch gap-4 md:grid-cols-2">
          {/* Stat card — the 48px numeral is never separated from its caption */}
          <Reveal className="h-full">
            <div className="flex h-full flex-col rounded-xl border border-[#262626] bg-[#0a0a0a] p-6">
              <span className="font-mono text-[48px] leading-none tabular-nums text-foreground">
                {BENCHMARK.headline}
              </span>
              <p className="mt-3 text-sm leading-relaxed text-foreground-secondary">
                {BENCHMARK.statCaption}
              </p>
              <div className="mt-3">
                <RepoLink path={BENCHMARK.methodologyPath} label="Methodology" />
              </div>
              <p className="mt-auto pt-5 font-mono text-xs leading-relaxed tabular-nums text-foreground-secondary">
                {BENCHMARK.footnote}
              </p>
            </div>
          </Reveal>

          {/* Terminal card — gate output as real mono text, no sequential animation */}
          <Reveal delayMs={80} className="h-full">
            <div className="flex h-full flex-col rounded-xl border border-[#262626] bg-[#050505] p-6 font-mono text-[13px] leading-relaxed">
              <p className="text-foreground-secondary">{BENCHMARK.promptLine}</p>
              <div className="mt-4 flex flex-col gap-1.5">
                {BENCHMARK.gateLines.map((line) => (
                  <div key={line} className="flex items-baseline justify-between gap-4">
                    <span className="text-foreground">{line}</span>
                    <span className="text-accent-text">✓</span>
                  </div>
                ))}
              </div>
              <p className="mt-auto pt-5 text-xs text-foreground-secondary">
                sample data — real scan output replaces this (asset A9)
              </p>
            </div>
          </Reveal>
        </div>

        <Reveal delayMs={80} className="mt-12">
          <p className="max-w-[640px] text-[15px] leading-relaxed text-foreground-secondary">
            {BENCHMARK.ceilingLine}
          </p>
        </Reveal>
      </div>
    </section>
  );
}

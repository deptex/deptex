/**
 * §3.4 The honesty split — the product-proof "wow" moment
 * (landing-page-redesign.plan.md). Same scan, two verdicts: a confirmed
 * finding at depscore 92 next to an unreachable one at 0. Noise dies by
 * evidence, not trust-us suppression. No glow here — the page's glow budget
 * is spent on the hero artifact and the Aegis recording.
 *
 * Card data is OBVIOUSLY-SAMPLE scaffold content; real rows from the express
 * dogfood scan replace it (asset A2).
 */
import { Reveal, TierPill } from "./primitives";

export default function HonestySplit() {
  return (
    <section className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-24">
        <Reveal>
          <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
            Most of your CVE backlog is unreachable.
            <span className="block">See the proof either way.</span>
          </h2>
          <p className="mt-4 text-[15px] text-foreground-secondary">
            Same repo. Same scan. Two verdicts.
          </p>
        </Reveal>

        <div className="mt-10 grid grid-cols-1 items-stretch gap-4 md:grid-cols-2 md:gap-6">
          {/* Confirmed card — mobile stacks this first */}
          <Reveal className="h-full">
            <div className="flex h-full flex-col gap-3 rounded-xl border border-[#404040] bg-[#0a0a0a] p-5">
              <div className="font-mono text-sm tabular-nums text-foreground">
                CVE-XXXX-XXXXX · package-a@1.2.3
              </div>
              <div className="flex items-center justify-between gap-3">
                <TierPill tier="confirmed" />
                <span className="font-mono text-sm tabular-nums">
                  <span className="text-foreground-secondary">depscore </span>
                  <span className="text-foreground">92</span>
                </span>
              </div>
              <div className="font-mono text-[13px] leading-relaxed text-foreground">
                req.query.id → buildQuery(id) → sink ⚠
              </div>
              <div className="font-mono text-xs tabular-nums text-foreground-secondary">
                3 hops · entry: public, unauthenticated route
              </div>
              <div className="mt-auto pt-2 text-sm text-foreground-secondary">
                view the flow →
              </div>
            </div>
          </Reveal>

          {/* Unreachable card — deliberately visually quieter */}
          <Reveal delayMs={80} className="h-full">
            <div className="flex h-full flex-col gap-3 rounded-xl border border-border bg-[#0a0a0a] p-5">
              <div className="font-mono text-sm tabular-nums text-foreground-secondary">
                CVE-XXXX-XXXXX · package-b@4.5.6
              </div>
              <div className="flex items-center justify-between gap-3">
                <TierPill tier="unreachable" />
                <span className="font-mono text-sm tabular-nums text-foreground-secondary">
                  depscore 0
                </span>
              </div>
              <div className="font-mono text-[13px] leading-relaxed text-foreground-secondary">
                vulnerable fn: res.redirect
              </div>
              <div className="text-xs text-foreground-secondary">
                never called from your code
              </div>
              <div className="mt-auto pt-2 text-sm text-foreground-secondary">
                auto-deprioritized · proof →
              </div>
            </div>
          </Reveal>
        </div>

        <Reveal delayMs={160}>
          <p className="mt-3 font-mono text-xs text-foreground-secondary">
            sample data — real scan output replaces this (asset A2)
          </p>
          <p className="mt-10 max-w-[640px] text-[15px] leading-relaxed">
            <span className="text-foreground">
              Unreachable findings score zero and drop out of your queue.
            </span>{" "}
            <span className="text-foreground-secondary">
              {"They stay visible, with the evidence for why they don't matter."}
            </span>
          </p>
        </Reveal>
      </div>
    </section>
  );
}

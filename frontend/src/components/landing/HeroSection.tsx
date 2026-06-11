/**
 * HeroSection — landing-page-redesign.plan.md §3.2.
 *
 * Motion: H1 + subhead + CTAs render INSTANTLY (LCP candidates — zero
 * entrance animation, no Reveal). The trace panel's one-time draw-on
 * pass lives inside TraceSpecimen. Atmosphere = the wave-gradient node
 * chain (founder pick, 2026-06-11).
 */
import { Link } from "react-router-dom";
import { Button } from "../ui/button";
import { RepoLink, SpecimenFrame } from "./primitives";
import TraceSpecimen from "./TraceSpecimen";

export default function HeroSection() {
  return (
    <section className="relative w-full overflow-hidden bg-[#050505]">
      {/* Wave atmosphere, positioned behind the headline zone */}
      <div className="absolute inset-x-0 top-0 h-[700px] pointer-events-none" aria-hidden>
        <div className="wave-gradient">
          <div className="wave-node node-1" />
          <div className="wave-node node-2" />
          <div className="wave-node node-3" />
          <div className="wave-node node-4" />
          <div className="wave-node node-5" />
        </div>
      </div>

      <div className="relative z-10 mx-auto max-w-[1200px] px-6 pb-20 pt-28 sm:pb-24 sm:pt-36">
        <div className="mx-auto max-w-[800px] text-center">
          <h1 className="text-[38px] font-semibold leading-[1.1] tracking-[-0.02em] text-foreground sm:text-[60px]">
            Your repo sets the score.
            <span className="block">
              <span className="bg-gradient-to-r from-[#2dd4bf] via-[#34d08a] to-[#86efac] bg-clip-text text-transparent">
                Aegis
              </span>{" "}
              writes the fix.
            </span>
          </h1>
          <p className="mx-auto mt-6 max-w-[640px] text-[15px] leading-[1.6] text-foreground sm:text-[17px]">
            Every finding gets a contextual risk score based on your code, not just CVSS.
            Aegis, your org's own security engineer, investigates and writes the fix.
          </p>

          {/* CTAs — mobile: stack full-width, green first */}
          <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
            <Button variant="green" asChild className="w-full sm:w-auto">
              <Link to="/login">Try for free</Link>
            </Button>
            {/* Same pill geometry as the green primary (settings-cancel pattern) */}
            <Button
              variant="outline"
              asChild
              className="w-full !h-8 !rounded-lg !px-3 text-foreground sm:w-auto"
            >
              <Link to="/get-demo">Book a demo</Link>
            </Button>
          </div>
        </div>

        {/* The trace specimen — the page's focal artifact, one glow */}
        <div className="mx-auto mt-14 max-w-[720px]">
          <SpecimenFrame glow>
            <TraceSpecimen />
          </SpecimenFrame>
          <div className="mt-3 flex flex-col items-center gap-1 text-center">
            <p className="font-mono text-xs text-foreground-secondary">
              ▸ Real scan output from our open dogfood corpus —{" "}
              <RepoLink path="depscanner/test-repos" />
            </p>
            <p className="font-mono text-[11px] text-foreground-muted">
              sample data — real scan output replaces this (asset A1)
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

/**
 * HeroSection — landing-page-redesign.plan.md §3.2.
 *
 * Motion: H1 + subhead + CTAs render INSTANTLY (LCP candidates — zero
 * entrance animation, no Reveal). Atmosphere = the folded DotSheet with a
 * clearance pocket behind the type (replaced the wave-gradient, founder
 * 2026-06-12; wave CSS kept dormant in Main.css). Type-only: the
 * screenshot collage was cut 2026-06-11 (founder) — the FindingJourney
 * film panel directly below is the page's first hero-scale product visual.
 */
import { Link } from "react-router-dom";
import { Button } from "../ui/button";
import DotDrape from "./DotDrape";

export default function HeroSection() {
  return (
    <section className="relative w-full overflow-hidden bg-[#050505]">
      {/* Atmosphere: static halftone drapery in the top-left corner only
          (founder call 2026-06-12 — one anchored statement piece, not a
          symmetric wrap; no animation, like the reference) */}
      <div className="pointer-events-none absolute inset-0 hidden md:block" aria-hidden>
        <DotDrape className="h-full w-full" />
      </div>

      <div className="relative z-10 mx-auto max-w-[1200px] px-6 pb-6 pt-28 sm:pb-8 sm:pt-36">
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

      </div>
    </section>
  );
}

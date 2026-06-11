/**
 * HeroSection — landing-page-redesign.plan.md §3.2.
 *
 * Motion: H1 + subhead + CTAs render INSTANTLY (LCP candidates — zero
 * entrance animation, no Reveal). Atmosphere = the wave-gradient node
 * chain (founder pick, 2026-06-11). Visual = two-piece collage:
 * findings table + Aegis fix card (one receipt per headline beat).
 */
import { Link } from "react-router-dom";
import { Button } from "../ui/button";

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

        {/* Hero collage — two receipts for the two-beat headline:
            main window = findings table ("your repo sets the score"),
            overlap card = Aegis fixing ("Aegis writes the fix").
            Real app screenshots replace the canvases (capture specs in plan §7). */}
        <div className="relative mx-auto mb-10 mt-16 max-w-[880px]">
          <div
            className="glow-green left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 opacity-40"
            aria-hidden
          />
          <div className="relative">
            {/* HERO-1: the findings dashboard — "your repo sets the score" */}
            <img
              src="/images/landing/hero-findings.png"
              alt="Deptex findings dashboard: vulnerability prioritization funnel, findings by type, and the findings table with contextual depscores"
              className="w-full rounded-xl border border-border shadow-[0_8px_40px_-8px_rgba(0,0,0,0.7)]"
            />
            {/* HERO-2: the Aegis fix plan — "Aegis writes the fix" */}
            <div className="relative mx-6 -mt-8 overflow-hidden rounded-xl border border-[#333] shadow-[0_16px_48px_-4px_rgba(0,0,0,0.9)] sm:absolute sm:-bottom-12 sm:-right-10 sm:mx-0 sm:mt-0 sm:w-[380px]">
              <img
                src="/images/landing/hero-aegis-plan.png"
                alt="Aegis fix plan: patch CVE-2021-23337 by bumping lodash — issue, plan, to-dos, and verification steps"
                className="aspect-[3/4] w-full object-cover object-top"
              />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/**
 * HeroSection — Linear/Cursor-style hero (founder 2026-06-16).
 *
 * Left-aligned title + CTAs, then a MASSIVE product visual directly below. The
 * product IS the art — no abstract background (which ended the wave→dots→grid
 * saga). The big visual is HeroShowcase: a tabbed, INTERACTIVE product window
 * (Connect / Triage / Fix) replacing the old film — real scrollable DOM, no
 * recording (founder 2026-06-16, Aikido reference).
 *
 * The H1 renders instantly (LCP). The standalone FindingJourney film section
 * was absorbed here and is now unused.
 */
import { Link } from "react-router-dom";
import { Button } from "../ui/button";
import HeroShowcase from "./HeroShowcase";

export default function HeroSection() {
  return (
    <section className="relative w-full overflow-hidden bg-[#050505]">
      <div className="mx-auto max-w-[1200px] px-6 pb-20 pt-28 sm:pt-36">
        {/* Title block — left-aligned title, CTAs pushed right and
            bottom-aligned with the subhead (Linear pattern) */}
        <div className="flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-[820px]">
            <h1 className="text-[40px] font-semibold leading-[1.05] tracking-[-0.02em] text-foreground sm:text-[60px]">
              Secure your stack.
              <span className="block">Cut the noise.</span>
              <span className="block">
                <span className="bg-gradient-to-r from-[#2dd4bf] via-[#34d08a] to-[#86efac] bg-clip-text text-transparent">
                  Aegis
                </span>{" "}
                does the rest.
              </span>
            </h1>
            <p className="mt-6 max-w-[500px] text-[15px] leading-[1.6] text-foreground sm:text-base">
              Deptex is the AI security platform for your dependencies and code —
              every finding scored by what's actually reachable, not just CVSS.
            </p>
          </div>
          <div className="flex shrink-0 gap-3">
            <Button variant="green" asChild>
              <Link to="/login">Try for free</Link>
            </Button>
            <Button
              variant="outline"
              asChild
              className="!h-8 !rounded-lg !px-3 text-foreground"
            >
              <Link to="/get-demo">Book a demo</Link>
            </Button>
          </div>
        </div>

        {/* Massive product visual — tabbed interactive showcase */}
        <div className="mt-16 sm:mt-20">
          <HeroShowcase />
        </div>
      </div>
    </section>
  );
}

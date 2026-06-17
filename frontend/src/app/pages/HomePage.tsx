/**
 * Landing page — composition shell.
 *
 * Order reworked 2026-06-16 after a competitor landing-page study (Endor,
 * Socket, Semgrep, Aikido, Snyk, Wiz): the number-forward camp asserts its
 * noise-reduction stat PUNCHY and HIGH and parks methodology in docs — nobody
 * leads with (or even ships) a rigorous benchmark block on the homepage. So the
 * heavy benchmark was split then dropped: the punchy 79.6% lives in ProofStatBand
 * (the logo-wall slot — pre-launch, the number IS the social proof) and the
 * Verified section explains HOW we earn it; the corpus/methodology stays in the
 * repo (depscanner/docs/reachability-benchmark.md), where the field keeps it.
 * Aegis was promoted up to right after Verified — the hero's differentiator.
 *
 * Top (founder 2026-06-16): the hero is now Linear/Cursor-style — left-aligned
 * title + CTAs with the product film as its big visual (HeroSection absorbed the
 * old standalone FindingJourney section; that file is now unused). Cut from the original
 * plan: policy-as-code section, honesty split + evidence ladder (absorbed into
 * FindingJourney), standalone ProofStrip (→ ProofStatBand), deep BenchmarkSection
 * (placeholder-gated + orphaned; methodology lives in the repo), InlineCTA, and
 * ChangelogBand (hardcoded entries go stale; docs routes not live pre-launch).
 */
import HeroSection from "../../components/landing/HeroSection";
import ProofStatBand from "../../components/landing/ProofStatBand";
import VerifiedSection from "../../components/landing/VerifiedSection";
import AegisSection from "../../components/landing/AegisSection";
import BreadthWall from "../../components/landing/BreadthWall";
import OpenCodeSection from "../../components/landing/OpenCodeSection";
import StackBand from "../../components/landing/StackBand";
import FinalCTA from "../../components/landing/FinalCTA";

export default function HomePage() {
  return (
    <div className="bg-[#050505] text-foreground">
      <HeroSection />
      <ProofStatBand />
      <VerifiedSection />
      <AegisSection />
      <BreadthWall />
      <OpenCodeSection />
      <StackBand />
      <FinalCTA />
    </div>
  );
}

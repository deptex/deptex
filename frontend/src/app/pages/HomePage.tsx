/**
 * Landing page — composition shell.
 *
 * Order reworked 2026-06-16 after a competitor landing-page study (Endor,
 * Socket, Semgrep, Aikido, Snyk, Wiz): the number-forward camp asserts its
 * noise-reduction stat PUNCHY and HIGH and parks methodology in docs — nobody
 * leads with (or even ships) a rigorous benchmark block on the homepage. So the
 * heavy benchmark was split then dropped.
 *
 * Section 2 (founder 2026-06-18): a standalone stat band / engine diagram /
 * noise funnel were all tried and dropped — they duplicated the reachability
 * story Verified already tells with a real product visual. So the punchy 79.6% /
 * 5× stats were FOLDED INTO VerifiedSection ("we don't guess, we trace the
 * path"), which is now section 2 right under the hero: the outcome stat + the
 * trace→findings proof in one place. The corpus/methodology stays in the repo
 * (depscanner/docs/reachability-benchmark.md). Aegis follows — the differentiator.
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
import VerifiedSection from "../../components/landing/VerifiedSection";
import AegisSection from "../../components/landing/AegisSection";
import BreadthWall from "../../components/landing/BreadthWall";
import FrameworkBand from "../../components/landing/FrameworkBand";
import OpenSourceSection from "../../components/landing/OpenSourceSection";
import FinalCTA from "../../components/landing/FinalCTA";

export default function HomePage() {
  return (
    <div className="bg-[#050505] text-foreground">
      <HeroSection />
      <VerifiedSection />
      <AegisSection />
      <BreadthWall />
      <FrameworkBand />
      <OpenSourceSection />
      <FinalCTA />
    </div>
  );
}

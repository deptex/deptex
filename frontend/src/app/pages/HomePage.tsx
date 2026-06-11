/**
 * Landing page — composition shell (founder-directed lineup, 2026-06-11):
 * hero → finding journey (flagship) → noise number (receipts, near the top)
 * → mid-page CTA → numbers + breadth → Aegis → open code → stack →
 * changelog → close.
 *
 * Cut from the original plan lineup: policy-as-code section (engine exists
 * in code but is not used in the app currently — founder call), honesty
 * split + pipeline + evidence ladder (absorbed into FindingJourney).
 */
import HeroSection from "../../components/landing/HeroSection";
import FindingJourney from "../../components/landing/FindingJourney";
import BenchmarkSection from "../../components/landing/BenchmarkSection";
import InlineCTA from "../../components/landing/InlineCTA";
import ProofStrip from "../../components/landing/ProofStrip";
import BreadthWall from "../../components/landing/BreadthWall";
import AegisSection from "../../components/landing/AegisSection";
import OpenCodeSection from "../../components/landing/OpenCodeSection";
import StackBand from "../../components/landing/StackBand";
import ChangelogBand from "../../components/landing/ChangelogBand";
import FinalCTA from "../../components/landing/FinalCTA";

export default function HomePage() {
  return (
    <div className="bg-[#050505] text-foreground">
      <HeroSection />
      <FindingJourney />
      <BenchmarkSection />
      <InlineCTA />
      <ProofStrip />
      <BreadthWall />
      <AegisSection />
      <OpenCodeSection />
      <StackBand />
      <ChangelogBand />
      <FinalCTA />
    </div>
  );
}

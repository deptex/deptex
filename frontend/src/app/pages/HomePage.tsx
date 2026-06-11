/**
 * Landing page — composition shell for the section components in
 * components/landing/ (landing-page-redesign.plan.md §3, narrative order §2):
 * claim → instant artifact proof → consequence → mechanism → depth → receipts
 * → breadth → action → trust → momentum → close.
 *
 * Scaffold state: DOM artifacts carry labeled sample data; recordings render
 * as PlaceholderCanvas slots (assets A1–A11, plan §7).
 */
import HeroSection from "../../components/landing/HeroSection";
import ProofStrip from "../../components/landing/ProofStrip";
import HonestySplit from "../../components/landing/HonestySplit";
import PipelineWalkthrough from "../../components/landing/PipelineWalkthrough";
import EvidenceLadder from "../../components/landing/EvidenceLadder";
import BenchmarkSection from "../../components/landing/BenchmarkSection";
import InlineCTA from "../../components/landing/InlineCTA";
import BreadthWall from "../../components/landing/BreadthWall";
import AegisSection from "../../components/landing/AegisSection";
import PolicySection from "../../components/landing/PolicySection";
import OpenCodeSection from "../../components/landing/OpenCodeSection";
import StackBand from "../../components/landing/StackBand";
import ChangelogBand from "../../components/landing/ChangelogBand";
import FinalCTA from "../../components/landing/FinalCTA";

export default function HomePage() {
  return (
    <div className="bg-[#050505] text-foreground">
      <HeroSection />
      <ProofStrip />
      <HonestySplit />
      <PipelineWalkthrough />
      <EvidenceLadder />
      <BenchmarkSection />
      <InlineCTA />
      <BreadthWall />
      <AegisSection />
      <PolicySection />
      <OpenCodeSection />
      <StackBand />
      <ChangelogBand />
      <FinalCTA />
    </div>
  );
}

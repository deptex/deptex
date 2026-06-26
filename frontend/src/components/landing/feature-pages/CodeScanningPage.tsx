/**
 * Code scanning — dedicated product page. Video hero → real findings table
 * (SAST + secrets) → capability grid → CTA.
 */
import { Braces, KeyRound, GitPullRequest, ShieldCheck } from "lucide-react";
import VulnerabilityExpandableTable from "../../security/VulnerabilityExpandableTable";
import { HERO_ORG_ID, codeFindings, heroFindingDetail } from "../heroDemo";
import {
  FeatureVideoHero,
  Showcase,
  CapabilityGrid,
  FeatureFinalCTA,
  type Capability,
} from "./sections";

const CAPS: Capability[] = [
  { Icon: Braces, title: "SAST", body: "Static analysis across your whole workspace, deduped and CWE-scored, so risks are caught before they merge." },
  { Icon: KeyRound, title: "Secret detection", body: "Leaked keys and tokens, caught and live-verified — a working credential outranks a dormant one." },
  { Icon: GitPullRequest, title: "PR checks & merge gating", body: "Findings surface as PR checks with sticky comments; block merges on GitHub and GitLab." },
  { Icon: ShieldCheck, title: "Deduped & scored", body: "Cross-file dedup and CWE-based scoring, so one root cause isn't reported as ten separate alerts." },
];

export default function CodeScanningPage() {
  return (
    <div className="bg-background text-foreground">
      <FeatureVideoHero
        eyebrow="Code scanning"
        headline="Catch it before it merges."
        sub="Static analysis and live-verified secret detection across your whole codebase — deduped, CWE-scored, and surfaced as PR checks."
      />

      <Showcase
        title="SAST and secrets, in one list."
        body="Every static-analysis finding and verified secret, ranked by depscore so the exploitable ones rise to the top instead of getting buried under style nits."
      >
        <VulnerabilityExpandableTable
          organizationId={HERO_ORG_ID}
          rows={codeFindings}
          canManageFindings={false}
          fetchDetail={heroFindingDetail}
          hideRefineToggle
          hideTypeFilter
        />
      </Showcase>

      <CapabilityGrid title="Everything in code scanning." items={CAPS} />

      <FeatureFinalCTA
        title="Scan your code for what's exploitable."
        sub="Connect a repo and see your first findings in minutes."
      />
    </div>
  );
}

/**
 * Infrastructure & DAST — dedicated product page. Video hero → real findings
 * table (IaC misconfigs) → capability grid → CTA. DAST has no mock component,
 * so it lives in the capability grid.
 */
import { Layers, Container, Radar, ArrowUpCircle } from "lucide-react";
import VulnerabilityExpandableTable from "../../security/VulnerabilityExpandableTable";
import { HERO_ORG_ID, infraFindings, heroFindingDetail } from "../heroDemo";
import {
  FeatureVideoHero,
  Showcase,
  CapabilityGrid,
  FeatureFinalCTA,
  type Capability,
} from "./sections";

const CAPS: Capability[] = [
  { Icon: Layers, title: "IaC misconfigurations", body: "Misconfigs across Terraform, Kubernetes, Helm, CloudFormation and Dockerfiles, mapped to the files that introduce them." },
  { Icon: Container, title: "Container & image CVEs", body: "Image CVEs with base-image upgrade advice, and a bridge linking OS-package CVEs to the code that loads them." },
  { Icon: ArrowUpCircle, title: "Base-image upgrades", body: "Concrete upgrade paths that clear the most CVEs for the least churn." },
  { Icon: Radar, title: "DAST", body: "Your running app gets actively attacked, guided by an OpenAPI spec synthesized from your detected routes." },
];

export default function InfrastructureDastPage() {
  return (
    <div className="bg-background text-foreground">
      <FeatureVideoHero
        eyebrow="Infrastructure & DAST"
        headline="Secure what you ship and run."
        sub="Misconfigurations across Terraform, Kubernetes and Dockerfiles, image CVEs with base-image fixes, and active runtime testing of your live app."
      />

      <Showcase
        title="Misconfigs, mapped to the file."
        body="Every IaC and container finding points at the exact line that introduces it and the fix — ranked by depscore, so a world-open security group beats a missing readiness probe."
      >
        <VulnerabilityExpandableTable
          organizationId={HERO_ORG_ID}
          rows={infraFindings}
          canManageFindings={false}
          fetchDetail={heroFindingDetail}
          hideRefineToggle
          hideTypeFilter
        />
      </Showcase>

      <CapabilityGrid title="Everything in infrastructure & DAST." items={CAPS} />

      <FeatureFinalCTA
        title="Scan what you deploy."
        sub="Connect a repo and catch the misconfigs before they ship."
      />
    </div>
  );
}

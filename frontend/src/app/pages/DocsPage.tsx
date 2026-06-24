import { useState } from "react";
import VulnerabilitiesContent from "./docs/VulnerabilitiesContent";
import ProjectsContent from "./docs/ProjectsContent";
import DependenciesContent from "./docs/DependenciesContent";
import ComplianceContent from "./docs/ComplianceContent";
import QuickStartContent from "./docs/QuickStartContent";
import OrganizationsContent from "./docs/OrganizationsContent";
import SBOMComplianceContent from "./docs/SBOMComplianceContent";
import TeamsContent from "./docs/TeamsContent";
import AegisContent from "./docs/AegisContent";
import EnterpriseSecurityContent from "./docs/EnterpriseSecurityContent";
import IntegrationsContent from "./docs/IntegrationsContent";
import PoliciesContent from "./docs/PoliciesContent";
import NotificationRulesContent from "./docs/NotificationRulesContent";
import TermsContent from "./docs/TermsContent";
import PrivacyContent from "./docs/PrivacyContent";
import SecurityContent from "./docs/SecurityContent";

interface DocMeta {
  title: string;
  description: string;
}

const docMeta: Record<string, DocMeta> = {
  introduction: {
    title: "Introduction",
    description: "Learn what Deptex is and how it helps you manage dependency security across your organization.",
  },
  "quick-start": {
    title: "Quick Start",
    description: "Get up and running with Deptex in minutes with this step-by-step setup guide.",
  },
  projects: {
    title: "Projects",
    description: "How Deptex models your repositories as projects, runs extraction pipelines, and tracks status.",
  },
  dependencies: {
    title: "Dependencies",
    description: "Dependency resolution, scoring, supply chain signals, malicious detection, and version management.",
  },
  vulnerabilities: {
    title: "Vulnerabilities",
    description: "Vulnerability discovery, Depscore risk scoring, reachability analysis, EPSS, CISA KEV, and AI fixing.",
  },
  compliance: {
    title: "Compliance",
    description: "Custom statuses, policy evaluation flow, SBOM exports, license tracking, and policy versioning.",
  },
  "sbom-compliance": {
    title: "SBOM Compliance",
    description: "Software Bill of Materials generation, CycloneDX and SPDX formats, legal notices, and compliance frameworks.",
  },
  organizations: {
    title: "Organizations",
    description: "Organization settings, custom statuses, roles and permissions, members, and integrations.",
  },
  teams: {
    title: "Teams",
    description: "Team-scoped project visibility, membership, dashboards, and permission model.",
  },
  policies: {
    title: "Policies",
    description: "Define and enforce security and compliance policies across your organization with policy-as-code.",
  },
  integrations: {
    title: "Integrations",
    description: "Connect Deptex with GitHub, GitLab, Bitbucket, Slack, and more.",
  },
  "notification-rules": {
    title: "Notification Rules",
    description: "Configure automated alerts that trigger when specific events occur across your projects and dependencies.",
  },
  terms: {
    title: "Terms of Service",
    description: "Terms governing your use of Deptex.",
  },
  privacy: {
    title: "Privacy Policy",
    description: "How we collect, use, and protect your data.",
  },
  security: {
    title: "Security",
    description: "Our security practices and commitment.",
  },
  "enterprise-security": {
    title: "Enterprise Security",
    description: "MFA, SSO (SAML), session management, IP allowlist, API tokens, audit log, and SCIM provisioning.",
  },
  aegis: {
    title: "Aegis",
    description: "Autonomous security agent: chat, tasks, automations, and Slack bot.",
  },
};

const fallback: DocMeta = {
  title: "Not Found",
  description: "This documentation page doesn't exist yet.",
};

interface DocsPageProps {
  section?: string;
}

const introductionOffers: { title: string; body: string }[] = [
  {
    title: "Reachability-scored CVE scanning",
    body: "Every dependency vulnerability is scored by whether it's actually reachable in your code (Depscore), across 8 languages — so you fix what's exploitable, not just what's listed.",
  },
  {
    title: "Supply-chain & malicious package detection",
    body: "Malicious package detection, SLSA provenance verification, and OpenSSF signals on every dependency you pull in.",
  },
  {
    title: "Code scanning",
    body: "Static analysis (SAST) and live-verified secret detection across your whole codebase, deduped and scored.",
  },
  {
    title: "Infrastructure & DAST",
    body: "IaC misconfigurations, container image CVEs with base-image fixes, and active runtime testing of your live app.",
  },
  {
    title: "Aegis — autonomous security agent",
    body: "Chats about your posture, plans the fix, opens a draft pull request you review, runs scheduled automations, and remembers context between runs.",
  },
  {
    title: "Policy-as-code",
    body: "Per-dependency policies, project statuses, and PR checks, executed in a sandbox and versioned with full change history.",
  },
  {
    title: "Organizations, teams & integrations",
    body: "Role-based access with scoped project visibility, wired into GitHub, GitLab, Bitbucket, Slack, Jira, and Linear.",
  },
];

function IntroductionContent() {
  const [screenshotError, setScreenshotError] = useState(false);

  return (
    <>
      <p className="text-foreground/90 leading-relaxed mb-8">
        Deptex is an AI-powered dependency and code security platform. It connects to your
        repositories, scans every dependency, line of code, and piece of infrastructure, and scores
        each finding by what&apos;s actually reachable — then Aegis investigates and ships the fix as
        a pull request you review.
      </p>

      <div className="mb-10">
        <h2 className="text-lg font-semibold text-foreground mb-3">See the product</h2>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden shadow-md aspect-video bg-background-subtle flex items-center justify-center min-h-[200px]">
          {screenshotError ? (
            <p className="text-sm text-foreground/70 px-4 text-center">
              Overview image at <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs">public/images/dashboardimage.png</code> could not be loaded.
            </p>
          ) : (
            <img
              src="/images/dashboardimage.png"
              alt="Deptex organization overview — org graph with teams, projects, health scores, and extraction status"
              className="w-full h-full object-cover object-top"
              onError={() => setScreenshotError(true)}
            />
          )}
        </div>
        <p className="mt-2 text-sm text-foreground/70">
          Organization dashboard: org graph with teams, projects, health scores, and extraction status.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-4">What you get</h2>
        <div className="space-y-5">
          {introductionOffers.map((item) => (
            <div key={item.title} className="border-l-2 border-white/[0.08] pl-4">
              <h3 className="font-medium text-foreground">{item.title}</h3>
              <p className="mt-1 text-sm leading-relaxed text-foreground/80">{item.body}</p>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

export default function DocsPage({ section }: DocsPageProps) {
  const meta = (section && docMeta[section]) || fallback;

  const renderContent = () => {
    switch (section) {
      case "introduction":
        return <IntroductionContent />;
      case "quick-start":
        return <QuickStartContent />;
      case "projects":
        return <ProjectsContent />;
      case "dependencies":
        return <DependenciesContent />;
      case "vulnerabilities":
        return <VulnerabilitiesContent />;
      case "compliance":
        return <ComplianceContent />;
      case "sbom-compliance":
        return <SBOMComplianceContent />;
      case "organizations":
        return <OrganizationsContent />;
      case "teams":
        return <TeamsContent />;
      case "integrations":
        return <IntegrationsContent />;
      case "policies":
        return <PoliciesContent />;
      case "notification-rules":
        return <NotificationRulesContent />;
      case "aegis":
        return <AegisContent />;
      case "terms":
        return <TermsContent />;
      case "privacy":
        return <PrivacyContent />;
      case "security":
        return <SecurityContent />;
      case "enterprise-security":
        return <EnterpriseSecurityContent />;
      default:
        return (
          <div className="rounded-lg border border-border bg-background-card p-6">
            <p className="text-sm text-foreground/90">
              This documentation page doesn&apos;t exist yet.
            </p>
          </div>
        );
    }
  };

  return (
    <article>
      <div className="mb-8 pb-8 border-b border-border">
        <p className="text-xs font-semibold uppercase tracking-wider text-foreground/60 mb-3">
          Documentation
        </p>
        <h1 className="text-3xl font-semibold text-foreground mb-3">{meta.title}</h1>
        <p className="text-base text-foreground/85 leading-relaxed">{meta.description}</p>
      </div>

      {renderContent()}
    </article>
  );
}

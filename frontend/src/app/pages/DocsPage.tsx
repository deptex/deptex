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
import WatchtowerContent from "./docs/WatchtowerContent";
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
  watchtower: {
    title: "Watchtower",
    description: "Supply chain monitoring and forensic analysis per dependency, with an organization-level overview.",
  },
  aegis: {
    title: "Aegis",
    description: "Autonomous security agent: chat, tasks, automations, Slack bot, PR review, and BYOK AI.",
  },
};

const fallback: DocMeta = {
  title: "Not Found",
  description: "This documentation page doesn't exist yet.",
};

interface DocsPageProps {
  section?: string;
}

const introductionOffers = [
  "Custom organization-defined statuses for project compliance (not just pass/fail)",
  "AI-powered vulnerability fixing with automated PR creation (Aider) and human review",
  "Dependency Score (package reputation) and Depscore (context-aware vulnerability risk) for prioritization",
  "Live extraction logs and real-time progress via Supabase Realtime",
  "SLSA provenance verification and malicious package detection (e.g. Socket.dev)",
  "SBOM generation and compliance tracking for frameworks and license policies",
  "Autonomous Security Agent (Aegis) to chat, run tasks, automations, and Slack bot",
  "Organizations and teams with roles, permissions, and scoped visibility",
  "Policy-as-code (packagePolicy, projectStatus, pullRequestCheck) and integrations (GitHub, GitLab, Bitbucket, Slack, etc.)",
];

function IntroductionContent() {
  const [screenshotError, setScreenshotError] = useState(false);

  return (
    <>
      <p className="text-foreground/90 leading-relaxed mb-8">
        Deptex is a security and compliance platform for your dependency supply chain. It connects to
        your repositories, tracks every dependency, and gives you a single place to see risks,
        enforce policies with custom statuses, and use AI-powered fixing (automated PRs) and the
        autonomous security agent (Aegis) to remediate and report on your behalf.
      </p>

      <div className="mb-10">
        <h2 className="text-lg font-semibold text-foreground mb-3">See the product</h2>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden shadow-md aspect-video bg-background-subtle flex items-center justify-center min-h-[200px]">
          {screenshotError ? (
            <p className="text-sm text-foreground/70 px-4 text-center">
              Add a screenshot at <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs">public/images/docs-app-overview.png</code> to show your app here.
            </p>
          ) : (
            <img
              src="/images/docs-app-overview.png"
              alt="Deptex app overview — organization dashboard with projects and dependency insights"
              className="w-full h-full object-cover object-top"
              onError={() => setScreenshotError(true)}
            />
          )}
        </div>
        <p className="mt-2 text-sm text-foreground/70">
          Organization dashboard and project overview.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">What we offer</h2>
        <ul className="space-y-2 text-foreground/90">
          {introductionOffers.map((item, i) => (
            <li key={i} className="flex gap-2">
              <span className="shrink-0 mt-1.5 size-1.5 rounded-full bg-foreground-muted" aria-hidden />
              <span className="leading-relaxed">{item}</span>
            </li>
          ))}
        </ul>
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
      case "watchtower":
        return <WatchtowerContent />;
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

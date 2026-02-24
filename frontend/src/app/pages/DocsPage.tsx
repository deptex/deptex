import { useState } from "react";

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
    description: "Get up and running with Deptex in minutes.",
  },
  projects: {
    title: "Projects",
    description: "Understand how Deptex models your repositories as projects and tracks their dependency graphs.",
  },
  dependencies: {
    title: "Dependencies",
    description: "Explore how Deptex resolves, indexes, and monitors your project's dependency tree.",
  },
  vulnerabilities: {
    title: "Vulnerabilities",
    description: "See how Deptex surfaces CVEs and advisories affecting your dependencies.",
  },
  compliance: {
    title: "Compliance",
    description: "Learn how Deptex maps your dependencies against compliance frameworks and license policies.",
  },
  "dependency-tracking": {
    title: "Dependency Tracking",
    description: "Deep dependency tracking across repositories with real-time drift detection.",
  },
  "vulnerability-intelligence": {
    title: "Vulnerability Intelligence",
    description: "CVE monitoring, enrichment, and prioritization powered by Deptex intelligence.",
  },
  "sbom-compliance": {
    title: "SBOM Compliance",
    description: "Generate and track Software Bills of Materials (SBOMs) for your projects.",
  },
  "anomaly-detection": {
    title: "Anomaly Detection",
    description: "Detect suspicious changes in your supply chain with behavioral analysis.",
  },
  "security-agent": {
    title: "Security Agent (Aegis)",
    description: "Let Deptex's autonomous AI security engineer monitor and respond to threats on your behalf.",
  },
  organizations: {
    title: "Organizations",
    description: "Manage your organization, members, and settings in Deptex.",
  },
  teams: {
    title: "Teams",
    description: "Organize members into teams with scoped project visibility and alerting.",
  },
  policies: {
    title: "Policies",
    description: "Define and enforce security and compliance policies across your organization.",
  },
  integrations: {
    title: "Integrations",
    description: "Connect Deptex with your existing tools including GitHub, Slack, and CI/CD pipelines.",
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
  "Deep dependency tracking across repositories with real-time drift detection",
  "Vulnerability intelligence: CVE monitoring, reachability analysis, and prioritization",
  "SBOM generation and compliance tracking for frameworks and license policies",
  "Anomaly detection to surface suspicious package and supply-chain behavior",
  "Autonomous Security Agent (Aegis) to monitor, remediate, and report on your behalf",
  "Organizations and teams with roles, permissions, and scoped visibility",
  "Policies and integrations (e.g. GitHub, Slack, CI/CD) to fit your workflow",
];

function IntroductionContent() {
  const [screenshotError, setScreenshotError] = useState(false);

  return (
    <>
      <p className="text-foreground-secondary leading-relaxed mb-8">
        Deptex is a security and compliance platform for your dependency supply chain. It connects to
        your repositories, tracks every dependency, and gives you a single place to see risks,
        enforce policies, and let an AI security engineer (Aegis) help fix issues automatically.
      </p>

      <div className="mb-10">
        <h2 className="text-lg font-semibold text-foreground mb-3">See the product</h2>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden shadow-md aspect-video bg-background-subtle flex items-center justify-center min-h-[200px]">
          {screenshotError ? (
            <p className="text-sm text-foreground-muted px-4 text-center">
              Add a screenshot at <code className="rounded bg-background-card px-1.5 py-0.5 text-xs">public/images/docs-app-overview.png</code> to show your app here.
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
        <p className="mt-2 text-sm text-foreground-muted">
          Organization dashboard and project overview.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">What we offer</h2>
        <ul className="space-y-2 text-foreground-secondary">
          {introductionOffers.map((item, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-primary shrink-0 mt-1.5 size-1.5 rounded-full bg-primary" aria-hidden />
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
  const isIntroduction = section === "introduction";

  return (
    <article>
      <div className="mb-8 pb-8 border-b border-border">
        <p className="text-xs font-semibold uppercase tracking-wider text-foreground-muted mb-3">
          Documentation
        </p>
        <h1 className="text-3xl font-semibold text-foreground mb-3">{meta.title}</h1>
        <p className="text-base text-foreground-secondary leading-relaxed">{meta.description}</p>
      </div>

      {isIntroduction ? (
        <IntroductionContent />
      ) : (
        <div className="rounded-lg border border-border bg-background-card p-6">
          <p className="text-sm text-foreground-secondary">
            This page is coming soon. Check back later for full documentation.
          </p>
        </div>
      )}
    </article>
  );
}

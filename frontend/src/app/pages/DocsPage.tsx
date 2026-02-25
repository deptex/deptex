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

function IntegrationsContent() {
  return (
    <div className="space-y-10">
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Deptex integrates with GitHub, GitLab, Bitbucket for CI/CD, Slack and Discord for notifications,
          and Jira, Linear, and Asana for ticketing. You can also add <strong className="text-foreground">Custom Webhook Integrations</strong> —
          a bring-your-own-endpoint approach that lets you receive events at any URL without writing a full integration.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Custom Webhooks</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          From Settings → Integrations, click &quot;Add Custom&quot; in the Notifications or Ticketing section.
          Enter a name, webhook URL (must start with <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs">https://</code> or <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs">http://</code>),
          and optionally upload an icon. On creation, you receive a signing secret — copy it immediately; it&apos;s only shown once.
        </p>
        <p className="text-foreground-secondary leading-relaxed">
          When events fire, Deptex sends HTTP POST requests to your webhook URL. Each request is signed with HMAC-SHA256 so you can verify authenticity.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Request Format</h2>
        <p className="text-foreground-secondary leading-relaxed mb-3">Each webhook request includes:</p>
        <div className="rounded-lg border border-border bg-background-subtle/30 p-4 font-mono text-sm overflow-x-auto">
          <div className="text-foreground-secondary">Headers:</div>
          <div><span className="text-foreground-muted">X-Deptex-Signature:</span> <span className="text-foreground">sha256=&lt;hmac_hex&gt;</span></div>
          <div><span className="text-foreground-muted">X-Deptex-Event:</span> <span className="text-foreground">&lt;event_type&gt;</span></div>
          <div><span className="text-foreground-muted">Content-Type:</span> <span className="text-foreground">application/json</span></div>
          <div className="mt-3 text-foreground-secondary">Body: JSON (see Payload format below)</div>
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Payload Format</h2>
        <p className="text-foreground-secondary leading-relaxed mb-3">The request body is JSON with this structure:</p>
        <pre className="rounded-lg border border-border bg-background-subtle/30 p-4 text-sm text-foreground overflow-x-auto">
{`{
  "event": "vulnerability.found",
  "timestamp": "2026-02-25T12:00:00Z",
  "organization_id": "uuid",
  "data": {
    "vulnerability_id": "CVE-2026-XXXX",
    "severity": "critical",
    "package": "lodash",
    "version": "4.17.20",
    "project": "my-project"
  }
}`}
        </pre>
        <p className="text-foreground-secondary leading-relaxed mt-2 text-sm">
          The <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs">data</code> object varies by event type.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Event Types</h2>
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-background-subtle/30">
                <th className="text-left py-2.5 px-3 font-medium text-foreground">Event</th>
                <th className="text-left py-2.5 px-3 font-medium text-foreground">Description</th>
              </tr>
            </thead>
            <tbody className="text-foreground-secondary">
              <tr className="border-b border-border"><td className="py-2.5 px-3 font-mono text-foreground">vulnerability.found</td><td className="py-2.5 px-3">A new vulnerability was detected</td></tr>
              <tr className="border-b border-border"><td className="py-2.5 px-3 font-mono text-foreground">vulnerability.resolved</td><td className="py-2.5 px-3">A vulnerability was resolved</td></tr>
              <tr className="border-b border-border"><td className="py-2.5 px-3 font-mono text-foreground">aegis.activity</td><td className="py-2.5 px-3">AI agent action or recommendation</td></tr>
              <tr className="border-b border-border"><td className="py-2.5 px-3 font-mono text-foreground">administrative.member_added</td><td className="py-2.5 px-3">A member was added to the org</td></tr>
              <tr><td className="py-2.5 px-3 font-mono text-foreground">administrative.settings_changed</td><td className="py-2.5 px-3">Organization settings were modified</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Verifying Signatures</h2>
        <p className="text-foreground-secondary leading-relaxed mb-3">
          Use the signing secret to verify that requests came from Deptex. Compute HMAC-SHA256 of the raw request body
          and compare with the <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs">X-Deptex-Signature</code> header (format: <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs">sha256=&lt;hex&gt;</code>).
        </p>
        <div className="space-y-4">
          <div>
            <p className="text-sm text-foreground-muted mb-1.5">Python</p>
            <pre className="rounded-lg border border-border bg-background-subtle/30 p-4 text-sm text-foreground overflow-x-auto">
{`import hmac
import hashlib

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = 'sha256=' + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)`}
            </pre>
          </div>
          <div>
            <p className="text-sm text-foreground-muted mb-1.5">Node.js</p>
            <pre className="rounded-lg border border-border bg-background-subtle/30 p-4 text-sm text-foreground overflow-x-auto">
{`const crypto = require('crypto');

function verifySignature(payload, signature, secret) {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(signature)
  );
}`}
            </pre>
          </div>
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">API Endpoints</h2>
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-background-subtle/30">
                <th className="text-left py-2.5 px-3 font-medium text-foreground w-24">Method</th>
                <th className="text-left py-2.5 px-3 font-medium text-foreground">Endpoint</th>
                <th className="text-left py-2.5 px-3 font-medium text-foreground">Description</th>
              </tr>
            </thead>
            <tbody className="text-foreground-secondary">
              <tr className="border-b border-border"><td className="py-2.5 px-3 font-mono text-foreground">POST</td><td className="py-2.5 px-3 font-mono text-xs">/api/integrations/organizations/:orgId/custom-integrations</td><td className="py-2.5 px-3">Create (returns secret)</td></tr>
              <tr className="border-b border-border"><td className="py-2.5 px-3 font-mono text-foreground">PUT</td><td className="py-2.5 px-3 font-mono text-xs">/api/integrations/organizations/:orgId/custom-integrations/:id</td><td className="py-2.5 px-3">Update or regenerate secret</td></tr>
              <tr><td className="py-2.5 px-3 font-mono text-foreground">DELETE</td><td className="py-2.5 px-3 font-mono text-xs">/api/integrations/organizations/:orgId/connections/:id</td><td className="py-2.5 px-3">Remove</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

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
  const isIntegrations = section === "integrations";

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
      ) : isIntegrations ? (
        <IntegrationsContent />
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

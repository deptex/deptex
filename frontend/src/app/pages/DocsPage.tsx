import { useState } from "react";
import { Link } from "react-router-dom";
import { Github, GitBranch, Slack, Mail, Webhook, FileCode, Code, BookOpen, Settings, MessageCircle } from "lucide-react";
import { Button } from "../../components/ui/button";

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
  "notification-rules": {
    title: "Notification Rules",
    description: "Configure automated alerts that trigger when specific events occur across your projects and dependencies.",
  },
  api: {
    title: "API Reference",
    description: "REST API documentation and endpoints for integrating with Deptex.",
  },
  learn: {
    title: "Learn",
    description: "Tutorials, guides, and resources to get the most out of Deptex.",
  },
  help: {
    title: "Help & Support",
    description: "Get help, contact support, and find answers to common questions.",
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

const availableIntegrations = [
  { name: "GitHub", icon: "/images/integrations/github.png", IconFallback: Github, category: "CI/CD", description: "Connect repositories for dependency scanning and security monitoring." },
  { name: "GitLab", icon: "/images/integrations/gitlab.png", IconFallback: GitBranch, category: "CI/CD", description: "Integrate with GitLab repos and CI/CD pipelines." },
  { name: "Bitbucket", icon: "/images/integrations/bitbucket.png", IconFallback: GitBranch, category: "CI/CD", description: "Connect Bitbucket repositories for scanning." },
  { name: "Slack", icon: "/images/integrations/slack.png", IconFallback: Slack, category: "Notifications", description: "Real-time security alerts and vulnerability notifications." },
  { name: "Discord", icon: "/images/integrations/discord.png", IconFallback: Slack, category: "Notifications", description: "Send alerts to Discord channels." },
  { name: "Email", icon: null, IconFallback: Mail, category: "Notifications", description: "Email notifications for critical vulnerabilities." },
  { name: "Jira", icon: "/images/integrations/jira.png", IconFallback: FileCode, category: "Ticketing", description: "Create tickets for security issues." },
  { name: "Linear", icon: "/images/integrations/linear.png", IconFallback: Code, category: "Ticketing", description: "Sync issues with Linear." },
  { name: "Asana", icon: "/images/integrations/asana.png", IconFallback: FileCode, category: "Ticketing", description: "Track remediation in Asana." },
  { name: "Custom Webhook", icon: null, IconFallback: Webhook, category: "Custom", description: "Receive events at any URL with HMAC signing." },
];

function IntegrationIcon({ icon, IconFallback, name }: { icon: string | null; IconFallback: React.ComponentType<{ className?: string }>; name: string }) {
  const [imgError, setImgError] = useState(false);
  if (icon && !imgError) {
    return (
      <img src={icon} alt={name} className="h-5 w-5 rounded-sm flex-shrink-0 object-contain" onError={() => setImgError(true)} />
    );
  }
  return <IconFallback className="h-5 w-5 text-foreground-secondary flex-shrink-0" aria-hidden />;
}

function IntegrationsContent() {
  return (
    <div className="space-y-12">
      {/* Available Integrations Table */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Available Integrations</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Deptex connects with your existing tools.
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full table-fixed">
            <colgroup>
              <col className="w-[200px]" />
              <col className="w-[120px]" />
              <col />
            </colgroup>
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Integration</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Category</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {availableIntegrations.map((int) => (
                <tr key={int.name} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <IntegrationIcon icon={int.icon} IconFallback={int.IconFallback} name={int.name} />
                      <span className="text-sm font-medium text-foreground">{int.name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-foreground-secondary bg-background-subtle px-2 py-1 rounded">{int.category}</span>
                  </td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{int.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Custom Webhooks Section */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Custom Webhooks</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Add <strong className="text-foreground">Custom Webhook Integrations</strong> — a bring-your-own-endpoint approach that lets you receive events at any URL without writing a full integration. From Settings → Integrations, click &quot;Add Custom&quot; in the Notifications or Ticketing section.
          </p>
          <p className="text-foreground-secondary leading-relaxed">
            Enter a name, webhook URL (must start with <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">https://</code>),
            and optionally upload an icon. On creation, you receive a signing secret — copy it immediately; it&apos;s only shown once. When events fire, Deptex sends HTTP POST requests signed with HMAC-SHA256.
          </p>
        </div>
      </div>

      {/* Request Format */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Request Format</h2>
        <p className="text-foreground-secondary leading-relaxed mb-3">Each webhook request includes:</p>
        <div className="rounded-lg border border-border bg-background-card p-4 font-mono text-sm overflow-x-auto">
          <div className="text-foreground-secondary">Headers:</div>
          <div><span className="text-foreground-muted">X-Deptex-Signature:</span> <span className="text-foreground">sha256=&lt;hmac_hex&gt;</span></div>
          <div><span className="text-foreground-muted">X-Deptex-Event:</span> <span className="text-foreground">&lt;event_type&gt;</span></div>
          <div><span className="text-foreground-muted">Content-Type:</span> <span className="text-foreground">application/json</span></div>
          <div className="mt-3 text-foreground-secondary">Body: JSON (see Payload format below)</div>
        </div>
      </div>

      {/* Payload Format */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Payload Format</h2>
        <p className="text-foreground-secondary leading-relaxed mb-3">The request body is JSON with this structure:</p>
        <pre className="rounded-lg border border-border bg-background-card p-4 text-sm text-foreground overflow-x-auto font-mono">
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

      {/* Event Types Table */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Event Types</h2>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Event</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">vulnerability.found</td><td className="px-4 py-3 text-foreground-secondary">A new vulnerability was detected</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">vulnerability.resolved</td><td className="px-4 py-3 text-foreground-secondary">A vulnerability was resolved</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">aegis.activity</td><td className="px-4 py-3 text-foreground-secondary">AI agent action or recommendation</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">administrative.member_added</td><td className="px-4 py-3 text-foreground-secondary">A member was added to the org</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">administrative.settings_changed</td><td className="px-4 py-3 text-foreground-secondary">Organization settings were modified</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Verifying Signatures */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Verifying Signatures</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Use the signing secret to verify that requests came from Deptex. Compute HMAC-SHA256 of the raw request body
          and compare with the <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">X-Deptex-Signature</code> header (format: <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">sha256=&lt;hex&gt;</code>).
        </p>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Python</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`import hmac
import hashlib

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = 'sha256=' + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)`}
            </pre>
          </div>
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Node.js</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
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

    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Policies Documentation                                            */
/* ------------------------------------------------------------------ */

const policyFunctions = [
  {
    name: "pullRequestCheck(context)",
    trigger: "PR / merge request that changes dependencies",
    returns: "{ passed: boolean, violations: string[] }",
    description: "Evaluated when a pull request adds, updates, or removes dependencies. Block the merge by returning passed: false with a list of violation messages.",
  },
  {
    name: "projectCompliance(context)",
    trigger: "Periodic scan or on-demand compliance check",
    returns: "{ compliant: boolean, violations: string[] }",
    description: "Evaluated against all current dependencies in a project. Drives the compliance badge and the Compliance tab violations list.",
  },
];

const projectFields = [
  { field: "name", type: "string", description: "Project name." },
  { field: "asset_tier", type: "AssetTier", description: '"CROWN_JEWELS" | "EXTERNAL" | "INTERNAL" | "NON_PRODUCTION" — the project\'s criticality tier.' },
];

const dependencyFields = [
  { field: "name", type: "string", description: "Package name (e.g. \"lodash\")." },
  { field: "version", type: "string", description: "Installed version string." },
  { field: "license", type: "string", description: "SPDX license identifier (e.g. \"MIT\")." },
  { field: "is_direct", type: "boolean", description: "true for direct dependencies, false for transitive." },
  { field: "environment", type: "string", description: "\"production\", \"development\", etc." },
  { field: "score", type: "number", description: "Deptex reputation score (0 \u2013 100)." },
  { field: "openssf_score", type: "number", description: "OpenSSF Scorecard score (0.0 \u2013 10.0)." },
  { field: "weekly_downloads", type: "number", description: "npm weekly download count." },
  { field: "last_published_at", type: "string", description: "ISO 8601 date of last publish." },
  { field: "releases_last_12_months", type: "number", description: "Number of releases in the past 12 months." },
  { field: "files_importing_count", type: "number", description: "How many files in the project import this package." },
  { field: "registry_integrity_status", type: "AnalysisStatus", description: "Registry integrity check: \"pass\" | \"warning\" | \"fail\"." },
  { field: "install_scripts_status", type: "AnalysisStatus", description: "Pre/post-install script check: \"pass\" | \"warning\" | \"fail\"." },
  { field: "entropy_analysis_status", type: "AnalysisStatus", description: "Obfuscation / entropy analysis: \"pass\" | \"warning\" | \"fail\"." },
  { field: "vulnerabilities", type: "Vulnerability[]", description: "Known vulnerabilities affecting this dependency version." },
];

const vulnFields = [
  { field: "osv_id", type: "string", description: "OSV identifier (e.g. \"GHSA-xxxx-xxxx-xxxx\")." },
  { field: "severity", type: "string", description: "\"critical\" | \"high\" | \"medium\" | \"low\"." },
  { field: "cvss_score", type: "number", description: "CVSS v3 base score (0.0 \u2013 10.0)." },
  { field: "epss_score", type: "number", description: "EPSS exploit prediction score (0.0 \u2013 1.0). Higher means more likely to be exploited." },
  { field: "depscore", type: "number", description: "Composite risk score (0 \u2013 100) combining CVSS, EPSS, CISA KEV, reachability, and asset tier." },
  { field: "is_reachable", type: "boolean", description: "Whether the vulnerable code path is reachable from the project." },
  { field: "cisa_kev", type: "boolean", description: "true if this CVE is in CISA's Known Exploited Vulnerabilities catalog." },
  { field: "fixed_versions", type: "string[]", description: "Versions that fix this vulnerability. Empty if no fix exists." },
  { field: "aliases", type: "string[]", description: "CVE IDs and other advisory aliases." },
  { field: "summary", type: "string", description: "Human-readable vulnerability summary." },
  { field: "published_at", type: "string", description: "ISO 8601 date when the advisory was published." },
];

const prContextFields = [
  { field: "project", type: "Project", description: "The project being checked." },
  { field: "added", type: "Dependency[]", description: "Dependencies newly added in this PR." },
  { field: "updated", type: "UpdatedDependency[]", description: "Dependencies whose version changed. Includes from_version and to_version." },
  { field: "removed", type: "RemovedDependency[]", description: "Dependencies removed in this PR (name and version only)." },
];

const complianceContextFields = [
  { field: "project", type: "Project", description: "The project being evaluated." },
  { field: "dependencies", type: "Dependency[]", description: "All dependencies currently in the project." },
];

function FieldTable({ fields, caption }: { fields: { field: string; type: string; description: string }[]; caption?: string }) {
  return (
    <div className="rounded-lg border border-border bg-background-card overflow-hidden">
      {caption && (
        <div className="px-4 py-2 bg-background-card-header border-b border-border">
          <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">{caption}</span>
        </div>
      )}
      <table className="w-full text-sm">
        <thead className={caption ? "border-b border-border" : "bg-background-card-header border-b border-border"}>
          <tr>
            <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[180px]">Field</th>
            <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[140px]">Type</th>
            <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {fields.map((f) => (
            <tr key={f.field} className="hover:bg-table-hover transition-colors">
              <td className="px-4 py-2.5 font-mono text-xs text-foreground">{f.field}</td>
              <td className="px-4 py-2.5 font-mono text-xs text-foreground-secondary">{f.type}</td>
              <td className="px-4 py-2.5 text-sm text-foreground-secondary">{f.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PoliciesContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex <strong className="text-foreground">Policy-as-Code</strong> lets you define organization-wide rules as JavaScript functions.
            Your policy code is evaluated against real dependency and vulnerability data whenever a pull request changes dependencies or during periodic compliance scans.
          </p>
          <p>
            Define two functions in the editor &mdash; <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pullRequestCheck(context)</code> to
            gate merges and <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">projectCompliance(context)</code> to
            evaluate ongoing compliance. Both receive a rich context object with all the data Deptex knows about the project&rsquo;s dependencies.
          </p>
        </div>
      </div>

      {/* Policy Functions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Policy Functions</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Your policy code should export these two functions. Both are optional &mdash; define whichever you need.
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Function</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Trigger</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Returns</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {policyFunctions.map((fn) => (
                <tr key={fn.name} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-foreground">{fn.name}</td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{fn.trigger}</td>
                  <td className="px-4 py-3 font-mono text-xs text-foreground-secondary">{fn.returns}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4 space-y-3">
          {policyFunctions.map((fn) => (
            <div key={fn.name} className="rounded-lg border border-border bg-background-card p-4">
              <p className="text-sm font-medium text-foreground mb-1">
                <code className="font-mono text-xs">{fn.name}</code>
              </p>
              <p className="text-sm text-foreground-secondary">{fn.description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Context API — pullRequestCheck */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Context API Reference</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Each policy function receives a <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context</code> object.
          The shape depends on which function is being called.
        </p>

        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">pullRequestCheck &mdash; Context Fields</h3>
            <FieldTable fields={prContextFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">projectCompliance &mdash; Context Fields</h3>
            <FieldTable fields={complianceContextFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">Project</h3>
            <FieldTable fields={projectFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">Dependency</h3>
            <FieldTable fields={dependencyFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">Vulnerability</h3>
            <FieldTable fields={vulnFields} />
          </div>
        </div>
      </div>

      {/* Key Data Explained */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Key Data Fields Explained</h2>
        </div>
        <div className="p-6 space-y-5">
          <div>
            <p className="text-sm font-medium text-foreground mb-1">depscore <span className="text-foreground-secondary font-normal">(0 &ndash; 100)</span></p>
            <p className="text-sm text-foreground-secondary leading-relaxed">
              A composite vulnerability risk score that combines CVSS severity, EPSS exploit probability, CISA KEV status, code reachability, and the project&rsquo;s asset tier.
              Higher is riskier. Formula: <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">baseImpact &times; threatMultiplier &times; environmentalMultiplier</code>.
            </p>
          </div>
          <div>
            <p className="text-sm font-medium text-foreground mb-1">openssf_score <span className="text-foreground-secondary font-normal">(0.0 &ndash; 10.0)</span></p>
            <p className="text-sm text-foreground-secondary leading-relaxed">
              The OpenSSF Scorecard score evaluates open-source project health: CI tests, code review, branch protection, signed releases, etc. Higher is better.
            </p>
          </div>
          <div>
            <p className="text-sm font-medium text-foreground mb-1">epss_score <span className="text-foreground-secondary font-normal">(0.0 &ndash; 1.0)</span></p>
            <p className="text-sm text-foreground-secondary leading-relaxed">
              The Exploit Prediction Scoring System (EPSS) estimates the probability that a vulnerability will be exploited in the wild within the next 30 days. A score of 0.5 means 50% probability.
            </p>
          </div>
          <div>
            <p className="text-sm font-medium text-foreground mb-1">is_reachable</p>
            <p className="text-sm text-foreground-secondary leading-relaxed">
              Deptex performs static analysis to determine whether the vulnerable code path is actually reachable from your project&rsquo;s source code.
              Unreachable vulnerabilities are still tracked but carry significantly lower risk.
            </p>
          </div>
          <div>
            <p className="text-sm font-medium text-foreground mb-1">Supply Chain Signals</p>
            <p className="text-sm text-foreground-secondary leading-relaxed">
              <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">registry_integrity_status</code>,{" "}
              <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">install_scripts_status</code>, and{" "}
              <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">entropy_analysis_status</code> are
              each <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">&quot;pass&quot;</code> | <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">&quot;warning&quot;</code> | <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">&quot;fail&quot;</code>.
              They detect tampered registry packages, suspicious install scripts, and obfuscated code respectively.
            </p>
          </div>
        </div>
      </div>

      {/* Example Policies */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Example Policies</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Copy and adapt these examples in Settings &rarr; Policies. You can combine multiple checks in a single function.
        </p>

        <div className="space-y-6">
          {/* Example 1: License */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">License Allowlist / Blocklist</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`const BANNED = ["AGPL-3.0", "GPL-3.0"];
const ALLOWED = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"];

function pullRequestCheck(context) {
  const violations = [];
  for (const pkg of [...context.added, ...context.updated]) {
    const lic = pkg.license || "UNKNOWN";
    if (BANNED.some(b => lic.includes(b))) {
      violations.push(\`Banned license \${lic} on \${pkg.name}\`);
    } else if (ALLOWED.length && !ALLOWED.some(a => lic.includes(a)) && lic !== "UNKNOWN") {
      violations.push(\`License \${lic} not in allowlist (\${pkg.name})\`);
    }
  }
  return { passed: violations.length === 0, violations };
}`}
            </pre>
          </div>

          {/* Example 2: Critical reachable vulns */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Block Critical Reachable Vulnerabilities</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`function pullRequestCheck(context) {
  const violations = [];
  for (const pkg of [...context.added, ...context.updated]) {
    for (const v of pkg.vulnerabilities) {
      if (v.severity === "critical" && v.is_reachable) {
        violations.push(\`\${v.osv_id} (depscore \${v.depscore}) in \${pkg.name}@\${pkg.version}\`);
      }
      if (v.cisa_kev) {
        violations.push(\`CISA KEV: \${v.osv_id} in \${pkg.name}@\${pkg.version}\`);
      }
    }
  }
  return { passed: violations.length === 0, violations };
}`}
            </pre>
          </div>

          {/* Example 3: OpenSSF score */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Require Minimum OpenSSF Score for Production</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`function pullRequestCheck(context) {
  const violations = [];
  for (const pkg of context.added) {
    if (pkg.is_direct && pkg.environment === "production" && pkg.openssf_score < 3) {
      violations.push(
        \`\${pkg.name} has OpenSSF score \${pkg.openssf_score} (min 3 for direct prod deps)\`
      );
    }
  }
  return { passed: violations.length === 0, violations };
}`}
            </pre>
          </div>

          {/* Example 4: Supply chain */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Supply Chain Integrity Checks</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`function pullRequestCheck(context) {
  const violations = [];
  for (const pkg of [...context.added, ...context.updated]) {
    if (pkg.registry_integrity_status === "fail") {
      violations.push(\`Registry integrity failure: \${pkg.name}@\${pkg.version}\`);
    }
    if (pkg.install_scripts_status === "fail") {
      violations.push(\`Suspicious install scripts: \${pkg.name}@\${pkg.version}\`);
    }
    if (pkg.entropy_analysis_status === "fail") {
      violations.push(\`High entropy (obfuscation): \${pkg.name}@\${pkg.version}\`);
    }
  }
  return { passed: violations.length === 0, violations };
}`}
            </pre>
          </div>
        </div>
      </div>

      {/* Exception Applications */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Exception Applications</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Projects can request <strong className="text-foreground">policy exceptions</strong> when their specific use case requires deviating from the organization policy.
            Exception requests create a diff view showing the proposed policy changes for that project.
          </p>
          <div>
            <p className="text-sm font-medium text-foreground mb-2">Workflow</p>
            <ol className="list-decimal list-inside space-y-1.5 text-sm text-foreground-secondary">
              <li>A project member opens the project&rsquo;s policy settings and submits an exception request with a reason and modified policy code.</li>
              <li>Organization admins (users with <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_compliance</code> permission) see the request in Settings &rarr; Policies &rarr; Exception applications.</li>
              <li>Reviewers see a side-by-side diff of the base policy vs. the requested changes and can <strong className="text-foreground">Accept</strong> or <strong className="text-foreground">Reject</strong>.</li>
              <li>Accepted exceptions override the organization policy for that specific project only.</li>
            </ol>
          </div>
        </div>
      </div>

      {/* API Endpoints */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">API Endpoints</h2>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-20">Method</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Endpoint</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-foreground">GET</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/policies</td>
                <td className="px-4 py-3 text-foreground-secondary">Get organization policy code</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-foreground">PUT</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/policies</td>
                <td className="px-4 py-3 text-foreground-secondary">Update organization policy code</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-foreground">GET</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/policy-exceptions</td>
                <td className="px-4 py-3 text-foreground-secondary">List all exception applications</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-foreground">POST</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/projects/:projectId/policy-exceptions</td>
                <td className="px-4 py-3 text-foreground-secondary">Submit exception request for a project</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-foreground">PUT</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/policy-exceptions/:exceptionId</td>
                <td className="px-4 py-3 text-foreground-secondary">Accept or reject an exception</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Notification Rules Documentation                                   */
/* ------------------------------------------------------------------ */

const notificationTriggerEvents = [
  { event: "vulnerability_discovered", description: "A new vulnerability (CVE / advisory) was found affecting a dependency in a project." },
  { event: "dependency_added", description: "A new dependency was added to a project." },
  { event: "dependency_updated", description: "An existing dependency's version was changed." },
  { event: "dependency_removed", description: "A dependency was removed from a project." },
  { event: "compliance_violation", description: "A project's compliance check transitioned from compliant to non-compliant." },
  { event: "risk_score_changed", description: "A project's health score changed significantly (crossed a threshold)." },
  { event: "license_violation", description: "A dependency with a banned or unapproved license was detected." },
  { event: "supply_chain_anomaly", description: "Suspicious commit activity or behavioral anomaly was detected in a dependency." },
  { event: "new_version_available", description: "A newer version of a tracked dependency was published to the registry." },
  { event: "security_analysis_failure", description: "Registry integrity, install scripts, or entropy analysis returned a 'fail' status." },
];

const notifContextEventFields = [
  { field: "type", type: "string", description: "The event that triggered the evaluation. One of the trigger event types listed above." },
];

const notifContextProjectFields = [
  { field: "name", type: "string", description: "Project name." },
  { field: "asset_tier", type: "string", description: '"CROWN_JEWELS" | "EXTERNAL" | "INTERNAL" | "NON_PRODUCTION" — the project\'s criticality tier.' },
  { field: "health_score", type: "number", description: "Project health score (0 – 100). Lower means more risk." },
  { field: "is_compliant", type: "boolean", description: "Whether the project currently passes all compliance policies." },
  { field: "dependencies_count", type: "number", description: "Total number of dependencies in the project." },
];

const notifContextDependencyFields = [
  { field: "name", type: "string", description: "Package name (e.g. \"lodash\")." },
  { field: "version", type: "string", description: "Installed version string." },
  { field: "license", type: "string", description: "SPDX license identifier (e.g. \"MIT\")." },
  { field: "is_direct", type: "boolean", description: "true for direct dependencies, false for transitive." },
  { field: "environment", type: "string", description: '"production" or "development".' },
  { field: "score", type: "number", description: "Deptex reputation score (0 – 100)." },
  { field: "openssf_score", type: "number", description: "OpenSSF Scorecard score (0.0 – 10.0)." },
  { field: "weekly_downloads", type: "number", description: "npm weekly download count." },
  { field: "registry_integrity_status", type: "string", description: '"pass" | "warning" | "fail" — registry integrity check.' },
  { field: "install_scripts_status", type: "string", description: '"pass" | "warning" | "fail" — pre/post-install script check.' },
  { field: "entropy_analysis_status", type: "string", description: '"pass" | "warning" | "fail" — obfuscation / entropy analysis.' },
  { field: "vulnerabilities", type: "array", description: "Known vulnerabilities affecting this dependency version (see Vulnerability below)." },
];

const notifContextVulnFields = [
  { field: "osv_id", type: "string", description: 'OSV identifier (e.g. "GHSA-xxxx-xxxx-xxxx").' },
  { field: "severity", type: "string", description: '"critical" | "high" | "medium" | "low".' },
  { field: "cvss_score", type: "number", description: "CVSS v3 base score (0.0 – 10.0)." },
  { field: "epss_score", type: "number", description: "EPSS exploit prediction score (0.0 – 1.0)." },
  { field: "depscore", type: "number", description: "Composite risk score (0 – 100)." },
  { field: "is_reachable", type: "boolean", description: "Whether the vulnerable code path is reachable from the project." },
  { field: "cisa_kev", type: "boolean", description: "true if in CISA's Known Exploited Vulnerabilities catalog." },
  { field: "fixed_versions", type: "string[]", description: "Versions that fix this vulnerability." },
  { field: "summary", type: "string", description: "Human-readable vulnerability summary." },
];

const notifContextPreviousFields = [
  { field: "health_score", type: "number | undefined", description: "Previous health score (only set for risk_score_changed events)." },
  { field: "is_compliant", type: "boolean | undefined", description: "Previous compliance status (only set for compliance_violation events)." },
];

function NotificationRulesContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            <strong className="text-foreground">Notification Rules</strong> let you define automated alerts that fire when specific events occur across your projects and dependencies.
            Each rule consists of a <strong className="text-foreground">trigger function</strong> written in JavaScript and one or more <strong className="text-foreground">destinations</strong> (Slack, Discord, Jira, Linear, Asana, email, or custom webhooks).
          </p>
          <p>
            When an event occurs (e.g. a new vulnerability is discovered), Deptex evaluates your trigger function with a rich context object. If the function returns{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">true</code>, the notification is sent to all configured destinations. Return{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">false</code> to skip.
          </p>
          <p>
            Use the <strong className="text-foreground">AI assistant</strong> in the rule editor to describe what you want in plain English &mdash; it will generate the trigger code for you.
          </p>
        </div>
      </div>

      {/* Trigger Events */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Trigger Events</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          These are the events that can trigger a notification rule. Your trigger function receives the event type in{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context.event.type</code> and can filter on it.
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[240px]">Event</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {notificationTriggerEvents.map((e) => (
                <tr key={e.event} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-foreground">{e.event}</td>
                  <td className="px-4 py-3 text-foreground-secondary">{e.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Context Object Reference */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Context Object Reference</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Your trigger function receives a <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context</code> object with the following shape.
          Fields that are not applicable to the current event type will be <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">null</code>.
        </p>

        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">context.event</h3>
            <FieldTable fields={notifContextEventFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">context.project</h3>
            <FieldTable fields={notifContextProjectFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">context.dependency <span className="font-normal text-foreground-secondary">(nullable)</span></h3>
            <p className="text-sm text-foreground-secondary mb-2">
              The dependency related to the event. Present for dependency_added, dependency_updated, dependency_removed, vulnerability_discovered, license_violation, new_version_available, and security_analysis_failure events.
            </p>
            <FieldTable fields={notifContextDependencyFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">context.vulnerability <span className="font-normal text-foreground-secondary">(nullable)</span></h3>
            <p className="text-sm text-foreground-secondary mb-2">
              The specific vulnerability that triggered the event. Present only for vulnerability_discovered events.
            </p>
            <FieldTable fields={notifContextVulnFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">context.previous <span className="font-normal text-foreground-secondary">(nullable)</span></h3>
            <p className="text-sm text-foreground-secondary mb-2">
              Previous state values for comparison. Only present for change-type events (risk_score_changed, compliance_violation).
            </p>
            <FieldTable fields={notifContextPreviousFields} />
          </div>
        </div>
      </div>

      {/* Example Trigger Functions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Example Trigger Functions</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Copy and adapt these examples when creating notification rules. Each function receives{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context</code> and must return{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">true</code> (send notification) or{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">false</code> (skip).
        </p>

        <div className="space-y-6">
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">High Depscore Vulnerability Alert</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`// Alert when a vulnerability with depscore above 75 is discovered
if (context.event.type !== 'vulnerability_discovered') return false;
if (!context.vulnerability) return false;

return context.vulnerability.depscore > 75;`}
            </pre>
          </div>

          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Critical Reachable Vulnerabilities Only</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`// Only notify for critical severity vulnerabilities that are reachable
if (context.event.type !== 'vulnerability_discovered') return false;
if (!context.vulnerability) return false;

return context.vulnerability.severity === 'critical'
    && context.vulnerability.is_reachable;`}
            </pre>
          </div>

          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">New Dependencies with Low OpenSSF Score</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`// Alert when a newly added direct dependency has a low OpenSSF score
if (context.event.type !== 'dependency_added') return false;
if (!context.dependency) return false;

return context.dependency.is_direct
    && context.dependency.openssf_score < 3;`}
            </pre>
          </div>

          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Supply Chain Security Failures</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`// Notify on any supply chain analysis failure (suspicious packages)
if (!context.dependency) return false;

const types = ['dependency_added', 'dependency_updated', 'security_analysis_failure'];
if (!types.includes(context.event.type)) return false;

return context.dependency.registry_integrity_status === 'fail'
    || context.dependency.install_scripts_status === 'fail'
    || context.dependency.entropy_analysis_status === 'fail';`}
            </pre>
          </div>

          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Crown Jewel Projects &mdash; Any Vulnerability</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`// Alert on any vulnerability in CROWN_JEWELS projects
if (context.event.type !== 'vulnerability_discovered') return false;

return context.project.asset_tier === 'CROWN_JEWELS';`}
            </pre>
          </div>

          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">License Violation Alert</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`// Notify when a dependency with a banned license is detected
if (context.event.type !== 'license_violation') return false;
if (!context.dependency) return false;

const BANNED = ['AGPL-3.0', 'GPL-3.0', 'SSPL-1.0'];
return BANNED.some(b => (context.dependency.license || '').includes(b));`}
            </pre>
          </div>
        </div>
      </div>

      {/* Destinations */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Destinations</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Each notification rule can send alerts to one or more destinations. Destinations are configured through your organization&apos;s connected integrations in{" "}
          <strong className="text-foreground">Settings &rarr; Integrations</strong>.
        </p>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[
            { name: "Slack", icon: Slack, desc: "Posts a formatted message to the configured channel." },
            { name: "Discord", icon: MessageCircle, desc: "Sends a rich embed to the configured Discord channel." },
            { name: "Email", icon: Mail, desc: "Sends an email notification to the configured address." },
            { name: "Jira", icon: FileCode, desc: "Creates a Jira issue in the configured project." },
            { name: "Linear", icon: Code, desc: "Creates a Linear issue in the configured team." },
            { name: "Asana", icon: FileCode, desc: "Creates an Asana task in the configured project." },
            { name: "Custom Webhook", icon: Webhook, desc: "Sends a signed HTTP POST to your custom webhook endpoint." },
          ].map(({ name, icon: Icon, desc }) => (
            <div
              key={name}
              className="rounded-lg border border-border bg-background-card p-4 hover:border-foreground-secondary/30 transition-colors"
            >
              <div className="flex items-center gap-3 mb-2">
                <div className="h-9 w-9 rounded-lg bg-background-subtle flex items-center justify-center">
                  <Icon className="h-4 w-4 text-foreground-secondary" />
                </div>
                <span className="font-medium text-foreground text-sm">{name}</span>
              </div>
              <p className="text-xs text-foreground-secondary leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* API Endpoints */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">API Endpoints</h2>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-24">Method</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Endpoint</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground">GET</td><td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/notification-rules</td><td className="px-4 py-3 text-foreground-secondary">List all notification rules</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground">POST</td><td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/notification-rules</td><td className="px-4 py-3 text-foreground-secondary">Create a notification rule</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground">PUT</td><td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/notification-rules/:ruleId</td><td className="px-4 py-3 text-foreground-secondary">Update a notification rule</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground">DELETE</td><td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/notification-rules/:ruleId</td><td className="px-4 py-3 text-foreground-secondary">Delete a notification rule</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

const helpDocLinks = [
  { label: "Quick Start", slug: "quick-start", description: "Get up and running in minutes." },
  { label: "Introduction", slug: "introduction", description: "Overview of Deptex and its capabilities." },
  { label: "Policies", slug: "policies", description: "Define and enforce security and compliance policies." },
  { label: "Integrations", slug: "integrations", description: "Connect GitHub, Slack, CI/CD, and more." },
  { label: "Notification Rules", slug: "notification-rules", description: "Configure automated alerts." },
  { label: "Organizations", slug: "organizations", description: "Manage your organization and settings." },
  { label: "Terms of Service", slug: "terms", description: "Terms governing your use of Deptex." },
  { label: "Privacy Policy", slug: "privacy", description: "How we collect, use, and protect your data." },
  { label: "Security", slug: "security", description: "Our security practices and commitment." },
];

function TermsContent() {
  return (
    <div className="space-y-8">
      <p className="text-foreground-secondary leading-relaxed">
        These Terms of Service govern your use of Deptex. By using our platform, you agree to these terms.
      </p>
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Acceptance of Terms</h2>
        <p className="text-foreground-secondary leading-relaxed">
          By accessing or using Deptex, you agree to be bound by these Terms. If you do not agree, please do not use our services.
        </p>
      </div>
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Use of the Service</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Deptex provides dependency tracking, vulnerability monitoring, and compliance tools for software development teams. You agree to use the service in compliance with applicable laws and not to misuse or abuse the platform.
        </p>
      </div>
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Contact</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Questions about these terms? Reach out at{" "}
          <a href="mailto:deptex.app@gmail.com" className="text-primary hover:underline">deptex.app@gmail.com</a>.
        </p>
      </div>
    </div>
  );
}

function PrivacyContent() {
  return (
    <div className="space-y-8">
      <p className="text-foreground-secondary leading-relaxed">
        We take your privacy seriously. This policy describes how Deptex collects, uses, and protects your information.
      </p>
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Information We Collect</h2>
        <p className="text-foreground-secondary leading-relaxed">
          We collect information you provide (e.g., account details, organization data) and usage data necessary to operate the service, including repository metadata and dependency information from your connected projects.
        </p>
      </div>
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">How We Use It</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Your data is used to deliver Deptex features: dependency scanning, vulnerability alerts, compliance reporting, and integrations you configure. We do not sell your personal information.
        </p>
      </div>
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Data Security</h2>
        <p className="text-foreground-secondary leading-relaxed">
          We use industry-standard practices to protect your data. For more details, see our{" "}
          <Link to="/docs/security" className="text-primary hover:underline">Security</Link> page.
        </p>
      </div>
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Contact</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Privacy questions? Email us at{" "}
          <a href="mailto:deptex.app@gmail.com" className="text-primary hover:underline">deptex.app@gmail.com</a>.
        </p>
      </div>
    </div>
  );
}

function SecurityContent() {
  return (
    <div className="space-y-8">
      <p className="text-foreground-secondary leading-relaxed">
        Security is at the core of Deptex. We help you secure your dependency supply chain and take our own security practices seriously.
      </p>
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">What We Protect</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Deptex safeguards your account data, organization settings, and the dependency and vulnerability information we process. We use encryption in transit and at rest, and follow secure development practices.
        </p>
      </div>
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Access Control</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Organizations can define roles, permissions, and team-scoped access. SSO and MFA (on Pro+) add extra layers for enterprise customers.
        </p>
      </div>
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Compliance & Transparency</h2>
        <p className="text-foreground-secondary leading-relaxed">
          We are working toward SOC2 and other compliance certifications. For security questionnaires or specific documentation requests, contact us at{" "}
          <a href="mailto:deptex.app@gmail.com" className="text-primary hover:underline">deptex.app@gmail.com</a>.
        </p>
      </div>
    </div>
  );
}

function HelpContent() {
  return (
    <div className="space-y-12">
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Find what you need</h2>
        <p className="text-foreground-secondary leading-relaxed mb-6">
          Start with our documentation to learn how Deptex works. These guides cover the most common tasks and questions.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          {helpDocLinks.map((item) => (
            <Link
              key={item.slug}
              to={`/docs/${item.slug}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex gap-3 rounded-lg border border-border bg-background-card p-4 hover:bg-table-hover hover:border-foreground-secondary/30 transition-colors text-left group"
            >
              <BookOpen className="h-5 w-5 text-foreground-secondary shrink-0 mt-0.5 group-hover:text-foreground transition-colors" />
              <div>
                <p className="text-sm font-medium text-foreground group-hover:text-primary transition-colors">{item.label}</p>
                <p className="text-xs text-foreground-secondary mt-0.5">{item.description}</p>
              </div>
            </Link>
          ))}
        </div>
      </div>

      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header flex items-center gap-2">
          <Settings className="h-4 w-4 text-foreground-secondary" />
          <h2 className="text-lg font-semibold text-foreground">Still need help?</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Can&apos;t find what you&apos;re looking for? Reach out to our support team and we&apos;ll get back to you as soon as possible.
          </p>
          <Button
            size="lg"
            className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40"
            onClick={() => { window.location.href = "mailto:deptex.app@gmail.com?subject=Support Request"; }}
          >
            <Mail className="h-5 w-5" />
            Contact Support
          </Button>
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

  const renderContent = () => {
    switch (section) {
      case "introduction":
        return <IntroductionContent />;
      case "integrations":
        return <IntegrationsContent />;
      case "policies":
        return <PoliciesContent />;
      case "notification-rules":
        return <NotificationRulesContent />;
      case "help":
        return <HelpContent />;
      case "terms":
        return <TermsContent />;
      case "privacy":
        return <PrivacyContent />;
      case "security":
        return <SecurityContent />;
      default:
        return (
          <div className="rounded-lg border border-border bg-background-card p-6">
            <p className="text-sm text-foreground-secondary">
              This page is coming soon. Check back later for full documentation.
            </p>
          </div>
        );
    }
  };

  return (
    <article>
      <div className="mb-8 pb-8 border-b border-border">
        <p className="text-xs font-semibold uppercase tracking-wider text-foreground-muted mb-3">
          Documentation
        </p>
        <h1 className="text-3xl font-semibold text-foreground mb-3">{meta.title}</h1>
        <p className="text-base text-foreground-secondary leading-relaxed">{meta.description}</p>
      </div>

      {renderContent()}
    </article>
  );
}

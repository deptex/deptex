import { useState } from "react";
import { Link } from "react-router-dom";
import { Github, GitBranch, Slack, Mail, Webhook, FileCode, Code, Settings, MessageCircle } from "lucide-react";
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

      {/* Pull Request Checks */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Pull Request Checks</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            When a pull request (GitHub) or merge request (GitLab/Bitbucket) changes dependencies, Deptex runs your{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pullRequestCheck</code> policy function.
            The returned <strong className="text-foreground">status</strong> is mapped to the provider&rsquo;s pass/fail: if the status has{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">is_passing</code> true, the check passes; otherwise it fails.
            The check summary shows the status name and violation list so developers know what to fix.
          </p>
        </div>
      </div>

      {/* GitLab and Bitbucket Webhooks */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">GitLab and Bitbucket Webhooks</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            <strong className="text-foreground">GitLab:</strong> Connect repos via OAuth; Deptex can register webhooks for Push and Merge Request events.
            Push events trigger extraction when the project&rsquo;s sync setting allows it; MR events run PR checks and post status updates and comments.
          </p>
          <p className="text-foreground-secondary leading-relaxed">
            <strong className="text-foreground">Bitbucket:</strong> Similarly, connect via OAuth; webhooks for <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">repo:push</code> and{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pullrequest:*</code> trigger extraction and PR checks. Build statuses and PR comments are posted to the provider.
          </p>
          <p className="text-foreground-secondary leading-relaxed text-sm">
            Extraction on new commits is controlled per project (sync frequency: manual, on commit, daily, or weekly). Incremental extraction runs the full pipeline for the affected repo.
          </p>
        </div>
      </div>

      {/* AI-Powered Fixing */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">AI-Powered Fixing</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Deptex integrates with <strong className="text-foreground">Aider</strong> to generate vulnerability fixes automatically. When you request a fix from the Security tab (or via Aegis), Deptex clones the repository, runs Aider with a strategy tailored to the vulnerability type, validates the fix (install, audit, tests), and creates a pull request in the connected provider.
          </p>
          <p className="text-foreground-secondary leading-relaxed">
            Fixes are always created as draft PRs for human review. Your organization must have an AI provider configured (BYOK) in Settings → AI Configuration; the fix runs on a Fly.io worker with scale-to-zero. The <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">ai_fix_completed</code> event fires when a fix PR is created or the fix fails.
          </p>
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
  "event": "vulnerability_discovered",
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
        <p className="text-foreground-secondary leading-relaxed mb-3 text-sm">
          The <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">X-Deptex-Event</code> header and payload <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">event</code> field use underscore names. Common types:
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Event</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">vulnerability_discovered</td><td className="px-4 py-3 text-foreground-secondary">A new vulnerability was detected</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">vulnerability_resolved</td><td className="px-4 py-3 text-foreground-secondary">A vulnerability was resolved</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">vulnerability_severity_increased</td><td className="px-4 py-3 text-foreground-secondary">EPSS or KEV changed on existing vuln</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">dependency_added</td><td className="px-4 py-3 text-foreground-secondary">A dependency was added to a project</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">dependency_updated</td><td className="px-4 py-3 text-foreground-secondary">A dependency version was changed</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">status_changed</td><td className="px-4 py-3 text-foreground-secondary">Project compliance status changed</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">compliance_violation</td><td className="px-4 py-3 text-foreground-secondary">Project transitioned to non-passing status</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">extraction_completed</td><td className="px-4 py-3 text-foreground-secondary">Extraction pipeline finished successfully</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">extraction_failed</td><td className="px-4 py-3 text-foreground-secondary">Extraction pipeline failed</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">pr_check_completed</td><td className="px-4 py-3 text-foreground-secondary">PR policy check finished (pass or fail)</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">malicious_package_detected</td><td className="px-4 py-3 text-foreground-secondary">Dependency flagged as malicious</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">ai_fix_completed</td><td className="px-4 py-3 text-foreground-secondary">AI fix PR was created or fix failed</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground text-xs">risk_score_changed</td><td className="px-4 py-3 text-foreground-secondary">Project health score crossed a threshold</td></tr>
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
    name: "packagePolicy(context)",
    trigger: "Per-dependency during policy evaluation",
    returns: "{ allowed: boolean, reasons: string[] }",
    description: "Evaluated once per dependency. Return allowed: false to block a package; reasons are shown in the Compliance tab. Stored in organization_package_policies; can be overridden per project.",
  },
  {
    name: "projectStatus(context)",
    trigger: "After extraction or on-demand compliance check",
    returns: "{ status: 'StatusName', violations: string[] }",
    description: "Evaluated against all current dependencies (with policyResult from packagePolicy). Returns one of your org's custom status names. Drives the compliance badge and Compliance tab. Stored in organization_status_codes.",
  },
  {
    name: "pullRequestCheck(context)",
    trigger: "PR / merge request that changes dependencies",
    returns: "{ status: 'StatusName', violations: string[] }",
    description: "Evaluated when a PR adds, updates, or removes dependencies. Return a status name; is_passing maps to provider pass/fail. Stored in organization_pr_checks.",
  },
];

const projectFields = [
  { field: "name", type: "string", description: "Project name." },
  { field: "asset_tier", type: "AssetTier", description: '"CROWN_JEWELS" | "EXTERNAL" | "INTERNAL" | "NON_PRODUCTION" — the project\'s criticality tier.' },
  { field: "status", type: "string", description: "Current custom status name assigned by projectStatus." },
  { field: "status_is_passing", type: "boolean", description: "Whether the current status is marked as passing (used for PR check pass/fail)." },
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
  { field: "malicious_indicator", type: "object | null", description: "If set: { source, confidence, reason } from malicious package detection." },
  { field: "slsa_level", type: "number", description: "SLSA provenance level (0\u20134)." },
  { field: "is_dev_dependency", type: "boolean", description: "true if dev-only (e.g. devDependencies)." },
  { field: "dependency_score", type: "number", description: "Package reputation score (0\u2013100) with SLSA/malicious multipliers applied." },
  { field: "policy_result", type: "{ allowed, reasons }", description: "Result of packagePolicy for this dep (in projectStatus/pullRequestCheck context)." },
];

const vulnFields = [
  { field: "osv_id", type: "string", description: "OSV identifier (e.g. \"GHSA-xxxx-xxxx-xxxx\")." },
  { field: "severity", type: "string", description: "\"critical\" | \"high\" | \"medium\" | \"low\"." },
  { field: "cvss_score", type: "number", description: "CVSS v3 base score (0.0 \u2013 10.0)." },
  { field: "epss_score", type: "number", description: "EPSS exploit prediction score (0.0 \u2013 1.0). Higher means more likely to be exploited." },
  { field: "depscore", type: "number", description: "Composite risk score (0 \u2013 100) combining CVSS, EPSS, CISA KEV, reachability, and asset tier." },
  { field: "is_reachable", type: "boolean", description: "Whether the vulnerable code path is reachable (legacy; prefer reachability_level)." },
  { field: "reachability_level", type: "string | null", description: "\"confirmed\" | \"data_flow\" | \"function\" | \"module\" | \"unreachable\" — code-level reachability tier (Phase 6B)." },
  { field: "reachability_details", type: "object | null", description: "Optional data-flow path details when reachability_level is set." },
  { field: "cisa_kev", type: "boolean", description: "true if this CVE is in CISA's Known Exploited Vulnerabilities catalog." },
  { field: "fixed_versions", type: "string[]", description: "Versions that fix this vulnerability. Empty if no fix exists." },
  { field: "aliases", type: "string[]", description: "CVE IDs and other advisory aliases." },
  { field: "summary", type: "string", description: "Human-readable vulnerability summary." },
  { field: "published_at", type: "string", description: "ISO 8601 date when the advisory was published." },
];

const packagePolicyContextFields = [
  { field: "dependency", type: "Dependency", description: "The single dependency being evaluated." },
  { field: "tier", type: "AssetTier", description: "Project's asset tier (name, rank, multiplier) for context." },
];

const prContextFields = [
  { field: "project", type: "Project", description: "The project being checked." },
  { field: "added", type: "Dependency[]", description: "Dependencies newly added in this PR (each has policyResult)." },
  { field: "updated", type: "UpdatedDependency[]", description: "Dependencies whose version changed. Includes from_version and to_version." },
  { field: "removed", type: "RemovedDependency[]", description: "Dependencies removed in this PR (name and version only)." },
];

const complianceContextFields = [
  { field: "project", type: "Project", description: "The project being evaluated." },
  { field: "dependencies", type: "Dependency[]", description: "All dependencies in the project; each has policyResult from packagePolicy." },
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
            Your policy code is evaluated against real dependency and vulnerability data whenever a pull request changes dependencies or after each extraction.
          </p>
          <p>
            Define up to three functions: <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">packagePolicy(context)</code> to
            allow or block individual packages, <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">projectStatus(context)</code> to
            assign a custom compliance status to the project, and <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pullRequestCheck(context)</code> to
            gate merges. Each is stored in a separate table and can be overridden per project. All receive a rich context object with dependency and vulnerability data.
          </p>
        </div>
      </div>

      {/* Custom Statuses */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Custom Statuses</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Organizations define their own statuses in <strong className="text-foreground">Settings &rarr; Statuses</strong>: name, color, rank, and{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">is_passing</code>. Policy functions return one of these status names
          (e.g. &ldquo;Compliant&rdquo;, &ldquo;Non-Compliant&rdquo;, &ldquo;Review Required&rdquo;). The <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">is_passing</code> flag
          determines whether a status counts as passing for PR checks and aggregate reporting.
        </p>
      </div>

      {/* Policy Functions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Policy Functions</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Your policy code can define any of these three functions. Each is optional &mdash; define only what you need.
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
            <h3 className="text-sm font-semibold text-foreground mb-3">packagePolicy &mdash; Context Fields</h3>
            <FieldTable fields={packagePolicyContextFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">projectStatus &mdash; Context Fields</h3>
            <FieldTable fields={complianceContextFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">pullRequestCheck &mdash; Context Fields</h3>
            <FieldTable fields={prContextFields} />
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

      {/* Built-in Functions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Built-in Functions</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Policy code runs in a sandbox with these helpers available:
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[200px]">Function</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">fetch(url, options)</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">Async HTTP requests to external APIs (proxied; handle errors with try/catch or save is blocked).</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">isLicenseAllowed(license, allowlist)</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">Returns true if the license matches or is covered by the allowlist (SPDX identifiers).</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">semverGt(a, b)</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">Semver comparison: true if version string a is greater than b.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">daysSince(dateString)</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">Returns the number of days elapsed since the given ISO 8601 date.</td>
              </tr>
            </tbody>
          </table>
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
            <p className="text-sm font-medium text-foreground mb-1">is_reachable / reachability_level</p>
            <p className="text-sm text-foreground-secondary leading-relaxed">
              Deptex performs code-level reachability analysis (Phase 6B). <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">reachability_level</code> can be
              <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">confirmed</code>, <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">data_flow</code>,{" "}
              <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">function</code>, <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">module</code>, or{" "}
              <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">unreachable</code>. Unreachable vulnerabilities carry lower risk in Depscore.
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
          {/* Example 1: packagePolicy — License */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">packagePolicy — License Allowlist</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`const BANNED = ["AGPL-3.0", "GPL-3.0"];
function packagePolicy(context) {
  const lic = context.dependency.license || "UNKNOWN";
  if (BANNED.some(b => lic.includes(b))) {
    return { allowed: false, reasons: ["Banned license: " + lic] };
  }
  return { allowed: true, reasons: [] };
}`}
            </pre>
          </div>

          {/* Example 2: projectStatus — License with status */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">projectStatus — License Violations</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`function projectStatus(context) {
  const violations = [];
  for (const d of context.dependencies) {
    if (d.policyResult && !d.policyResult.allowed) {
      violations.push(d.name + ": " + (d.policyResult.reasons || []).join(", "));
    }
  }
  return {
    status: violations.length === 0 ? "Compliant" : "Non-Compliant",
    violations
  };
}`}
            </pre>
          </div>

          {/* Example 3: pullRequestCheck — Critical reachable vulns */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">pullRequestCheck — Block Critical Reachable Vulnerabilities</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`function pullRequestCheck(context) {
  const violations = [];
  for (const pkg of [...context.added, ...context.updated]) {
    for (const v of (pkg.vulnerabilities || [])) {
      if (v.severity === "critical" && (v.is_reachable || v.reachability_level)) {
        violations.push(\`\${v.osv_id} in \${pkg.name}@\${pkg.version}\`);
      }
      if (v.cisa_kev) violations.push(\`CISA KEV: \${v.osv_id} in \${pkg.name}\`);
    }
  }
  return { status: violations.length === 0 ? "Compliant" : "Non-Compliant", violations };
}`}
            </pre>
          </div>

          {/* Example 4: Supply chain */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">pullRequestCheck — Supply Chain Integrity</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`function pullRequestCheck(context) {
  const violations = [];
  for (const pkg of [...context.added, ...context.updated]) {
    if (pkg.registry_integrity_status === "fail")
      violations.push(\`Registry integrity failure: \${pkg.name}@\${pkg.version}\`);
    if (pkg.install_scripts_status === "fail")
      violations.push(\`Suspicious install scripts: \${pkg.name}@\${pkg.version}\`);
    if (pkg.entropy_analysis_status === "fail")
      violations.push(\`High entropy: \${pkg.name}@\${pkg.version}\`);
  }
  return { status: violations.length === 0 ? "Compliant" : "Non-Compliant", violations };
}`}
            </pre>
          </div>

          {/* Example 5: Malicious package */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">packagePolicy — Malicious Package Detection</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`function packagePolicy(context) {
  const d = context.dependency;
  if (d.malicious_indicator) {
    return {
      allowed: false,
      reasons: ["MALICIOUS: " + (d.malicious_indicator.source || "unknown") + " — " + (d.malicious_indicator.reason || "flagged")]
    };
  }
  return { allowed: true, reasons: [] };
}`}
            </pre>
          </div>

          {/* Example 6: projectStatus with fetch */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">projectStatus — Custom Status with External API (fetch)</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`async function projectStatus(context) {
  const violations = [];
  let approved = [];
  try {
    const resp = await fetch("https://internal-api.company.com/approved-packages");
    approved = await resp.json();
  } catch (e) { /* if API is down, skip approved-list check */ }
  if (approved.length > 0) {
    for (const dep of context.dependencies) {
      if (!approved.includes(dep.name)) violations.push(dep.name + " not in approved registry");
    }
  }
  if (violations.length > 10) return { status: "Blocked", violations };
  if (violations.length > 0) return { status: "Review Required", violations };
  return { status: "Compliant", violations: [] };
}`}
            </pre>
          </div>
        </div>
      </div>

      {/* Policy Changes */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Policy Changes (Git-like Versioning)</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Projects can deviate from the organization policy through a <strong className="text-foreground">commit-chain model</strong>: each change creates a new version with full history, conflict detection, and optional AI-powered merge. You can revert to a previous version or back to the org base. See the <Link to="/docs/compliance" className="text-primary hover:underline">Compliance</Link> doc for Policy Changes and preflight check. Exception requests (e.g. one-click license exceptions) create a diff for review; admins with <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_policies</code> can accept or reject.
          </p>
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
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-foreground">GET</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/statuses</td>
                <td className="px-4 py-3 text-foreground-secondary">List custom statuses</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-foreground">POST</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/statuses</td>
                <td className="px-4 py-3 text-foreground-secondary">Create a custom status</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-foreground">PUT</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/statuses/:statusId</td>
                <td className="px-4 py-3 text-foreground-secondary">Update a status</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-foreground">DELETE</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/statuses/:statusId</td>
                <td className="px-4 py-3 text-foreground-secondary">Delete a custom status (system statuses cannot be deleted)</td>
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

const notificationTriggerEventsByCategory: { category: string; events: { event: string; description: string }[] }[] = [
  {
    category: "Vulnerability Events",
    events: [
      { event: "vulnerability_discovered", description: "A new vulnerability (CVE / advisory) was found affecting a dependency in a project." },
      { event: "vulnerability_severity_increased", description: "An existing vulnerability's severity was raised (e.g. medium → critical)." },
      { event: "vulnerability_resolved", description: "A vulnerability was resolved (dependency updated to a fixed version)." },
    ],
  },
  {
    category: "Dependency Events",
    events: [
      { event: "dependency_added", description: "A new dependency was added to a project." },
      { event: "dependency_updated", description: "An existing dependency's version was changed." },
      { event: "dependency_removed", description: "A dependency was removed from a project." },
      { event: "dependency_deprecated", description: "A dependency was marked as deprecated upstream." },
      { event: "new_version_available", description: "A newer version of a tracked dependency was published to the registry." },
    ],
  },
  {
    category: "Policy Events",
    events: [
      { event: "policy_violation", description: "A dependency violated the organization's package policy rules." },
      { event: "license_violation", description: "A dependency with a banned or unapproved license was detected." },
      { event: "status_changed", description: "A project's compliance status was changed by the policy engine." },
      { event: "compliance_violation", description: "A project's compliance check transitioned from compliant to non-compliant." },
    ],
  },
  {
    category: "PR & Extraction Events",
    events: [
      { event: "extraction_completed", description: "A project's dependency extraction pipeline finished successfully." },
      { event: "extraction_failed", description: "A project's extraction pipeline encountered an error." },
      { event: "pr_check_completed", description: "A PR policy check completed (passed or failed with violations)." },
    ],
  },
  {
    category: "Security Events",
    events: [
      { event: "malicious_package_detected", description: "A dependency was flagged as malicious by Socket.dev or similar analysis." },
      { event: "supply_chain_anomaly", description: "Suspicious commit activity or behavioral anomaly was detected in a dependency." },
      { event: "security_analysis_failure", description: "Registry integrity, install scripts, or entropy analysis returned a 'fail' status." },
    ],
  },
  {
    category: "AI Events",
    events: [
      { event: "ai_fix_completed", description: "An AI-powered fix (Aider) completed — PR created or fix failed." },
    ],
  },
  {
    category: "Membership & Admin Events",
    events: [
      { event: "member_invited", description: "A new member was invited to the organization." },
      { event: "member_joined", description: "A member accepted their invitation and joined." },
      { event: "member_removed", description: "A member was removed from the organization." },
      { event: "integration_connected", description: "A new integration (Slack, GitHub, etc.) was connected." },
      { event: "integration_disconnected", description: "An integration was disconnected." },
      { event: "project_created", description: "A new project was created in the organization." },
      { event: "project_deleted", description: "A project was deleted from the organization." },
    ],
  },
  {
    category: "System Events",
    events: [
      { event: "risk_score_changed", description: "A project's health score changed significantly (crossed a threshold)." },
      { event: "extraction_started", description: "A dependency extraction pipeline was kicked off." },
      { event: "dependency_license_changed", description: "An upstream dependency changed its license." },
      { event: "security_scan_completed", description: "Semgrep or TruffleHog scan completed for a project." },
      { event: "watchtower_analysis_completed", description: "Watchtower supply-chain analysis completed for a watched package." },
      { event: "aegis_automation_completed", description: "A scheduled Aegis automation finished its run." },
    ],
  },
];

const notifContextEventFields = [
  { field: "type", type: "string", description: "The event that triggered the evaluation. One of the 33+ trigger event types listed above." },
  { field: "timestamp", type: "string", description: "ISO 8601 timestamp of when the event occurred." },
];

const notifContextProjectFields = [
  { field: "name", type: "string", description: "Project name." },
  { field: "asset_tier", type: "string", description: '"CROWN_JEWELS" | "EXTERNAL" | "INTERNAL" | "NON_PRODUCTION" — the project\'s criticality tier.' },
  { field: "asset_tier_rank", type: "number", description: "Numeric rank of the asset tier (1 = highest criticality)." },
  { field: "health_score", type: "number", description: "Project health score (0 – 100). Lower means more risk." },
  { field: "status", type: "string", description: "Current custom compliance status name (e.g. Compliant, Non-Compliant)." },
  { field: "status_is_passing", type: "boolean", description: "Whether the current status is marked as passing." },
  { field: "team_name", type: "string | null", description: "Name of the team the project belongs to, if any." },
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

const notifContextPrFields = [
  { field: "number", type: "number", description: "PR number." },
  { field: "title", type: "string", description: "PR title." },
  { field: "author", type: "string", description: "PR author login." },
  { field: "deps_added", type: "object[]", description: "Dependencies added in this PR." },
  { field: "deps_updated", type: "object[]", description: "Dependencies updated in this PR (includes from_version, to_version)." },
  { field: "deps_removed", type: "string[]", description: "Dependencies removed in this PR." },
  { field: "check_result", type: "string", description: '"passed" | "failed" — result of the PR policy check.' },
  { field: "violations", type: "string[]", description: "Policy violations found, if any." },
];

const notifContextBatchFields = [
  { field: "count", type: "number", description: "Number of items in this batch (e.g. vulnerabilities discovered in one extraction run)." },
  { field: "items", type: "object[]", description: "Array of individual event items (same shape as the top-level context fields)." },
];

const notifContextPreviousFields = [
  { field: "health_score", type: "number | undefined", description: "Previous health score (only set for risk_score_changed events)." },
  { field: "previous_status", type: "string | undefined", description: "Previous custom status name (for status_changed, compliance_violation)." },
  { field: "previous_status_is_passing", type: "boolean | undefined", description: "Whether the previous status was passing." },
  { field: "version", type: "string | undefined", description: "Previous version string (only set for dependency_updated events)." },
  { field: "status", type: "string | undefined", description: "Previous project status name (only set for status_changed events)." },
];

function WatchtowerContent() {
  return (
    <div className="space-y-12">
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">What is Watchtower</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            <strong className="text-foreground">Watchtower</strong> is Deptex&apos;s proactive supply chain defense system. Enable it per-project to automatically monitor all direct dependencies for registry tampering, malicious install scripts, obfuscated payloads, and suspicious contributor activity.
          </p>
          <p>
            When you enable Watchtower, all direct dependencies are added to the watchlist. New dependencies added through future extractions are automatically included. Watchtower workers run on Fly.io with scale-to-zero &mdash; you only pay for actual analysis time.
          </p>
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Security Checks</h2>
        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-2">Registry Integrity Check</h3>
            <p className="text-foreground-secondary leading-relaxed">
              Compares the npm tarball published to the registry against the git source at the tagged commit. A failure means the published package contains code not present in the git repository &mdash; a strong indicator of a compromised publish. Available for npm packages with linked GitHub repositories.
            </p>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-2">Install Script Analysis</h3>
            <p className="text-foreground-secondary leading-relaxed">
              Scans <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">preinstall</code>, <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">install</code>, and <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">postinstall</code> scripts for: network access (http/https/net/dns), shell execution (exec/spawn/execSync), and dangerous operations (eval, Function(), base64, rm -rf, chmod 777). Install scripts run automatically on <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">npm install</code> &mdash; malicious packages exploit this for code execution.
            </p>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-2">Entropy Analysis</h3>
            <p className="text-foreground-secondary leading-relaxed">
              Computes Shannon entropy of JS/TS files. Normal code has entropy between 3.5&ndash;5.0. Obfuscated or encoded payloads typically exceed 5.5. High-entropy files suggest hidden malicious code using string encoding, variable mangling, or packed payloads.
            </p>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground mb-2">Commit Anomaly Detection</h3>
            <p className="text-foreground-secondary leading-relaxed">
              Scores each commit against the contributor&apos;s historical baseline: files changed, lines changed, unusual commit time/day, message length anomaly, insert/delete ratio shift, and new files worked on. Total score: 0&ndash;100. Mild anomaly &ge; 30, High anomaly &ge; 60.
            </p>
          </div>
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Quarantine System</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Hold new versions for 7 days before allowing upgrades. During quarantine, bump PRs are blocked. Toggle quarantine per-package from the project Watchtower tab. If security checks fail on the new version, it is blocked regardless of quarantine status.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">PR Guardrails Integration</h2>
        <p className="text-foreground-secondary leading-relaxed">
          When Watchtower is enabled, PR guardrails automatically block upgrades to versions that failed security checks or are currently quarantined. PRs that attempt to upgrade to a blocked version receive a detailed failure message explaining which check failed.
        </p>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">How to Enable</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Watchtower is enabled <strong className="text-foreground">per project</strong>. Go to your project&apos;s <strong className="text-foreground">Watchtower</strong> tab in the sidebar and click <strong className="text-foreground">&ldquo;Enable Watchtower&rdquo;</strong>. All direct dependencies for that project are then added to the watch list. New dependencies added through future extractions are auto-included for that project.
          </p>
          <p>
            The <strong className="text-foreground">organization Watchtower page</strong> (from the org sidebar) shows an overview of all projects that have Watchtower enabled: aggregated alerts, cross-project package coverage, and per-project activation status. Use it to see supply-chain risk across the whole organization.
          </p>
        </div>
      </div>
    </div>
  );
}

function NotificationRulesContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            <strong className="text-foreground">Notification Rules</strong> let you define automated alerts that fire when specific events occur across your projects and dependencies.
            Each rule consists of a <strong className="text-foreground">trigger function</strong> written in JavaScript and one or more <strong className="text-foreground">destinations</strong> (Slack, Discord, Jira, Linear, Asana, PagerDuty, email, or custom webhooks).
          </p>
          <p>
            When an event occurs, Deptex evaluates your trigger function with a rich context object. The function can return{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">true</code> / <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">false</code>{" "}
            for simple notify/skip, or return an object with <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">{`{ notify, message, title, priority }`}</code> for richer control.
          </p>
          <p>
            Use the <strong className="text-foreground">AI assistant</strong> in the rule editor to describe what you want in plain English &mdash; it will generate the trigger code for you.
            There are also <strong className="text-foreground">8 built-in templates</strong> to get started quickly (critical vulns, supply chain alerts, compliance, etc.).
          </p>
        </div>
      </div>

      {/* Trigger Events */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Trigger Events</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Deptex supports 33+ event types organized by category. Your trigger function receives the event type in{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context.event.type</code> and can filter on it.
        </p>
        <div className="space-y-4">
          {notificationTriggerEventsByCategory.map((cat) => (
            <div key={cat.category} className="rounded-lg border border-border bg-background-card overflow-hidden">
              <div className="px-4 py-2.5 bg-background-card-header border-b border-border">
                <span className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">{cat.category}</span>
              </div>
              <table className="w-full text-sm">
                <tbody className="divide-y divide-border">
                  {cat.events.map((e) => (
                    <tr key={e.event} className="hover:bg-table-hover transition-colors">
                      <td className="px-4 py-2.5 font-mono text-xs text-foreground w-[280px]">{e.event}</td>
                      <td className="px-4 py-2.5 text-foreground-secondary text-sm">{e.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
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
            <h3 className="text-sm font-semibold text-foreground mb-3">context.pr <span className="font-normal text-foreground-secondary">(nullable)</span></h3>
            <p className="text-sm text-foreground-secondary mb-2">
              Pull request details. Present for pr_check_completed and PR-triggered extraction events.
            </p>
            <FieldTable fields={notifContextPrFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">context.batch <span className="font-normal text-foreground-secondary">(nullable)</span></h3>
            <p className="text-sm text-foreground-secondary mb-2">
              When multiple events of the same type occur simultaneously (e.g. 10 vulnerabilities discovered in one extraction), they are batched. The trigger function is called once with the batch.
            </p>
            <FieldTable fields={notifContextBatchFields} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">context.previous <span className="font-normal text-foreground-secondary">(nullable)</span></h3>
            <p className="text-sm text-foreground-secondary mb-2">
              Previous state values for comparison. Present for change-type events (risk_score_changed, compliance_violation, status_changed, dependency_updated).
            </p>
            <FieldTable fields={notifContextPreviousFields} />
          </div>
        </div>
      </div>

      {/* Return Format */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Return Format</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Your trigger function can return a simple boolean or a richer object for more control over the notification.
        </p>
        <div className="space-y-4">
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Simple (boolean)</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`return true;   // send notification with default message
return false;  // skip — do not notify`}
            </pre>
          </div>
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-2 bg-background-card-header border-b border-border">
              <p className="text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Enhanced (object)</p>
            </div>
            <pre className="p-4 text-sm text-foreground overflow-x-auto font-mono">
{`return {
  notify: true,                          // required — send or skip
  title: "Critical vuln in prod",        // optional — custom title
  message: "GHSA-xxxx in lodash@4.17.20", // optional — custom body
  priority: "critical",                  // optional — "critical" | "high" | "medium" | "low"
};`}
            </pre>
          </div>
          <p className="text-sm text-foreground-secondary">
            The <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">priority</code> field maps to PagerDuty severity levels and affects email subject prefixes. If omitted, Deptex infers priority from the event type.
          </p>
        </div>
      </div>

      {/* Example Trigger Functions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Example Trigger Functions</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Copy and adapt these examples when creating notification rules. Each function receives{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context</code> and returns{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">true</code> / <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">false</code>{" "}
          or a <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">{`{ notify, message, title, priority }`}</code> object.
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
          Each notification rule can send alerts to one or more of 9 destination types. Destinations are configured through your organization&apos;s connected integrations in{" "}
          <strong className="text-foreground">Settings &rarr; Integrations</strong>.
        </p>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[
            { name: "Slack", icon: Slack, desc: "Posts a formatted message to the configured channel." },
            { name: "Discord", icon: MessageCircle, desc: "Sends a rich embed to the configured Discord channel." },
            { name: "Email", icon: Mail, desc: "Sends an email notification to the configured address." },
            { name: "PagerDuty", icon: Webhook, desc: "Triggers incidents for critical events via Events API v2. Priority maps to PD severity." },
            { name: "Jira", icon: FileCode, desc: "Creates a Jira issue in the configured project." },
            { name: "Linear", icon: Code, desc: "Creates a Linear issue in the configured team." },
            { name: "Asana", icon: FileCode, desc: "Creates an Asana task in the configured project." },
            { name: "Custom Webhook", icon: Webhook, desc: "Sends a signed HTTP POST (HMAC-SHA256) to your custom webhook endpoint." },
            { name: "Custom Ticketing", icon: Settings, desc: "Sends a signed HTTP POST formatted for ticketing system integration." },
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

      {/* Validation */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Validation</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          When you save a notification rule, Deptex performs a 3-step validation:
        </p>
        <ol className="list-decimal list-inside space-y-2 text-sm text-foreground-secondary">
          <li><strong className="text-foreground">Syntax check</strong> &mdash; the trigger code is parsed to ensure it&rsquo;s valid JavaScript.</li>
          <li><strong className="text-foreground">Sandbox execution</strong> &mdash; the function is run in an isolated sandbox with a sample context to verify it returns a boolean or valid object.</li>
          <li><strong className="text-foreground">Destination validation</strong> &mdash; at least one destination must be configured and reachable.</li>
        </ol>
      </div>

      {/* Testing */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Testing</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Use the <strong className="text-foreground">Test Rule</strong> button in the rule editor to dry-run your trigger against a sample event. The result shows whether the rule would fire, plus the returned message and priority.
          </p>
          <p>
            The <strong className="text-foreground">Send Test</strong> button sends an actual test notification to all configured destinations so you can verify formatting and delivery.
            Test deliveries are tagged as <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">dry_run</code> in the History tab.
          </p>
        </div>
      </div>

      {/* Delivery Tracking */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Delivery Tracking</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            The <strong className="text-foreground">History</strong> tab in Settings &rarr; Notifications shows every delivery attempt with status (delivered, failed, rate limited, skipped), timestamps, and error details.
          </p>
          <p>
            Failed deliveries can be <strong className="text-foreground">retried</strong> with a single click. Deptex automatically retries failed deliveries up to 3 times with exponential backoff (1 min, 5 min, 15 min) before marking them as permanently failed.
          </p>
          <p>
            The <strong className="text-foreground">Health</strong> tab provides an at-a-glance dashboard: delivery success rate (24h), total deliveries and events (7d), and a list of recent failures.
          </p>
        </div>
      </div>

      {/* Digest & Batching */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Digest &amp; Batching</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Configure <strong className="text-foreground">weekly</strong> or <strong className="text-foreground">daily</strong> digest summaries per notification rule. Instead of individual alerts, Deptex batches events and sends a single summary at the configured frequency.
          </p>
          <p>
            When multiple events of the same type occur simultaneously (e.g. 10 vulnerabilities discovered in one extraction run), they are automatically batched into a single notification with{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context.batch</code> containing the individual items.
          </p>
        </div>
      </div>

      {/* Rate Limits */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Rate Limits</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            To prevent notification storms, Deptex enforces rate limits:
          </p>
          <ul className="list-disc list-inside space-y-1.5 text-sm">
            <li><strong className="text-foreground">200 / hour</strong> per organization (across all rules and destinations).</li>
            <li><strong className="text-foreground">30 / hour</strong> per individual destination (e.g. one Slack channel).</li>
          </ul>
          <p>
            Notifications that hit the rate limit are recorded as <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">rate_limited</code> in the History tab and are not retried.
            The <strong className="text-foreground">Pause All</strong> button in the Notifications header lets you temporarily silence all notifications for 1h, 4h, or 24h.
          </p>
        </div>
      </div>

      {/* User Preferences */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">User Preferences</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Individual users can manage their notification preferences:
          </p>
          <ul className="list-disc list-inside space-y-1.5 text-sm">
            <li><strong className="text-foreground">Email opt-out</strong> &mdash; unsubscribe from email notifications while still receiving alerts via other channels.</li>
            <li><strong className="text-foreground">Do Not Disturb</strong> &mdash; set quiet hours during which notifications are held and delivered when DND ends.</li>
          </ul>
        </div>
      </div>

      {/* Templates */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Templates</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Deptex provides 8 built-in templates to get started quickly. Select a template when creating a new rule:
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          {[
            "Critical Vulnerabilities",
            "Supply Chain Anomalies",
            "New Dependencies Added",
            "Policy Violations",
            "Extraction Failures",
            "CISA KEV Alerts",
            "License Violations",
            "Health Score Drops",
          ].map((t) => (
            <div key={t} className="flex items-center gap-2 rounded-md border border-border bg-background-card px-3 py-2">
              <div className="h-1.5 w-1.5 rounded-full bg-primary flex-shrink-0" />
              <span className="text-sm text-foreground">{t}</span>
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
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground">POST</td><td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/notification-rules/:ruleId/test</td><td className="px-4 py-3 text-foreground-secondary">Dry-run a rule with a sample event</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground">POST</td><td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/notification-rules/:ruleId/send-test</td><td className="px-4 py-3 text-foreground-secondary">Send a test notification to all destinations</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground">GET</td><td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/notification-history</td><td className="px-4 py-3 text-foreground-secondary">List delivery history (filterable, paginated)</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground">POST</td><td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/notification-history/:deliveryId/retry</td><td className="px-4 py-3 text-foreground-secondary">Retry a failed delivery</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground">GET</td><td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/notification-stats</td><td className="px-4 py-3 text-foreground-secondary">Health dashboard stats (success rate, totals, failures)</td></tr>
              <tr className="hover:bg-table-hover transition-colors"><td className="px-4 py-3 font-mono text-foreground">POST</td><td className="px-4 py-3 font-mono text-xs text-foreground-secondary break-all">/api/organizations/:id/pagerduty/connect</td><td className="px-4 py-3 text-foreground-secondary">Connect PagerDuty (service name + routing key)</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

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

function IntroductionContent() {
  const [screenshotError, setScreenshotError] = useState(false);

  return (
    <>
      <p className="text-foreground-secondary leading-relaxed mb-8">
        Deptex is a security and compliance platform for your dependency supply chain. It connects to
        your repositories, tracks every dependency, and gives you a single place to see risks,
        enforce policies with custom statuses, and use AI-powered fixing (automated PRs) and the
        autonomous security agent (Aegis) to remediate and report on your behalf.
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
            <p className="text-sm text-foreground-secondary">
              This documentation page doesn&apos;t exist yet.
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

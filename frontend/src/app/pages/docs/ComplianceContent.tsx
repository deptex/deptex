import { Link } from "react-router-dom";

const evaluationFlow = [
  { step: 1, title: "Extraction completes", description: "Deptex finishes parsing manifests and lockfiles, producing the full dependency inventory." },
  { step: 2, title: "Policy code runs", description: "The organization\u2019s projectCompliance(context) function executes against the dependency data." },
  { step: 3, title: "Status assigned", description: "Based on the policy result, a custom status is assigned to the project (e.g. \u201cCompliant\u201d, \u201cAction Required\u201d)." },
  { step: 4, title: "Violations stored", description: "Any violation messages returned by the policy are persisted and surfaced in the Compliance tab." },
  { step: 5, title: "Badges updated", description: "The project\u2019s compliance badge and dashboard indicators reflect the new status." },
];

const sbomFormats = [
  { format: "CycloneDX 1.5", spec: "OWASP standard", description: "Component inventory with dependency graph, vulnerability references, and license data. JSON and XML output.", useCase: "Security-focused SBOM for vulnerability management and compliance auditing." },
  { format: "SPDX", spec: "ISO/IEC 5962:2021", description: "License-centric bill of materials with package, file, and snippet-level license annotations.", useCase: "License compliance, legal review, and open-source governance." },
];

export default function ComplianceContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex approaches compliance through three pillars: <strong className="text-foreground">custom statuses</strong> that
            model your organization&rsquo;s compliance states, <strong className="text-foreground">policy-as-code</strong> that
            automates evaluation, and <strong className="text-foreground">license tracking</strong> per dependency.
          </p>
          <p>
            Rather than imposing a fixed compliance framework, Deptex lets you define what &ldquo;compliant&rdquo; means for your organization
            and encodes those rules as JavaScript functions that run against real dependency data.
          </p>
        </div>
      </div>

      {/* Custom Statuses */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Custom Statuses</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Organizations define their own set of compliance statuses in <strong className="text-foreground">Settings &rarr; Statuses</strong>.
            Each status has a <strong className="text-foreground">name</strong>, <strong className="text-foreground">color</strong>,{" "}
            <strong className="text-foreground">rank</strong> (for ordering from best to worst), and an{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">is_passing</code> flag
            that determines whether the status counts as &ldquo;compliant.&rdquo;
          </p>
          <p>
            When <Link to="/docs/policies" className="text-primary hover:underline">policy evaluation</Link> runs,
            the policy code returns a result that maps to one of these statuses. Projects receive the corresponding status badge on the dashboard and in the Compliance tab.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-background-card overflow-hidden mt-4">
          <div className="px-4 py-3 border-b border-border bg-background-card-header">
            <h3 className="text-sm font-semibold text-foreground">Status Fields</h3>
          </div>
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[140px]">Field</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">name</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">Display label shown on badges and in the Compliance tab (e.g. &ldquo;Compliant&rdquo;, &ldquo;Action Required&rdquo;).</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">color</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">Hex color for the status badge.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">rank</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">Integer rank for sorting. Lower rank = better status. Used when displaying project lists sorted by compliance health.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">is_passing</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">
                  Boolean. When <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">true</code>, the status counts as &ldquo;compliant&rdquo; for aggregate reporting and PR checks.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Policy Evaluation Flow */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Policy Evaluation Flow</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Compliance status is determined automatically each time dependencies are extracted or updated. The full evaluation pipeline:
        </p>

        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-background-card-header">
            <h3 className="text-sm font-semibold text-foreground">Evaluation Pipeline</h3>
          </div>
          <div className="p-4">
            <ol className="space-y-4">
              {evaluationFlow.map((item) => (
                <li key={item.step} className="flex gap-4">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-background-subtle text-xs font-semibold text-foreground">
                    {item.step}
                  </span>
                  <div className="pt-0.5">
                    <p className="text-sm font-medium text-foreground">{item.title}</p>
                    <p className="text-sm text-foreground-secondary mt-0.5">{item.description}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </div>

        <p className="text-foreground-secondary leading-relaxed mt-3 text-sm">
          See <Link to="/docs/policies" className="text-primary hover:underline">Policies</Link> for
          how to write policy functions and the full context API reference.
        </p>
      </div>

      {/* SBOM Export */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">SBOM Export</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed mb-4">
          <p>
            Deptex generates Software Bills of Materials using <strong className="text-foreground">cdxgen</strong> during extraction.
            SBOMs are available for download from the project&rsquo;s <strong className="text-foreground">Compliance tab</strong> in two industry-standard formats.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[160px]">Format</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[180px]">Specification</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Use Case</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {sbomFormats.map((row) => (
                <tr key={row.format} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3 text-sm font-medium text-foreground">{row.format}</td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{row.spec}</td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{row.useCase}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <p className="text-foreground-secondary leading-relaxed mt-3 text-sm">
          SBOMs include component names, versions, licenses, dependency relationships, and known vulnerability references.
          Export from the Compliance tab or programmatically via the API.
        </p>
      </div>

      {/* Legal Notice Export */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Legal Notice Export</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            The Compliance tab provides a <strong className="text-foreground">Legal Notice</strong> export that generates a
            document listing every dependency, its version, and its license text. This is intended for distribution with
            your software to satisfy open-source license attribution requirements.
          </p>
          <p>
            The generated notice aggregates license information from registry metadata and SPDX identifiers.
            For packages with non-standard or unknown licenses, the notice flags them for manual review.
          </p>
        </div>
      </div>

      {/* License Tracking */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">License Tracking</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex identifies the SPDX license identifier for each dependency from registry metadata. Licenses are
            surfaced in the Dependencies tab, included in SBOM exports, and available in the{" "}
            <Link to="/docs/policies" className="text-primary hover:underline">policy context</Link> as the{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">license</code> field on each dependency.
          </p>
          <p>
            For policy enforcement, you can use the built-in{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">isLicenseAllowed(license, allowlist)</code>{" "}
            helper or write custom license checks directly in your policy code. Common patterns include maintaining
            an allowlist of approved licenses and blocking copyleft licenses like AGPL-3.0 for production dependencies.
          </p>
        </div>
      </div>

      {/* Policy Changes (Git-like Versioning) */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Policy Changes (Git-like Versioning)</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed mb-4">
          <p>
            Projects can deviate from the organization-wide policy through a <strong className="text-foreground">commit-chain model</strong> inspired by Git.
            Each change to a project&rsquo;s policy creates a new commit in the chain, preserving full history and enabling rollback.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-background-card-header">
            <h3 className="text-sm font-semibold text-foreground">How It Works</h3>
          </div>
          <div className="p-6 space-y-5">
            <div>
              <p className="text-sm font-medium text-foreground mb-1">Requesting changes</p>
              <p className="text-sm text-foreground-secondary leading-relaxed">
                A project member submits a policy change request from the project&rsquo;s Compliance settings.
                The request includes modified policy code and a reason. Organization admins review and approve or reject.
              </p>
            </div>
            <div>
              <p className="text-sm font-medium text-foreground mb-1">Conflict resolution with AI merge</p>
              <p className="text-sm text-foreground-secondary leading-relaxed">
                When the organization policy is updated after a project has diverged, Deptex detects the conflict.
                An AI-assisted merge suggests how to reconcile the project&rsquo;s exceptions with the new org policy,
                similar to a Git merge. Reviewers can accept the suggestion, edit it, or resolve manually.
              </p>
            </div>
            <div>
              <p className="text-sm font-medium text-foreground mb-1">Reverting to previous versions</p>
              <p className="text-sm text-foreground-secondary leading-relaxed">
                Every policy commit is immutable. You can browse the commit history and revert to any previous version
                with a single click. Reverting creates a new commit (like <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">git revert</code>), so the history stays intact.
              </p>
            </div>
            <div>
              <p className="text-sm font-medium text-foreground mb-1">One-click license exceptions</p>
              <p className="text-sm text-foreground-secondary leading-relaxed">
                For common cases like allowing a specific license for a single project, the Compliance tab offers a
                shortcut: click the license violation, choose &ldquo;Add Exception,&rdquo; and the system generates the policy
                diff automatically and submits it for approval.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Preflight Check */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Preflight Check</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            The <strong className="text-foreground">preflight check</strong> lets you test whether adding or updating a package
            would affect your project&rsquo;s compliance status <em>before</em> committing the change.
          </p>
          <p>
            From the Compliance tab, enter a package name and version to simulate. Deptex evaluates the package
            against your active policy code and returns the result: whether the policy would still pass,
            any new violations that would be introduced, and the license of the candidate package.
          </p>
          <p>
            This is also available via the <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pullRequestCheck</code> policy
            function during PR evaluation &mdash; the preflight UI effectively runs the same logic on demand without requiring a real pull request.
          </p>
        </div>
      </div>
    </div>
  );
}

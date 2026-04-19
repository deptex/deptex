import { Link } from "react-router-dom";

export default function ComplianceContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            Deptex approaches compliance through three pillars: <strong className="text-foreground">custom statuses</strong> that
            model your organization&rsquo;s compliance states, <strong className="text-foreground">policy-as-code</strong> that
            automates evaluation, and <strong className="text-foreground">license tracking</strong> per dependency.
          </p>
          <p>
            Rather than imposing a fixed framework, Deptex lets you define what &ldquo;compliant&rdquo; means and encodes
            those rules as JavaScript functions that run against real dependency data.
          </p>
        </div>
      </div>

      {/* Custom Statuses */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Custom Statuses</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            Organizations define compliance statuses in <strong className="text-foreground">Settings &rarr; Statuses</strong>.
            Each status has a name, color, rank (for ordering), and an <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">is_passing</code> flag
            that determines whether it counts as compliant. When policy evaluation runs, the result maps to one of these
            statuses. Projects receive the corresponding badge on the dashboard and in the Compliance tab.
          </p>
        </div>
      </div>

      {/* Policy Evaluation Flow */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Policy Evaluation Flow</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          Compliance status is determined automatically each time dependencies are extracted. The pipeline: extraction
          completes → policy code runs → status is assigned → violations are stored and surfaced in the Compliance tab.
          See <Link to="/docs/policies" className="text-foreground underline hover:no-underline">Policies</Link> for how to write policy functions.
        </p>
        <p className="text-foreground/90 leading-relaxed text-sm">
          The Compliance tab includes <strong className="text-foreground">Pull Requests</strong> and <strong className="text-foreground">Commits</strong> sub-tabs
          for PR check history and commit-triggered extraction status.
        </p>
      </div>

      {/* SBOM Export */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">SBOM Export</h2>
        <p className="text-foreground/90 leading-relaxed">
          Deptex generates SBOMs during extraction. Download from the project&rsquo;s <strong className="text-foreground">Compliance tab</strong> in
          CycloneDX (security-focused) or SPDX (license-focused) format. SBOMs include component names, versions, licenses,
          dependency relationships, and vulnerability references.
        </p>
      </div>

      {/* Legal Notice Export */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Legal Notice Export</h2>
        <p className="text-foreground/90 leading-relaxed">
          The Compliance tab provides a <strong className="text-foreground">Legal Notice</strong> export that lists every
          dependency, its version, and license text. Use it to satisfy open-source attribution requirements when
          distributing your software. Non-standard or unknown licenses are flagged for manual review.
        </p>
      </div>

      {/* License Tracking */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">License Tracking</h2>
        <p className="text-foreground/90 leading-relaxed">
          Deptex identifies the SPDX license for each dependency. Licenses appear in the Dependencies tab, SBOM exports,
          and in the <Link to="/docs/policies" className="text-foreground underline hover:no-underline">policy context</Link>.
          Use the built-in <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">isLicenseAllowed</code> helper
          or write custom checks. Common patterns: allowlist approved licenses, block copyleft (e.g. AGPL) for production.
        </p>
      </div>

      {/* Policy Changes */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Policy Changes</h2>
        <p className="text-foreground/90 leading-relaxed">
          Projects can deviate from the org-wide policy through a commit-chain model. Each change creates a new commit
          with full history and rollback. When the org policy updates after a project has diverged, Deptex detects conflicts
          and can suggest a merge. For license exceptions, the Compliance tab offers a shortcut: click the violation,
          choose &ldquo;Add Exception,&rdquo; and the system generates the policy diff for approval.
        </p>
      </div>

      {/* Preflight Check */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Preflight Check</h2>
        <p className="text-foreground/90 leading-relaxed">
          The <strong className="text-foreground">preflight check</strong> lets you test whether adding or updating a package
          would affect compliance <em>before</em> committing. Enter a package name and version in the Compliance tab;
          Deptex evaluates it against your policy and returns whether it would pass, any new violations, and the candidate&rsquo;s license.
        </p>
      </div>
    </div>
  );
}

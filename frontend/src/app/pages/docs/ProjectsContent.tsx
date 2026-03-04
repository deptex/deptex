import { Link } from "react-router-dom";

export default function ProjectsContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            A <strong className="text-foreground">project</strong> in Deptex represents a single monitored repository.
            When you connect a repository, Deptex creates a project that continuously tracks its{" "}
            <Link to="/docs/dependencies" className="text-foreground underline hover:no-underline">dependencies</Link>,{" "}
            <Link to="/docs/vulnerabilities" className="text-foreground underline hover:no-underline">vulnerabilities</Link>,{" "}
            <Link to="/docs/compliance" className="text-foreground underline hover:no-underline">compliance status</Link>, and extraction history.
          </p>
          <p>
            Projects are the central unit of work in Deptex. Every scan, policy evaluation, and notification is scoped to a project.
          </p>
        </div>
      </div>

      {/* Creating a Project */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Creating a Project</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground/90 leading-relaxed">
            Before creating a project you need at least one source-code provider connected. Go to{" "}
            <strong className="text-foreground">Settings &rarr; Integrations</strong> and connect GitHub, GitLab, or Bitbucket.
            See the <Link to="/docs/integrations" className="text-foreground underline hover:no-underline">Integrations</Link> docs for setup details.
          </p>
          <ol className="list-decimal list-inside space-y-1.5 text-sm text-foreground/90">
            <li>Click <strong className="text-foreground">New Project</strong> from the organization dashboard.</li>
            <li>Select the connected provider and choose a repository.</li>
            <li>Assign the project to a team (optional but recommended for scoped visibility).</li>
            <li>Deptex immediately queues an extraction for the default branch.</li>
          </ol>
          <p className="text-foreground/90 leading-relaxed text-sm">
            Supported providers: <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">GitHub</code>,{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">GitLab</code>,{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">Bitbucket</code>.
          </p>
        </div>
      </div>

      {/* Extraction Pipeline */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Extraction Pipeline</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          When an extraction runs, Deptex executes the following pipeline against your repository:
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-12">Step</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[180px]">Stage</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">1</td>
                <td className="px-4 py-3 text-foreground font-medium">Clone</td>
                <td className="px-4 py-3 text-foreground/90">Shallow-clone the repository at the target branch/commit.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">2</td>
                <td className="px-4 py-3 text-foreground font-medium">SBOM Generation</td>
                <td className="px-4 py-3 text-foreground/90">
                  Generate a CycloneDX Software Bill of Materials using{" "}
                  <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">cdxgen</code>. Resolves the full dependency tree including transitive dependencies.
                </td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">3</td>
                <td className="px-4 py-3 text-foreground font-medium">Vulnerability Scan</td>
                <td className="px-4 py-3 text-foreground/90">
                  Scan the SBOM using <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">dep-scan</code> for vulnerability matching and code-level reachability. Matches CVEs, GitHub Security Advisories, and OSV.
                </td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">4</td>
                <td className="px-4 py-3 text-foreground font-medium">SAST Analysis</td>
                <td className="px-4 py-3 text-foreground/90">
                  Run static application security testing via{" "}
                  <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">Semgrep</code> to detect code-level security issues and anti-patterns.
                </td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">5</td>
                <td className="px-4 py-3 text-foreground font-medium">Secrets Detection</td>
                <td className="px-4 py-3 text-foreground/90">
                  Scan for leaked secrets and credentials using{" "}
                  <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">TruffleHog</code>.
                </td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">6</td>
                <td className="px-4 py-3 text-foreground font-medium">Scoring</td>
                <td className="px-4 py-3 text-foreground/90">
                  Compute the project health score and per-vulnerability{" "}
                  <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">depscore</code> based on CVSS, EPSS, reachability, CISA KEV status, and asset tier.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-foreground/90 leading-relaxed mt-3 text-sm">
          AI-powered vulnerability fixing is a <strong className="text-foreground">separate flow</strong> triggered from the Security tab or Aegis; it does not run as part of extraction.
        </p>
      </div>

      {/* Live Extraction Logs */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Live Extraction Logs</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground/90 leading-relaxed">
            Each extraction streams live logs to the project detail page. Log lines are color-coded by level:
          </p>
          <div className="flex flex-wrap gap-3 text-sm">
            <span className="rounded bg-background-subtle px-2.5 py-1 text-foreground font-mono text-xs">INFO</span>
            <span className="rounded bg-background-subtle px-2.5 py-1 text-yellow-400 font-mono text-xs">WARN</span>
            <span className="rounded bg-background-subtle px-2.5 py-1 text-red-400 font-mono text-xs">ERROR</span>
            <span className="rounded bg-background-subtle px-2.5 py-1 text-blue-400 font-mono text-xs">DEBUG</span>
          </div>
          <p className="text-foreground/90 leading-relaxed">
            You can browse historical runs from the extraction history and view the full log output for any past extraction.
          </p>
        </div>
      </div>

      {/* Project Status */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Project Status</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            After each extraction, Deptex evaluates the project against all applicable{" "}
            <Link to="/docs/policies" className="text-foreground underline hover:no-underline">policies</Link> and assigns a custom status.
            The <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">is_passing</code> flag
            indicates whether the project satisfies every active policy rule.
          </p>
          <p>
            Statuses are determined entirely by policy evaluation &mdash; there are no hard-coded pass/fail thresholds.
            This lets your organization define what &ldquo;passing&rdquo; means based on your own risk tolerance and compliance requirements.
          </p>
        </div>
      </div>

      {/* Project Settings */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Project Settings</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          Each project exposes several configuration options in its Settings tab.
        </p>

        <div className="space-y-6">
          {/* Asset Tier */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-background-card-header">
              <h3 className="text-sm font-semibold text-foreground">Asset Tier</h3>
            </div>
            <div className="p-4">
              <p className="text-foreground/90 leading-relaxed mb-3 text-sm">
                The asset tier reflects the criticality of the repository and influences vulnerability scoring.
              </p>
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[180px]">Tier</th>
                      <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    <tr className="hover:bg-table-hover transition-colors">
                      <td className="px-4 py-3 font-mono text-xs text-foreground">CROWN_JEWELS</td>
                      <td className="px-4 py-3 text-foreground/90">Business-critical systems. Highest severity multiplier for vulnerability scoring.</td>
                    </tr>
                    <tr className="hover:bg-table-hover transition-colors">
                      <td className="px-4 py-3 font-mono text-xs text-foreground">EXTERNAL</td>
                      <td className="px-4 py-3 text-foreground/90">Public-facing applications. Elevated risk due to attack surface exposure.</td>
                    </tr>
                    <tr className="hover:bg-table-hover transition-colors">
                      <td className="px-4 py-3 font-mono text-xs text-foreground">INTERNAL</td>
                      <td className="px-4 py-3 text-foreground/90">Internal tools and services. Moderate severity multiplier.</td>
                    </tr>
                    <tr className="hover:bg-table-hover transition-colors">
                      <td className="px-4 py-3 font-mono text-xs text-foreground">NON_PRODUCTION</td>
                      <td className="px-4 py-3 text-foreground/90">Development, staging, or sandbox environments. Lowest severity multiplier.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Policy Inheritance */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-background-card-header">
              <h3 className="text-sm font-semibold text-foreground">Policy Inheritance</h3>
            </div>
            <div className="p-4 space-y-2 text-sm text-foreground/90 leading-relaxed">
              <p>
                By default, projects inherit the organization-level{" "}
                <Link to="/docs/policies" className="text-foreground underline hover:no-underline">policy</Link>. You can override this with a project-specific
                policy or request an exception through the policy exception workflow.
              </p>
              <p>
                When a project has its own policy, it replaces the org policy entirely for that project &mdash; policies are not merged.
              </p>
            </div>
          </div>

          {/* Repository Sync */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-background-card-header">
              <h3 className="text-sm font-semibold text-foreground">Repository Sync</h3>
            </div>
            <div className="p-4 text-sm text-foreground/90 leading-relaxed space-y-2">
              <p>
                Configure which branch to track and the <strong className="text-foreground">sync frequency</strong>: manual (extract only when you click Sync), on commit (webhook on push), daily, or weekly. Webhook-triggered extractions run when your provider sends a push event (for projects set to on commit). A <strong className="text-foreground">Sync</strong> button on the overview triggers a new extraction with a short cooldown to avoid duplicate runs.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Project Overview Dashboard */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Project Overview Dashboard</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          The project overview screen provides a snapshot of your repository&rsquo;s security posture.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          {[
            { label: "Health Score", desc: "A 0\u2013100 score reflecting overall security health (vulnerabilities, compliance, supply-chain). Computed after extraction and policy evaluation." },
            { label: "Dependency Count", desc: "Total direct and transitive dependencies from the latest extraction." },
            { label: "Vulnerability Summary", desc: "Counts by severity (critical, high, medium, low) with links to the Security tab." },
            { label: "Live Extraction Status", desc: "Real-time extraction progress; Sync button to re-run with cooldown." },
            { label: "Action Items", desc: "Prioritized list of critical vulns, compliance issues, and code findings." },
            { label: "Recent Activity", desc: "Timeline of extraction runs, policy evaluations, status changes, and vuln events." },
          ].map((item) => (
            <div
              key={item.label}
              className="rounded-lg border border-border bg-background-card p-4"
            >
              <p className="text-sm font-medium text-foreground mb-1">{item.label}</p>
              <p className="text-xs text-foreground/90 leading-relaxed">{item.desc}</p>
            </div>
          ))}
        </div>
        <p className="text-foreground/90 leading-relaxed mt-4 text-sm">
          The overview may also show a mini dependency graph. Drill into the{" "}
          <Link to="/docs/dependencies" className="text-foreground underline hover:no-underline">Dependencies</Link>,{" "}
          <Link to="/docs/vulnerabilities" className="text-foreground underline hover:no-underline">Vulnerabilities</Link>, and{" "}
          <Link to="/docs/compliance" className="text-foreground underline hover:no-underline">Compliance</Link>{" "}
          tabs for detailed breakdowns.
        </p>
      </div>
    </div>
  );
}

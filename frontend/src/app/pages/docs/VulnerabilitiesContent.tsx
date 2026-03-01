import { Link } from "react-router-dom";

const depscoreExample = [
  {
    scenario: "Crown Jewels, reachable, CISA KEV, high EPSS",
    base: 75,
    threat: "1.5 × 1.3 = 1.95",
    environmental: "1.5 × 1.0 = 1.5",
    dependency: "1.0",
    final: "~100 (capped)",
  },
  {
    scenario: "Internal app, unreachable, low EPSS",
    base: 75,
    threat: "1.0",
    environmental: "1.0 × 0.4 = 0.4",
    dependency: "1.0",
    final: "30",
  },
  {
    scenario: "Non-prod, transitive, dev-only",
    base: 75,
    threat: "1.0",
    environmental: "0.6 × 1.0 = 0.6",
    dependency: "0.75 × 0.4 = 0.3",
    final: "14",
  },
];

const reachabilityTiers = [
  {
    tier: "Reachable",
    description: "Static analysis confirms the vulnerable function is called from your code.",
    multiplier: "1.0×",
  },
  {
    tier: "Potentially Reachable",
    description: "The vulnerable function is imported but the exact call path could not be confirmed.",
    multiplier: "0.8×",
  },
  {
    tier: "Unreachable",
    description: "No import chain or call path connects your code to the vulnerable function.",
    multiplier: "0.4×",
  },
  {
    tier: "Unknown",
    description: "Reachability analysis was not possible (e.g. unsupported language or dynamic import).",
    multiplier: "0.9×",
  },
];

const assetTierWeights = [
  { tier: "Crown Jewels", multiplier: "1.5×", description: "Business-critical systems handling sensitive data or revenue." },
  { tier: "External", multiplier: "1.2×", description: "Public-facing applications and APIs." },
  { tier: "Internal", multiplier: "1.0×", description: "Internal tools and services (baseline)." },
  { tier: "Non-Production", multiplier: "0.6×", description: "Development, staging, and test environments." },
];

export default function VulnerabilitiesContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex continuously monitors your <Link to="/docs/dependencies" className="text-primary hover:underline">dependencies</Link> for
            known vulnerabilities by correlating package versions against multiple advisory databases.
            When a project is scanned, Deptex runs <strong className="text-foreground">dep-scan</strong> to identify affected packages,
            then enriches each finding with data from the <strong className="text-foreground">OSV</strong> (Open Source Vulnerabilities)
            database and the <strong className="text-foreground">NVD</strong> (National Vulnerability Database).
          </p>
          <p>
            Raw CVE and advisory data is only the starting point. Deptex layers on exploit intelligence (EPSS, CISA KEV),
            static reachability analysis, and your organization&rsquo;s asset context to produce a single composite score
            &mdash; the <strong className="text-foreground">Depscore</strong> &mdash; that tells you how much risk a
            vulnerability actually poses to <em>your</em> environment, not just how severe it is in the abstract.
          </p>
          <p>
            Vulnerabilities are surfaced in the project&rsquo;s Vulnerabilities tab, in organization-wide dashboards, and
            through <Link to="/docs/notification-rules" className="text-primary hover:underline">notification rules</Link> and{" "}
            <Link to="/docs/policies" className="text-primary hover:underline">policy checks</Link> you configure.
          </p>
        </div>
      </div>

      {/* Depscore */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Depscore</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            The Depscore is a composite risk score (0&ndash;100) that contextualizes vulnerability severity for your specific
            environment. Instead of relying on CVSS alone, it combines four multipliers so that the same CVE can score
            very differently depending on where and how the affected dependency is used.
          </p>
          <p>The formula:</p>
        </div>
        <pre className="rounded-lg border border-border bg-background-card p-4 text-sm text-foreground overflow-x-auto font-mono mt-3">
{`depscore = baseImpact × threatMultiplier × environmentalMultiplier × dependencyContextMultiplier`}
        </pre>

        <div className="mt-6 space-y-6">
          {/* Base Impact */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-background-card-header">
              <h3 className="text-sm font-semibold text-foreground">Base Impact</h3>
            </div>
            <div className="p-4 text-sm text-foreground-secondary leading-relaxed">
              The CVSS v3 base score (0&ndash;10) is normalized to a 0&ndash;100 scale.
              A CVSS of 7.5 becomes a base impact of 75.
            </div>
          </div>

          {/* Threat Multiplier */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-background-card-header">
              <h3 className="text-sm font-semibold text-foreground">Threat Multiplier</h3>
            </div>
            <div className="p-4 space-y-2 text-sm text-foreground-secondary leading-relaxed">
              <p>
                <strong className="text-foreground">EPSS probability boost</strong> &mdash; scales from{" "}
                <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">1.0×</code> to{" "}
                <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">1.5×</code> based
                on the EPSS probability. Higher exploitation likelihood increases the multiplier.
              </p>
              <p>
                <strong className="text-foreground">CISA KEV boost</strong> &mdash; if the CVE appears in CISA&rsquo;s Known Exploited
                Vulnerabilities catalog, a flat{" "}
                <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">1.3×</code> multiplier is applied.
              </p>
              <p>Both boosts are multiplicative, so a high-EPSS KEV entry can reach up to ~1.95×.</p>
            </div>
          </div>

          {/* Environmental Multiplier */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-background-card-header">
              <h3 className="text-sm font-semibold text-foreground">Environmental Multiplier</h3>
            </div>
            <div className="p-4 space-y-3 text-sm text-foreground-secondary leading-relaxed">
              <p>
                Combines the project&rsquo;s <strong className="text-foreground">asset tier</strong> weight with
                the <strong className="text-foreground">reachability</strong> multiplier.
              </p>
              <div className="rounded-lg border border-border bg-background-card overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-background-card-header border-b border-border">
                    <tr>
                      <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Asset Tier</th>
                      <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-24">Weight</th>
                      <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {assetTierWeights.map((t) => (
                      <tr key={t.tier} className="hover:bg-table-hover transition-colors">
                        <td className="px-4 py-2.5 text-sm font-medium text-foreground">{t.tier}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-foreground">{t.multiplier}</td>
                        <td className="px-4 py-2.5 text-sm text-foreground-secondary">{t.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p>
                Reachability further adjusts the environmental score. An unreachable vulnerability on a Crown Jewels
                project scores{" "}
                <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">1.5 × 0.4 = 0.6×</code>,
                significantly reducing the final Depscore.
              </p>
            </div>
          </div>

          {/* Dependency Context Multiplier */}
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-background-card-header">
              <h3 className="text-sm font-semibold text-foreground">Dependency Context Multiplier</h3>
            </div>
            <div className="p-4 space-y-2 text-sm text-foreground-secondary leading-relaxed">
              <p>
                <strong className="text-foreground">Directness</strong> &mdash; transitive dependencies apply a{" "}
                <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">0.75×</code> factor.
                Direct dependencies use <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">1.0×</code>.
              </p>
              <p>
                <strong className="text-foreground">Environment</strong> &mdash; dev-only dependencies apply{" "}
                <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">0.4×</code> since
                they don&rsquo;t ship to production.
              </p>
              <p>
                <strong className="text-foreground">Malicious package</strong> &mdash; if the package is flagged as
                malicious, a <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">1.3×</code> boost
                is applied regardless of other context.
              </p>
            </div>
          </div>
        </div>

        {/* Depscore Example */}
        <div className="mt-6">
          <h3 className="text-sm font-semibold text-foreground mb-3">Example: CVE with CVSS 7.5 across different contexts</h3>
          <div className="rounded-lg border border-border bg-background-card overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-background-card-header border-b border-border">
                <tr>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Scenario</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Base</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Threat</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Env.</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Dep.</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Depscore</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {depscoreExample.map((row) => (
                  <tr key={row.scenario} className="hover:bg-table-hover transition-colors">
                    <td className="px-4 py-2.5 text-sm text-foreground">{row.scenario}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-foreground-secondary">{row.base}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-foreground-secondary">{row.threat}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-foreground-secondary">{row.environmental}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-foreground-secondary">{row.dependency}</td>
                    <td className="px-4 py-2.5 font-mono text-xs font-semibold text-foreground">{row.final}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-sm text-foreground-secondary leading-relaxed mt-2">
            The same CVSS 7.5 vulnerability ranges from a Depscore of 14 to 100 depending on context.
            This is why Depscore is a better prioritization signal than raw CVSS.
          </p>
        </div>
      </div>

      {/* Reachability Analysis */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Reachability Analysis</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed mb-4">
          <p>
            Not every vulnerability in your dependency tree is exploitable. Deptex performs static analysis on your
            project&rsquo;s source code to determine whether the vulnerable code paths in a dependency are actually
            invoked. This dramatically reduces noise &mdash; in practice, a large percentage of flagged CVEs turn
            out to be unreachable.
          </p>
          <p>
            The analysis traces import chains and function call graphs from your application entry points through to the
            specific functions identified in the vulnerability advisory. Results are classified into four tiers:
          </p>
        </div>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[180px]">Tier</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[100px]">Multiplier</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {reachabilityTiers.map((t) => (
                <tr key={t.tier} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-2.5 text-sm font-medium text-foreground">{t.tier}</td>
                  <td className="px-4 py-2.5 text-sm text-foreground-secondary">{t.description}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-foreground">{t.multiplier}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-sm text-foreground-secondary leading-relaxed mt-3">
          Reachability results feed directly into the Depscore environmental multiplier and are displayed in the
          vulnerability detail sidebar alongside the traced call path when available.
        </p>
      </div>

      {/* EPSS Scoring */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">EPSS Scoring</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            The <strong className="text-foreground">Exploit Prediction Scoring System (EPSS)</strong> estimates the
            probability that a vulnerability will be exploited in the wild within the next 30 days. Unlike CVSS, which
            measures theoretical severity, EPSS uses real-world threat intelligence, exploit code availability, and
            observed attack patterns to produce a probability between 0.0 and 1.0.
          </p>
          <p>
            Deptex fetches EPSS data daily and uses it as a component of the Depscore threat multiplier. A vulnerability
            with a CVSS of 9.8 but an EPSS of 0.01 (1% exploitation probability) will score lower than one with a CVSS
            of 7.0 and an EPSS of 0.85. This helps you focus remediation effort on vulnerabilities that are actually
            being targeted, not just those with high theoretical impact.
          </p>
        </div>
      </div>

      {/* CISA KEV */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">CISA KEV</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            The <strong className="text-foreground">CISA Known Exploited Vulnerabilities (KEV)</strong> catalog is
            maintained by the U.S. Cybersecurity and Infrastructure Security Agency. It lists CVEs that have confirmed,
            active exploitation in the wild. Inclusion in KEV is one of the strongest signals that a vulnerability
            requires immediate attention.
          </p>
          <p>
            Deptex checks every discovered vulnerability against the KEV catalog. KEV entries receive a flat 1.3×
            boost in the Depscore threat multiplier and are flagged in the UI with a distinct badge. You can also
            write <Link to="/docs/policies" className="text-primary hover:underline">policy rules</Link> that specifically
            block or alert on KEV-listed CVEs.
          </p>
        </div>
      </div>

      {/* Vulnerability Detail Sidebar */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Vulnerability Detail Sidebar</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground-secondary leading-relaxed">
            Clicking a vulnerability row opens a detail sidebar with everything Deptex knows about that finding:
          </p>
          <ul className="space-y-2 text-sm text-foreground-secondary">
            <li className="flex gap-2">
              <span className="text-primary shrink-0 mt-1.5 size-1.5 rounded-full bg-primary" aria-hidden />
              <span><strong className="text-foreground">Advisory info</strong> &mdash; OSV/GHSA ID, CVE aliases, severity, CVSS score, and published date.</span>
            </li>
            <li className="flex gap-2">
              <span className="text-primary shrink-0 mt-1.5 size-1.5 rounded-full bg-primary" aria-hidden />
              <span><strong className="text-foreground">Affected &amp; fixed versions</strong> &mdash; which version ranges are affected and which versions contain a fix.</span>
            </li>
            <li className="flex gap-2">
              <span className="text-primary shrink-0 mt-1.5 size-1.5 rounded-full bg-primary" aria-hidden />
              <span><strong className="text-foreground">Reachability path</strong> &mdash; the traced call chain from your code to the vulnerable function, when available.</span>
            </li>
            <li className="flex gap-2">
              <span className="text-primary shrink-0 mt-1.5 size-1.5 rounded-full bg-primary" aria-hidden />
              <span><strong className="text-foreground">Depscore breakdown</strong> &mdash; visual breakdown of each multiplier that contributed to the final score.</span>
            </li>
            <li className="flex gap-2">
              <span className="text-primary shrink-0 mt-1.5 size-1.5 rounded-full bg-primary" aria-hidden />
              <span><strong className="text-foreground">EPSS &amp; KEV status</strong> &mdash; current EPSS probability and whether the CVE is in the CISA KEV catalog.</span>
            </li>
            <li className="flex gap-2">
              <span className="text-primary shrink-0 mt-1.5 size-1.5 rounded-full bg-primary" aria-hidden />
              <span><strong className="text-foreground">Affected code locations</strong> &mdash; files in your project that import or use the vulnerable package.</span>
            </li>
          </ul>
        </div>
      </div>

      {/* AI-Powered Fixing */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">AI-Powered Fixing</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex integrates with <strong className="text-foreground">Aider</strong>, an AI coding assistant, to
            generate automated fix patches for vulnerabilities. When you trigger a fix from the vulnerability detail
            sidebar, Deptex clones the affected repository, identifies the vulnerable dependency and its usage in your
            code, and hands the context to Aider for patch generation.
          </p>
          <p>
            Aider analyzes the vulnerability advisory, the affected code paths, and the available fix versions to produce
            a targeted patch. This may be a version bump in your lockfile, a code change to work around the vulnerability,
            or both. The generated patch is submitted as a pull request to your repository for human review.
          </p>
          <p>
            Safety measures are built in: Aider operates in a sandboxed clone, never pushes directly to protected branches,
            and every generated PR includes a summary of what was changed and why. You retain full control over whether
            to merge. The fix can also be configured to run through your CI pipeline before review.
          </p>
        </div>
      </div>

      {/* Background Monitoring */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Background Monitoring</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex doesn&rsquo;t only scan at import time. It periodically rechecks your projects against the latest
            advisory databases to catch newly disclosed vulnerabilities affecting packages you already use. The check
            frequency depends on your plan, with Pro and Enterprise tiers receiving near-real-time updates.
          </p>
          <p>
            When a new vulnerability is discovered during a background check, it appears in your project&rsquo;s
            Vulnerabilities tab and triggers any matching{" "}
            <Link to="/docs/notification-rules" className="text-primary hover:underline">notification rules</Link>.
            If you have Aegis enabled, it can also automatically begin remediation analysis.
          </p>
        </div>
      </div>

      {/* Version Management */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Version Management</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            For each vulnerable dependency, Deptex shows <strong className="text-foreground">safer versions</strong> &mdash;
            the nearest version that resolves the vulnerability without introducing breaking changes when possible.
            The <Link to="/docs/dependencies" className="text-primary hover:underline">Dependencies</Link> tab
            also displays a <strong className="text-foreground">versions behind</strong> count so you can see at a
            glance how far each package has drifted from its latest release.
          </p>
          <p>
            When multiple vulnerabilities affect the same package, Deptex calculates the minimum version that resolves
            all of them. This avoids the &ldquo;whack-a-mole&rdquo; pattern of upgrading for one CVE only to find
            another still applies. Version recommendations respect your declared semver constraints where available.
          </p>
        </div>
      </div>
    </div>
  );
}

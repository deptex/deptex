import { Link } from "react-router-dom";

const reachabilityTiers = [
  { tier: "Data flow", description: "Data-flow analysis shows the vulnerable sink is reachable from your code." },
  { tier: "Function", description: "The vulnerable function is imported and callable." },
  { tier: "Module", description: "The package is imported but the vulnerable function was not traced." },
  { tier: "Unreachable", description: "No import chain connects your code to the vulnerable function." },
];

export default function VulnerabilitiesContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            Deptex monitors your <Link to="/docs/dependencies" className="text-foreground underline hover:no-underline">dependencies</Link> for
            known vulnerabilities by correlating package versions against advisory databases. When a project is scanned,
            Deptex identifies affected packages and enriches each finding with severity, exploit intelligence, and
            reachability analysis.
          </p>
          <p>
            Raw CVE data is only the starting point. Deptex layers on EPSS (exploit probability), CISA KEV (known exploited),
            reachability analysis, and your asset context to produce the <strong className="text-foreground">Depscore</strong> —
            a composite risk score (0–100) that tells you how much risk a vulnerability actually poses to your environment.
          </p>
          <p>
            Vulnerabilities appear in the Security tab, organization dashboards, and through notification rules and policy checks.
          </p>
        </div>
      </div>

      {/* Depscore */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Depscore</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            The Depscore contextualizes vulnerability severity for your environment. It combines CVSS base impact with
            threat factors (EPSS probability, CISA KEV), your project&rsquo;s asset tier (Crown Jewels, External, Internal, Non-Production),
            and reachability (whether the vulnerable code is actually used). Transitive and dev-only dependencies carry reduced weight.
          </p>
          <p>
            The same CVE can score very differently depending on context — an unreachable vuln on a non-prod dev dependency
            scores much lower than a reachable KEV-listed vuln on a Crown Jewels project. Depscore helps you prioritize
            remediation on what matters.
          </p>
        </div>
      </div>

      {/* Reachability Analysis */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Reachability Analysis</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed mb-4">
          <p>
            Not every vulnerability in your dependency tree is exploitable. Deptex performs code-level reachability
            analysis to determine whether vulnerable code paths are actually invoked. Unreachable vulnerabilities
            receive a much lower Depscore. The Security tab lets you filter by reachability level.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[140px]">Level</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {reachabilityTiers.map((t) => (
                <tr key={t.tier} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-2.5 text-sm font-medium text-foreground">{t.tier}</td>
                  <td className="px-4 py-2.5 text-sm text-foreground/90">{t.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* EPSS and CISA KEV */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">EPSS and CISA KEV</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            <strong className="text-foreground">EPSS</strong> (Exploit Prediction Scoring System) estimates the probability
            that a vulnerability will be exploited in the next 30 days. Unlike CVSS (theoretical severity), EPSS uses
            real-world threat intelligence. A high-CVSS vuln with low EPSS scores lower than a medium-CVSS vuln with high EPSS.
          </p>
          <p>
            <strong className="text-foreground">CISA KEV</strong> lists CVEs with confirmed active exploitation. KEV entries
            are flagged in the UI and receive higher Depscore. You can write{" "}
            <Link to="/docs/policies" className="text-foreground underline hover:no-underline">policy rules</Link> to block or alert on KEV-listed CVEs.
          </p>
        </div>
      </div>

      {/* Vulnerability Detail */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Vulnerability Detail</h2>
        <p className="text-foreground/90 leading-relaxed mb-3">
          Clicking a vulnerability opens a detail sidebar with advisory info (CVE, severity, CVSS), reachability badge,
          affected and fixed versions, Depscore breakdown, EPSS and KEV status, and affected code locations. When
          reachability data is available, the Code Impact view shows the traced path.
        </p>
      </div>

      {/* AI-Powered Fixing */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">AI-Powered Fixing</h2>
        <p className="text-foreground/90 leading-relaxed">
          Deptex can generate automated fix patches for vulnerabilities. When you trigger a fix from the vulnerability
          detail sidebar, Deptex clones the repo, identifies the vulnerable dependency and its usage, and produces a
          targeted patch (version bump, code change, or both). The fix is submitted as a pull request for human review.
          Every generated PR includes a summary of changes. You retain full control over whether to merge.
        </p>
      </div>

      {/* Background Monitoring */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Background Monitoring</h2>
        <p className="text-foreground/90 leading-relaxed">
          Deptex periodically rechecks your projects against the latest advisory databases to catch newly disclosed
          vulnerabilities. When a new vuln is discovered, it appears in the Security tab and triggers matching
          notification rules. Aegis can also begin remediation analysis automatically.
        </p>
      </div>

      {/* Version Management */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Version Management</h2>
        <p className="text-foreground/90 leading-relaxed">
          For each vulnerable dependency, Deptex shows <strong className="text-foreground">safer versions</strong> —
          the nearest version that resolves the vulnerability without breaking changes when possible. When multiple
          vulns affect the same package, Deptex calculates the minimum version that resolves all of them. The{" "}
          <Link to="/docs/dependencies" className="text-foreground underline hover:no-underline">Dependencies</Link> tab
          shows how many versions behind each package is.
        </p>
      </div>
    </div>
  );
}

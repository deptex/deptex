import { Link } from "react-router-dom";

const scoreWeights = [
  { signal: "OpenSSF Scorecard", weight: "40%", description: "Project health: CI tests, code review, branch protection, signed releases." },
  { signal: "Popularity / Weekly Downloads", weight: "30%", description: "Registry download volume as a proxy for community adoption and trust." },
  { signal: "Maintenance / Release Cadence", weight: "30%", description: "Number of releases in the past 12 months and recency of last publish." },
];

const scoreMultipliers = [
  { multiplier: "SLSA Bonus", condition: "SLSA level > 1", effect: "1.05\u20131.1\u00d7", description: "Packages with verified build provenance receive a small score boost." },
  { multiplier: "Malicious Penalty", condition: "Flagged as malicious", effect: "0.1\u00d7", description: "Known-malicious packages are suppressed to near-zero." },
  { multiplier: "Transitive Discount", condition: "Transitive dependency", effect: "0.75\u00d7", description: "Indirect dependencies carry reduced weight since you don\u2019t control them directly." },
  { multiplier: "Dev-only Discount", condition: "environment = development", effect: "0.4\u00d7", description: "Dev dependencies never reach production, so their risk contribution is lower." },
];

const supplyChainSignals = [
  { signal: "Registry Integrity", field: "registry_integrity_status", pass: "Tarball hash matches registry metadata.", warning: "Minor metadata inconsistency detected.", fail: "Hash mismatch \u2014 package may have been tampered with." },
  { signal: "Install Scripts", field: "install_scripts_status", pass: "No pre/post-install scripts, or scripts are benign.", warning: "Install scripts present but not obviously malicious.", fail: "Suspicious install scripts detected (e.g. network calls, file writes outside node_modules)." },
  { signal: "Entropy / Obfuscation", field: "entropy_analysis_status", pass: "Source code has normal entropy.", warning: "Elevated entropy in some files.", fail: "Highly obfuscated code detected \u2014 common in malicious packages." },
];

const slsaLevels = [
  { level: "0", name: "No provenance", description: "No build provenance information available." },
  { level: "1", name: "Documentation", description: "Build process is documented but not verified." },
  { level: "2", name: "Build service", description: "Built by a hosted build service with generated provenance." },
  { level: "3", name: "Hardened builds", description: "Tamper-resistant build platform with non-falsifiable provenance." },
  { level: "4", name: "Full attestation", description: "Two-party review and hermetic, reproducible builds." },
];

export default function DependenciesContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex discovers dependencies by parsing <strong className="text-foreground">manifest files</strong> (e.g.{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">package.json</code>,{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">requirements.txt</code>,{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">go.mod</code>) and{" "}
            <strong className="text-foreground">lockfiles</strong> (e.g.{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">package-lock.json</code>,{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">yarn.lock</code>).
            Lockfiles provide the full resolved dependency tree including transitive dependencies and exact versions.
          </p>
          <p>
            After extraction, each dependency is enriched with registry metadata, OpenSSF Scorecard data, supply-chain analysis signals, and vulnerability advisories.
            The result is a scored, categorized inventory of every package your project depends on.
          </p>
        </div>
      </div>

      {/* Dependency Score */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Dependency Score</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Each dependency receives a reputation score from 0 to 100 (higher is better). The base score is a weighted blend of three signals, then adjusted by multipliers for provenance and risk factors.
        </p>

        <div className="rounded-lg border border-border bg-background-card overflow-hidden mb-6">
          <div className="px-4 py-3 border-b border-border bg-background-card-header">
            <h3 className="text-sm font-semibold text-foreground">Base Score Weights</h3>
          </div>
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Signal</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-24">Weight</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {scoreWeights.map((row) => (
                <tr key={row.signal} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3 text-sm font-medium text-foreground">{row.signal}</td>
                  <td className="px-4 py-3 text-sm font-mono text-foreground">{row.weight}</td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{row.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-background-card-header">
            <h3 className="text-sm font-semibold text-foreground">Score Multipliers</h3>
          </div>
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Multiplier</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Condition</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-24">Effect</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {scoreMultipliers.map((row) => (
                <tr key={row.multiplier} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3 text-sm font-medium text-foreground">{row.multiplier}</td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{row.condition}</td>
                  <td className="px-4 py-3 text-sm font-mono text-foreground">{row.effect}</td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{row.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Direct vs Transitive */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Direct vs Transitive Dependencies</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            <strong className="text-foreground">Direct</strong> dependencies are packages explicitly declared in your manifest file.{" "}
            <strong className="text-foreground">Transitive</strong> dependencies are pulled in by your direct dependencies (or their dependencies, recursively).
          </p>
          <p>
            Deptex determines this from the lockfile&rsquo;s dependency graph. The distinction matters for risk assessment:
            transitive dependencies receive a <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">0.75&times;</code> multiplier
            in the Dependency Score because you have less direct control over them, but they still represent real supply-chain surface area.
          </p>
          <p>
            The Dependencies tab marks each entry as <strong className="text-foreground">Direct</strong> or <strong className="text-foreground">Transitive</strong> and
            lets you filter by type to focus remediation on the packages you control.
          </p>
        </div>
      </div>

      {/* Dev vs Production */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Dev vs Production Dependencies</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex reads the <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">devDependencies</code> vs{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">dependencies</code> distinction
            from your manifest (or equivalent markers in other ecosystems). Packages used only during development, testing, or build time are tagged as{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">development</code>.
          </p>
          <p>
            Dev-only dependencies carry a <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">0.4&times;</code> weight
            in the Dependency Score because they never ship to end users and therefore present a narrower attack surface.
            They still appear in the dependency list and SBOM exports, but their contribution to the project&rsquo;s overall health score is reduced.
          </p>
        </div>
      </div>

      {/* Supply Chain Signals */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Supply Chain Signals</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Deptex runs three automated analyses on every dependency to detect supply-chain compromise. Each returns a status of{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pass</code>,{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">warning</code>, or{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">fail</code>.
        </p>

        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Signal</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Pass</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Warning</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Fail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {supplyChainSignals.map((row) => (
                <tr key={row.signal} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3 text-sm font-medium text-foreground">
                    {row.signal}
                    <div className="font-mono text-xs text-foreground-secondary mt-0.5">{row.field}</div>
                  </td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{row.pass}</td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{row.warning}</td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{row.fail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <p className="text-foreground-secondary leading-relaxed mt-3 text-sm">
          These signals are available in{" "}
          <Link to="/docs/policies" className="text-primary hover:underline">policy code</Link>{" "}
          and{" "}
          <Link to="/docs/notification-rules" className="text-primary hover:underline">notification rules</Link>{" "}
          for automated enforcement.
        </p>
      </div>

      {/* Malicious Package Detection */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Malicious Package Detection</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex cross-references every dependency against known-malicious package databases (including OSV, Phylum, and Socket advisories).
            When a match is found, the dependency is flagged and its score receives the{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">0.1&times;</code> malicious penalty.
          </p>
          <p>
            Flagged packages include a <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">malicious_indicator</code> object with three fields:
          </p>
        </div>

        <div className="rounded-lg border border-border bg-background-card overflow-hidden mt-4">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[140px]">Field</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[100px]">Type</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">source</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary">string</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">The advisory database that reported the package (e.g. &ldquo;osv&rdquo;, &ldquo;phylum&rdquo;).</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">confidence</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary">number</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">Confidence score from 0 to 1. Values above 0.8 indicate a high-confidence match.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">reason</td>
                <td className="px-4 py-3 font-mono text-xs text-foreground-secondary">string</td>
                <td className="px-4 py-3 text-sm text-foreground-secondary">Human-readable explanation of why the package was flagged (e.g. &ldquo;known typosquat of lodash&rdquo;).</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* SLSA Provenance */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">SLSA Provenance</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed mb-4">
          <p>
            <strong className="text-foreground">SLSA</strong> (Supply-chain Levels for Software Artifacts) is a framework for ensuring the integrity of software artifacts.
            Deptex checks published provenance attestations and assigns a SLSA level to each dependency.
          </p>
          <p>
            Packages at SLSA level 2 or higher receive a score bonus (1.05&ndash;1.1&times;) because their build process is verified and harder to tamper with.
          </p>
        </div>

        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-20">Level</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[180px]">Name</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {slsaLevels.map((row) => (
                <tr key={row.level} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3 text-sm font-mono text-foreground">{row.level}</td>
                  <td className="px-4 py-3 text-sm font-medium text-foreground">{row.name}</td>
                  <td className="px-4 py-3 text-sm text-foreground-secondary">{row.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Version Management */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Version Management</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex tracks the installed version of every dependency against the latest published version in the registry.
            When a newer version is available, the dependency is marked as <strong className="text-foreground">outdated</strong> and
            the <strong className="text-foreground">versions behind</strong> count shows how many releases you&rsquo;re behind.
          </p>
          <p>
            For each outdated dependency, Deptex identifies the <strong className="text-foreground">safe upgrade target</strong> &mdash;
            the latest version that satisfies your declared semver range and resolves known vulnerabilities where possible.
            This avoids recommending major-version jumps that could introduce breaking changes.
          </p>
          <p>
            Version data feeds into the project health score: projects with many outdated dependencies trend lower,
            and vulnerabilities with available fixes are prioritized higher in the{" "}
            <Link to="/docs/vulnerabilities" className="text-primary hover:underline">Vulnerabilities</Link> tab.
          </p>
        </div>
      </div>
    </div>
  );
}

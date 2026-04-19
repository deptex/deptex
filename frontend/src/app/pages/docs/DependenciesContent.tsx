import { Link } from "react-router-dom";

const supplyChainSignals = [
  { signal: "Registry Integrity", pass: "Tarball hash matches registry metadata.", warning: "Minor metadata inconsistency detected.", fail: "Hash mismatch — package may have been tampered with." },
  { signal: "Install Scripts", pass: "No pre/post-install scripts, or scripts are benign.", warning: "Install scripts present but not obviously malicious.", fail: "Suspicious install scripts detected." },
  { signal: "Entropy / Obfuscation", pass: "Source code has normal entropy.", warning: "Elevated entropy in some files.", fail: "Highly obfuscated code detected — common in malicious packages." },
];

export default function DependenciesContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
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
            After extraction, each dependency is enriched with registry metadata, OpenSSF Scorecard data, supply-chain analysis, and vulnerability advisories.
          </p>
        </div>
      </div>

      {/* Dependency Score */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Dependency Score</h2>
        <p className="text-foreground/90 leading-relaxed">
          Each dependency receives a reputation score from 0 to 100 (higher is better). The score blends OpenSSF Scorecard (project health), popularity/downloads, and maintenance/release cadence. It is then adjusted: packages with SLSA provenance get a small bonus; malicious packages are suppressed; transitive and dev-only dependencies carry reduced weight since you have less control over them.
        </p>
      </div>

      {/* Direct vs Transitive */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Direct vs Transitive Dependencies</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            <strong className="text-foreground">Direct</strong> dependencies are packages explicitly declared in your manifest.{" "}
            <strong className="text-foreground">Transitive</strong> dependencies are pulled in by your direct dependencies (or their dependencies, recursively).
          </p>
          <p>
            The Dependencies tab marks each entry as Direct or Transitive and lets you filter by type to focus remediation on the packages you control.
          </p>
        </div>
      </div>

      {/* Dev vs Production */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Dev vs Production Dependencies</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            Deptex reads the <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">devDependencies</code> vs{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">dependencies</code> distinction
            from your manifest. Dev-only packages carry reduced weight in scoring because they never ship to production.
          </p>
        </div>
      </div>

      {/* Supply Chain Signals */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Supply Chain Signals</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          Deptex runs three automated analyses on every dependency to detect supply-chain compromise. Each returns pass, warning, or fail.
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
                  <td className="px-4 py-3 text-sm font-medium text-foreground">{row.signal}</td>
                  <td className="px-4 py-3 text-sm text-foreground/90">{row.pass}</td>
                  <td className="px-4 py-3 text-sm text-foreground/90">{row.warning}</td>
                  <td className="px-4 py-3 text-sm text-foreground/90">{row.fail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Malicious Package Detection */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Malicious Package Detection</h2>
        <p className="text-foreground/90 leading-relaxed">
          Deptex cross-references every dependency against known-malicious package databases. When a match is found, the dependency is flagged and its score is suppressed. Flagged packages show the source and reason in the UI.
        </p>
      </div>

      {/* SLSA Provenance */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">SLSA Provenance</h2>
        <p className="text-foreground/90 leading-relaxed">
          <strong className="text-foreground">SLSA</strong> (Supply-chain Levels for Software Artifacts) verifies build integrity. Deptex checks published provenance attestations and assigns a level (0–4) to each dependency. Packages at level 2 or higher receive a score bonus because their build process is verified.
        </p>
      </div>

      {/* Version Management */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Version Management</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            Deptex tracks the installed version of every dependency against the latest in the registry. When a newer version is available, the dependency is marked as <strong className="text-foreground">outdated</strong> and the <strong className="text-foreground">versions behind</strong> count shows how many releases you&rsquo;re behind.
          </p>
          <p>
            For each outdated dependency, Deptex identifies the <strong className="text-foreground">safe upgrade target</strong> — the latest version that satisfies your semver range and resolves known vulnerabilities where possible, avoiding major-version jumps that could introduce breaking changes.
          </p>
          <p>
            Version data feeds into the project health score and the{" "}
            <Link to="/docs/vulnerabilities" className="text-foreground underline hover:no-underline">Vulnerabilities</Link> tab prioritizes fixes when available.
          </p>
        </div>
      </div>
    </div>
  );
}

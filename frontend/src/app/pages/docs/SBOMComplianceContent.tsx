import { Link } from "react-router-dom";

const ecosystems = [
  { name: "npm / Node.js", files: "package.json, package-lock.json, yarn.lock, pnpm-lock.yaml" },
  { name: "pip / PyPI", files: "requirements.txt, pyproject.toml, Pipfile.lock" },
  { name: "Go Modules", files: "go.mod, go.sum" },
  { name: "Maven / Gradle", files: "pom.xml, build.gradle" },
  { name: "Cargo", files: "Cargo.toml, Cargo.lock" },
  { name: "Bundler", files: "Gemfile, Gemfile.lock" },
  { name: "NuGet", files: "*.csproj, packages.config" },
  { name: "Composer", files: "composer.json, composer.lock" },
  { name: "pub", files: "pubspec.yaml, pubspec.lock" },
];

export default function SBOMComplianceContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            A <strong className="text-foreground">Software Bill of Materials (SBOM)</strong> is a complete, machine-readable
            inventory of every component in your software — packages, versions, licenses, and dependency relationships.
            It helps you assess risk, meet compliance requirements, and respond quickly when new vulnerabilities are disclosed.
          </p>
          <p>
            Deptex generates an SBOM for every extraction run. Download in CycloneDX or SPDX format from the project&rsquo;s{" "}
            <strong className="text-foreground">Compliance</strong> tab.
          </p>
        </div>
      </div>

      {/* SBOM Generation */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">SBOM Generation</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          During extraction, Deptex analyzes your repository to produce a CycloneDX SBOM. It resolves manifest and lock
          files, identifies direct and transitive dependencies, and records license and package URL metadata for each component.
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-background-card-header">
            <h3 className="text-sm font-semibold text-foreground">Supported Ecosystems</h3>
          </div>
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Ecosystem</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Manifest / Lock Files</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {ecosystems.map((eco) => (
                <tr key={eco.name} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-2.5 text-sm font-medium text-foreground">{eco.name}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-foreground/90">{eco.files}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Formats */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Formats</h2>
        <div className="space-y-4 text-foreground/90 leading-relaxed">
          <p>
            <strong className="text-foreground">CycloneDX JSON</strong> — Full component inventory with dependency graph,
            package URLs, and license data. Recommended for security tooling and automation.
          </p>
          <p>
            <strong className="text-foreground">SPDX</strong> — License-focused format for procurement, legal review, and
            audit workflows. Converted from CycloneDX on demand. Both formats describe the same component set.
          </p>
        </div>
      </div>

      {/* Storage and Access */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Storage and Access</h2>
        <p className="text-foreground/90 leading-relaxed">
          SBOMs are stored per project and per extraction run. Each new extraction produces a fresh SBOM; previous runs
          are retained so you can compare over time. Access is scoped to the organization — only authenticated members
          with project visibility can download SBOM files.
        </p>
      </div>

      {/* Legal Notice */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Legal Notice</h2>
        <p className="text-foreground/90 leading-relaxed">
          Deptex can generate <strong className="text-foreground">notice files</strong> from SBOM data — a plain-text
          file listing every third-party component with its license text. Use it to satisfy attribution requirements
          when distributing your software. Available from the Compliance tab alongside SBOM downloads.
        </p>
      </div>

      {/* Compliance Frameworks */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Compliance Frameworks</h2>
        <p className="text-foreground/90 leading-relaxed">
          Deptex SBOMs are designed to satisfy major frameworks: U.S. EO 14028 (federal software), NTIA Minimum Elements,
          and EU Cyber Resilience Act. Use <Link to="/docs/policies" className="text-foreground underline hover:no-underline">Policies</Link> to
          enforce organization-specific rules on top of these baselines.
        </p>
      </div>
    </div>
  );
}

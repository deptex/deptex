import { Link } from "react-router-dom";

const ecosystems = [
  { name: "npm / Node.js", files: "package.json, package-lock.json, yarn.lock, pnpm-lock.yaml", language: "JavaScript / TypeScript" },
  { name: "pip / PyPI", files: "requirements.txt, setup.py, pyproject.toml, Pipfile.lock", language: "Python" },
  { name: "Go Modules", files: "go.mod, go.sum", language: "Go" },
  { name: "Maven / Gradle", files: "pom.xml, build.gradle, build.gradle.kts", language: "Java / Kotlin" },
  { name: "Cargo", files: "Cargo.toml, Cargo.lock", language: "Rust" },
  { name: "Bundler", files: "Gemfile, Gemfile.lock", language: "Ruby" },
  { name: "NuGet", files: "*.csproj, packages.config, Directory.Packages.props", language: "C# / .NET" },
  { name: "Composer", files: "composer.json, composer.lock", language: "PHP" },
  { name: "CocoaPods", files: "Podfile, Podfile.lock", language: "Swift / Objective-C" },
  { name: "pub", files: "pubspec.yaml, pubspec.lock", language: "Dart / Flutter" },
];

const complianceFrameworks = [
  { framework: "EO 14028", description: "U.S. Executive Order on Improving the Nation\u2019s Cybersecurity \u2014 requires SBOM delivery for software sold to federal agencies." },
  { framework: "NTIA Minimum Elements", description: "Defines the minimum fields an SBOM must contain: supplier, component name, version, unique identifier, dependency relationship, author, and timestamp." },
  { framework: "EU Cyber Resilience Act (CRA)", description: "Mandates vulnerability handling and SBOM requirements for products with digital elements sold in the EU." },
];

export default function SBOMComplianceContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            A <strong className="text-foreground">Software Bill of Materials (SBOM)</strong> is a
            complete, machine-readable inventory of every component in your software. It lists
            packages, versions, licenses, and dependency relationships so that your organization
            can assess risk, meet compliance requirements, and respond quickly when new
            vulnerabilities are disclosed.
          </p>
          <p>
            Deptex generates an SBOM for every extraction run and stores it alongside the
            dependency data. You can download SBOMs in CycloneDX or SPDX format at any time
            from the project&rsquo;s <strong className="text-foreground">Compliance</strong> tab.
          </p>
        </div>
      </div>

      {/* SBOM Generation */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">SBOM Generation</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed mb-4">
          <p>
            During extraction, Deptex uses{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">cdxgen</code>{" "}
            to analyze your repository and produce a CycloneDX SBOM. The tool resolves
            manifest and lock files, identifies direct and transitive dependencies, and
            records license and purl (package URL) metadata for each component.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-background-card-header">
            <h3 className="text-sm font-semibold text-foreground">Supported Ecosystems</h3>
          </div>
          <table className="w-full text-sm">
            <thead className="border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Ecosystem</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Manifest / Lock Files</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Language</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {ecosystems.map((eco) => (
                <tr key={eco.name} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-2.5 text-sm font-medium text-foreground">{eco.name}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-foreground-secondary">{eco.files}</td>
                  <td className="px-4 py-2.5 text-sm text-foreground-secondary">{eco.language}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* CycloneDX Format */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">CycloneDX Format</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex generates SBOMs in{" "}
            <strong className="text-foreground">CycloneDX 1.5</strong> (JSON). Each SBOM includes
            the component inventory, dependency graph, license declarations, package URLs (purls),
            and metadata about the tool and extraction run that produced it.
          </p>
          <p>
            CycloneDX is the recommended format for most use cases. It is supported by a wide
            range of security tools and is the native output of{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">cdxgen</code>.
          </p>
        </div>
      </div>

      {/* SPDX Format */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">SPDX Format</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex also supports export in <strong className="text-foreground">SPDX</strong> format,
            which is widely used in legal and license-compliance workflows. SPDX SBOMs emphasize
            license metadata and are accepted by many procurement and audit tools.
          </p>
          <p>
            The CycloneDX SBOM is converted to SPDX on demand when you select the SPDX download
            option. Both formats describe the same component set; the primary difference is schema
            structure and the level of license detail.
          </p>
        </div>
      </div>

      {/* Storage and Access */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Storage and Access</h2>
        </div>
        <div className="p-6 space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            SBOMs are stored in Supabase Storage, organized per project and per extraction run.
            Each time a new extraction completes, a fresh SBOM is generated and stored alongside
            the run metadata. Previous SBOMs are retained so you can compare changes over time.
          </p>
          <p>
            Access is scoped to the organization. Only authenticated members with project
            visibility can download or view SBOM files.
          </p>
        </div>
      </div>

      {/* Export Options */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Export Options</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Download SBOMs from the project&rsquo;s{" "}
          <strong className="text-foreground">Compliance</strong> tab. Available formats:
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-border bg-background-card p-4">
            <p className="text-sm font-medium text-foreground mb-1">CycloneDX JSON</p>
            <p className="text-xs text-foreground-secondary leading-relaxed">
              Full component inventory with dependency graph, purls, and license data.
              Recommended for security tooling and automation.
            </p>
          </div>
          <div className="rounded-lg border border-border bg-background-card p-4">
            <p className="text-sm font-medium text-foreground mb-1">SPDX</p>
            <p className="text-xs text-foreground-secondary leading-relaxed">
              License-focused format for procurement, legal review, and audit workflows.
              Converted from CycloneDX on demand.
            </p>
          </div>
        </div>
      </div>

      {/* Legal Notice Generation */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Legal Notice Generation</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Deptex can auto-generate <strong className="text-foreground">notice files</strong>{" "}
            from the SBOM data. A notice file lists every third-party component along with its
            license text, making it easy to include in your product distribution or comply with
            attribution requirements.
          </p>
          <p>
            Notice generation is available from the Compliance tab alongside the SBOM download
            options. The output is a plain-text file suitable for bundling with your release
            artifacts.
          </p>
        </div>
      </div>

      {/* Compliance Frameworks */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Compliance Frameworks</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Deptex SBOMs are designed to satisfy the requirements of major compliance frameworks.
          Use <Link to="/docs/policies" className="text-primary hover:underline">Policies</Link>{" "}
          to enforce organization-specific rules on top of these baselines.
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[200px]">Framework</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {complianceFrameworks.map((cf) => (
                <tr key={cf.framework} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-2.5 text-sm font-medium text-foreground">{cf.framework}</td>
                  <td className="px-4 py-2.5 text-foreground-secondary">{cf.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

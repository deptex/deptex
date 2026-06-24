import { Link } from "react-router-dom";
import { Boxes, Bug, ShieldAlert, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Area {
  label: string;
  icon: LucideIcon;
  body: React.ReactNode;
}

const areas: Area[] = [
  {
    label: "The dependency graph",
    icon: Boxes,
    body: "Each scan generates a CycloneDX software bill of materials and resolves the full transitive tree, so Deptex sees every package you actually pull in — not just what's listed in your manifest.",
  },
  {
    label: "Known vulnerabilities",
    icon: Bug,
    body: (
      <>
        Every package is matched against vulnerability databases (OSV, GitHub Advisories) and scored
        by reachability into a{" "}
        <Link to="/docs/reachability-depscore" className="text-accent-text hover:underline">
          Depscore
        </Link>
        , so the CVEs you can actually reach rise to the top.
      </>
    ),
  },
  {
    label: "Malicious packages",
    icon: ShieldAlert,
    body: "Beyond known CVEs, Deptex inspects package code and metadata for malicious behaviour — install-time scripts, obfuscation, data exfiltration, and typosquatting — to catch threats before they ship.",
  },
  {
    label: "Supply-chain signals",
    icon: ShieldCheck,
    body: "OpenSSF Scorecard signals, package maintenance and health scoring, and direct-vs-transitive context feed into how each finding is prioritised.",
  },
];

const ecosystems = [
  "npm — JavaScript / TypeScript",
  "PyPI — Python",
  "Maven — Java",
  "Go modules",
  "RubyGems — Ruby",
  "Composer — PHP",
  "Cargo — Rust",
  "NuGet — .NET",
];

export default function DependencyScanningContent() {
  return (
    <div className="space-y-12">
      <section>
        <p className="text-foreground/90 leading-relaxed">
          Deptex builds a complete picture of everything your project depends on — direct packages
          and the full transitive tree beneath them — and checks each one for known vulnerabilities,
          malicious code, and supply-chain risk. It runs automatically on every scan, across eight
          ecosystems.
        </p>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-4">What Deptex checks</h2>
        <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
          {areas.map((area) => {
            const Icon = area.icon;
            return (
              <div key={area.label} className="flex gap-4 p-5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background-subtle">
                  <Icon className="h-5 w-5 text-foreground" />
                </span>
                <div>
                  <h3 className="font-medium text-foreground">{area.label}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-foreground/80">{area.body}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-4">Supported ecosystems</h2>
        <div className="flex flex-wrap gap-2">
          {ecosystems.map((eco) => (
            <span
              key={eco}
              className="rounded-md border border-border bg-background-subtle px-2.5 py-1 text-xs text-foreground-secondary"
            >
              {eco}
            </span>
          ))}
        </div>
      </section>
    </div>
  );
}

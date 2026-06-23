import { Link } from "react-router-dom";
import {
  Bug,
  ShieldAlert,
  FileCode,
  KeyRound,
  Waypoints,
  FileCog,
  Container,
  Globe,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface FindingType {
  label: string;
  icon: LucideIcon;
  body: string;
}

interface Domain {
  title: string;
  to: string;
  types: FindingType[];
}

const domains: Domain[] = [
  {
    title: "Dependencies",
    to: "/docs/dependencies",
    types: [
      {
        label: "Dependency vulnerabilities",
        icon: Bug,
        body: "Known CVEs in the open-source packages you depend on, scored by reachability so the exploitable ones rise to the top.",
      },
      {
        label: "Malicious packages",
        icon: ShieldAlert,
        body: "Packages flagged as malicious — typosquats, install-time scripts, and backdoors — caught before they ship.",
      },
    ],
  },
  {
    title: "Code",
    to: "/docs/code",
    types: [
      {
        label: "Code findings (SAST)",
        icon: FileCode,
        body: "Static-analysis issues in your own source: injection, unsafe APIs, weak crypto, and other risky patterns.",
      },
      {
        label: "Secrets",
        icon: KeyRound,
        body: "Credentials and API keys committed to your code, live-verified against the provider to cut false positives.",
      },
      {
        label: "Data-flow",
        icon: Waypoints,
        body: "Traced paths where untrusted input reaches a dangerous sink in your first-party code.",
      },
    ],
  },
  {
    title: "Infrastructure & DAST",
    to: "/docs/infrastructure-dast",
    types: [
      {
        label: "IaC misconfigurations",
        icon: FileCog,
        body: "Insecure settings in Terraform, Kubernetes, and Dockerfiles, plus missing hardening best-practices.",
      },
      {
        label: "Container image CVEs",
        icon: Container,
        body: "Known vulnerabilities in the OS packages of your container images, collapsed into a single base-image upgrade fix.",
      },
      {
        label: "DAST findings",
        icon: Globe,
        body: "Issues found by actively testing your running application from the outside.",
      },
    ],
  },
];

export default function FindingTypesContent() {
  return (
    <div className="space-y-12">
      <section>
        <p className="text-foreground/90 leading-relaxed">
          Every scan produces findings, and Deptex sorts them into a handful of types depending on
          where the issue lives — in your dependencies, your code, or your infrastructure. Whatever
          the type, each finding gets a{" "}
          <Link to="/docs/reachability-depscore" className="text-accent-text hover:underline">
            Depscore
          </Link>{" "}
          so they all merge into one prioritized list instead of separate, competing queues.
        </p>
      </section>

      {domains.map((domain) => (
        <section key={domain.title}>
          <div className="flex items-baseline justify-between mb-4">
            <h2 className="text-lg font-semibold text-foreground">{domain.title}</h2>
            <Link
              to={domain.to}
              className="text-sm text-foreground-secondary hover:text-foreground transition-colors"
            >
              Learn more →
            </Link>
          </div>
          <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
            {domain.types.map((finding) => {
              const Icon = finding.icon;
              return (
                <div key={finding.label} className="flex gap-4 p-5">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background-subtle">
                    <Icon className="h-5 w-5 text-foreground" />
                  </span>
                  <div>
                    <h3 className="font-medium text-foreground">{finding.label}</h3>
                    <p className="mt-1 text-sm leading-relaxed text-foreground/80">{finding.body}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      ))}
    </div>
  );
}

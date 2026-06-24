import { FileCog, Container, Globe } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Area {
  label: string;
  icon: LucideIcon;
  body: string;
}

const areas: Area[] = [
  {
    label: "IaC misconfigurations",
    icon: FileCog,
    body: "Terraform, Kubernetes manifests, and Dockerfiles are checked for insecure settings — privileged containers, exposed secrets, missing controls — plus hardening best-practices, which collapse into a single nudge when they're purely defense-in-depth.",
  },
  {
    label: "Container image CVEs",
    icon: Container,
    body: "Deptex scans your container images for vulnerable OS packages. An out-of-date base image can carry thousands of CVEs, so they're collapsed into one actionable “upgrade the base image” fix with a recommended replacement.",
  },
  {
    label: "Dynamic testing (DAST)",
    icon: Globe,
    body: "Deptex spins up your running application and actively tests it from the outside with OWASP ZAP — discovering endpoints, replaying authentication, and probing for issues that only appear at runtime.",
  },
];

export default function InfrastructureDastContent() {
  return (
    <div className="space-y-12">
      <section>
        <p className="text-foreground/90 leading-relaxed">
          Security doesn&apos;t stop at your code. Deptex also scans the infrastructure you deploy
          and tests the application you actually run — so misconfigurations and runtime-only issues
          surface alongside everything else, in the same prioritised list.
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
    </div>
  );
}

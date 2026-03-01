import { Link } from "react-router-dom";

const steps = [
  {
    number: 1,
    title: "Create an Organization",
    description:
      "Sign up for Deptex and create your first organization. An organization is the top-level container for all your projects, teams, and settings.",
    link: { to: "/docs/organizations", label: "Organizations docs" },
  },
  {
    number: 2,
    title: "Connect an Integration",
    description:
      "Go to Settings \u2192 Integrations and connect your source-code provider. GitHub is the most common starting point, but GitLab and Bitbucket are also supported.",
    link: { to: "/docs/integrations", label: "Integrations docs" },
  },
  {
    number: 3,
    title: "Create a Project",
    description:
      'Click "New Project", select a repository from your connected integration, and assign it to a team. Deptex will immediately begin extracting dependencies.',
    link: { to: "/docs/projects", label: "Projects docs" },
  },
  {
    number: 4,
    title: "Watch the Extraction",
    description:
      "Live logs stream real-time progress as Deptex resolves your dependency tree, generates an SBOM, and enriches each package with vulnerability and supply-chain data.",
    link: { to: "/docs/sbom-compliance", label: "SBOM docs" },
  },
  {
    number: 5,
    title: "Explore Your Dashboard",
    description:
      "Navigate the project overview to see your dependency graph, vulnerability summary, compliance status, and health score at a glance.",
    link: { to: "/docs/dependencies", label: "Dependencies docs" },
  },
  {
    number: 6,
    title: "Set Up Policies",
    description:
      "Go to Settings \u2192 Policies to define organization-wide rules as JavaScript functions. Block risky licenses, enforce minimum OpenSSF scores, and more.",
    link: { to: "/docs/policies", label: "Policies docs" },
    optional: true,
  },
  {
    number: 7,
    title: "Define Custom Statuses",
    description:
      "Go to Settings \u2192 Statuses to create custom vulnerability statuses with names, colors, and ranks. Use them to track remediation workflows unique to your team.",
    link: { to: "/docs/organizations", label: "Organizations docs" },
    optional: true,
  },
  {
    number: 8,
    title: "Configure Notifications",
    description:
      "Go to Settings \u2192 Notification Rules to set up automated alerts. Write trigger functions in JavaScript or use the AI assistant to generate them from plain English.",
    link: { to: "/docs/notification-rules", label: "Notification Rules docs" },
    optional: true,
  },
];

export default function QuickStartContent() {
  return (
    <div className="space-y-12">
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">
          Get started in 5 minutes
        </h2>
        <p className="text-foreground-secondary leading-relaxed">
          Follow these steps to go from sign-up to a fully monitored dependency
          supply chain. Steps 6&ndash;8 are optional and can be configured at
          any time.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {steps.map((step) => (
          <div
            key={step.number}
            className="rounded-lg border border-border bg-background-card overflow-hidden"
          >
            <div className="px-4 py-3 border-b border-border bg-background-card-header flex items-center gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/15 text-xs font-semibold text-primary">
                {step.number}
              </span>
              <h3 className="text-sm font-semibold text-foreground">
                {step.title}
                {step.optional && (
                  <span className="ml-2 text-xs font-normal text-foreground-secondary">
                    (optional)
                  </span>
                )}
              </h3>
            </div>
            <div className="p-4 space-y-3">
              <p className="text-sm text-foreground-secondary leading-relaxed">
                {step.description}
              </p>
              <Link
                to={step.link.to}
                className="inline-block text-xs font-medium text-primary hover:underline"
              >
                {step.link.label} &rarr;
              </Link>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

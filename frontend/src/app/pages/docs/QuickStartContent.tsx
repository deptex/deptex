const steps = [
  {
    number: 1,
    title: "Create an Organization",
    description:
      "Sign up for Deptex and create your first organization. An organization is the top-level container for all your projects, teams, and settings.",
  },
  {
    number: 2,
    title: "Connect an Integration",
    description:
      "Go to Settings \u2192 Integrations and connect your source-code provider. GitHub is the most common starting point, but GitLab and Bitbucket are also supported.",
  },
  {
    number: 3,
    title: "Create a Project",
    description:
      'Click "New Project", select a repository from your connected integration, and assign it to a team. Deptex will immediately begin extracting dependencies.',
  },
  {
    number: 4,
    title: "Watch the Extraction",
    description:
      "Live logs stream real-time progress as Deptex resolves your dependency tree, generates an SBOM, and enriches each package with vulnerability and supply-chain data.",
  },
  {
    number: 5,
    title: "Explore Your Dashboard",
    description:
      "Navigate the project overview to see your dependency graph, vulnerability summary, compliance status, and health score at a glance.",
  },
];

export default function QuickStartContent() {
  return (
    <div className="space-y-12">
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">
          Get started in 5 minutes
        </h2>
        <p className="text-foreground/90 leading-relaxed">
          Follow these steps to go from sign-up to a fully monitored dependency
          supply chain.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {steps.map((step) => (
          <div
            key={step.number}
            className="rounded-lg border border-border bg-background-card overflow-hidden"
          >
            <div className="px-4 py-3 border-b border-border bg-background-card-header flex items-center gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold text-foreground">
                {step.number}
              </span>
              <h3 className="text-sm font-semibold text-foreground">
                {step.title}
              </h3>
            </div>
            <div className="p-4">
              <p className="text-sm text-foreground/90 leading-relaxed">
                {step.description}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

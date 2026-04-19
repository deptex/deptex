import { Link } from "react-router-dom";
import { Clock, ArrowRight } from "lucide-react";

const tutorials = [
  {
    slug: "first-project",
    title: "Your First Project",
    description:
      "Connect a repository, run your first extraction, and explore the dashboard.",
    difficulty: "Beginner" as const,
    time: "5 min",
  },
  {
    slug: "security-dashboard",
    title: "Reading Your Security Dashboard",
    description:
      "Navigate the project overview, understand Depscore, and explore the vulnerability graph.",
    difficulty: "Beginner" as const,
    time: "8 min",
  },
  {
    slug: "custom-policies",
    title: "Writing Custom Policies",
    description:
      "Create a policy that checks licenses and critical vulnerabilities using policy-as-code.",
    difficulty: "Intermediate" as const,
    time: "10 min",
  },
  {
    slug: "notification-rules",
    title: "Setting Up Notification Rules",
    description:
      "Create alert rules, connect Slack, and test your trigger functions.",
    difficulty: "Intermediate" as const,
    time: "8 min",
  },
  {
    slug: "compliance-sbom",
    title: "Managing Compliance & SBOM Exports",
    description:
      "Define custom statuses, set up compliance policies, and export SBOMs.",
    difficulty: "Intermediate" as const,
    time: "10 min",
  },
  {
    slug: "advanced-policies",
    title: "Advanced Policy Patterns with Fetch",
    description:
      "Use fetch() to check external APIs and build multi-tier compliance policies.",
    difficulty: "Advanced" as const,
    time: "12 min",
  },
];

const difficultyStyles: Record<
  string,
  string
> = {
  Beginner: "bg-emerald-500/10 text-emerald-400",
  Intermediate: "bg-blue-500/10 text-blue-400",
  Advanced: "bg-purple-500/10 text-purple-400",
};

export { tutorials };

export default function LearnPage() {
  return (
    <div className="min-h-screen pt-14">
      <div className="max-w-5xl mx-auto px-8 pt-12 pb-16">
        <div className="mb-10">
          <h1 className="text-2xl font-semibold text-foreground mb-2">
            Learn Deptex
          </h1>
          <p className="text-foreground-secondary leading-relaxed">
            Step-by-step tutorials to help you get the most out of Deptex.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          {tutorials.map((tutorial) => (
            <Link
              key={tutorial.slug}
              to={`/docs/learn/${tutorial.slug}`}
              className="group rounded-lg border border-border bg-background-card hover:border-foreground-secondary/30 transition-colors"
            >
              <div className="p-5 flex flex-col gap-3 h-full">
                <span
                  className={`self-start text-xs font-medium px-2 py-0.5 rounded-full ${difficultyStyles[tutorial.difficulty]}`}
                >
                  {tutorial.difficulty}
                </span>

                <h3 className="font-medium text-foreground">
                  {tutorial.title}
                </h3>

                <p className="text-sm text-foreground-secondary leading-relaxed flex-1">
                  {tutorial.description}
                </p>

                <div className="flex items-center justify-between pt-1">
                  <span className="flex items-center gap-1.5 text-xs text-foreground-muted">
                    <Clock className="h-3.5 w-3.5" />
                    {tutorial.time}
                  </span>
                  <ArrowRight className="h-4 w-4 text-foreground-muted opacity-0 -translate-x-1 group-hover:opacity-100 group-hover:translate-x-0 transition-all" />
                </div>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}

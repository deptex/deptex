import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Clock } from "lucide-react";
import { tutorials } from "./LearnPage";

interface Step {
  title: string;
  content: string;
}

const tutorialContent: Record<string, Step[]> = {
  "first-project": [
    {
      title: "Sign up and create an organization",
      content:
        "Head to the Deptex login page and sign up with your GitHub, GitLab, or email account. Once authenticated, create a new organization — this is the top-level container for all your projects, teams, and settings.",
    },
    {
      title: "Navigate to Settings → Integrations",
      content:
        "Open your organization and go to Settings → Integrations. This is where you connect the source-code providers that Deptex will scan for dependency manifests.",
    },
    {
      title: "Connect your GitHub account",
      content:
        "Click \"Add Integration\" and select GitHub (or GitLab / Bitbucket). Follow the OAuth flow to authorize Deptex. Once connected, Deptex can list your repositories and read their dependency files.",
    },
    {
      title: "Click \"New Project\" and select a repository",
      content:
        "Return to the Projects page and click \"New Project\". Choose a repository from your connected integration and assign it to a team. Deptex will immediately begin the extraction process.",
    },
    {
      title: "Watch the live extraction logs",
      content:
        "After creating the project, you'll see a real-time log stream as Deptex resolves your dependency tree, generates an SBOM, and enriches each package with vulnerability and supply-chain data. This typically takes under a minute.",
    },
    {
      title: "Explore your project dashboard",
      content:
        "Once extraction completes, you land on the project overview. Review your health score, dependency count, and vulnerability summary. Navigate to the Dependencies, Vulnerabilities, and Compliance tabs to dive deeper.",
    },
  ],

  "security-dashboard": [
    {
      title: "Open a project from your organization",
      content:
        "From your organization's Projects page, click any project to open its dashboard. The overview page provides a quick snapshot of your project's dependency health.",
    },
    {
      title: "Review the project overview cards",
      content:
        "The top section displays summary cards for health score (Depscore), total dependency count, and a vulnerability breakdown by severity. These cards update automatically after each extraction.",
    },
    {
      title: "Navigate to the Security tab",
      content:
        "Click the \"Vulnerabilities\" tab in the project sidebar. This view provides a filterable table and interactive graph of all known vulnerabilities affecting your dependency tree.",
    },
    {
      title: "Understand the vulnerability graph",
      content:
        "The dependency graph visualizes how vulnerabilities propagate through transitive dependencies. Nodes are colored by Depscore — red for critical risk, yellow for moderate, and green for healthy packages.",
    },
    {
      title: "Click a vulnerability to see details",
      content:
        "Select any vulnerability node or table row to open the detail panel. You'll see the advisory description, affected version ranges, reachability analysis, EPSS score, and a full Depscore breakdown explaining the risk rating.",
    },
    {
      title: "Filter vulnerabilities by severity, reachability, or status",
      content:
        "Use the filter bar to narrow results by severity level, reachability status, or custom vulnerability statuses your team has defined. Combine filters to focus on the most actionable issues first.",
    },
  ],

  "custom-policies": [
    {
      title: "Navigate to Organization Settings → Policies",
      content:
        "Open your organization settings and click the Policies section. This is where you define code-based rules that evaluate every package and project in your organization.",
    },
    {
      title: "Understand the three policy functions",
      content:
        "Deptex policies expose three hook functions: packagePolicy runs per-package and can flag violations, projectStatus sets an overall project status based on aggregated violations, and pullRequestCheck gates pull requests with pass/fail results.",
    },
    {
      title: "Write a packagePolicy function that checks licenses",
      content:
        "In the policy editor, write a packagePolicy function that inspects each package's license field. Return a violation object when a package uses a disallowed license like GPL-3.0 or AGPL-3.0. Violations appear in the project's Compliance tab.",
    },
    {
      title: "Write a projectStatus function",
      content:
        "Add a projectStatus function that receives the array of violations from packagePolicy. Set the project status to \"Blocked\" if any critical violations exist, \"Review Required\" for warnings, and \"Compliant\" when the list is empty.",
    },
    {
      title: "Test your policy against project data",
      content:
        "Click the \"Test Policy\" button to run your functions against real project data without saving. The preview panel shows which packages would be flagged and what status would be assigned.",
    },
    {
      title: "Save and observe status changes",
      content:
        "Save your policy to activate it. Deptex re-evaluates all projects immediately. Navigate to any project's overview or your organization's Compliance page to see the updated statuses and violation counts.",
    },
  ],

  "notification-rules": [
    {
      title: "Navigate to Organization Settings → Notification Rules",
      content:
        "Open your organization settings and select Notification Rules. This page lists all existing rules and lets you create new ones that fire when specific dependency events occur.",
    },
    {
      title: "Create a new notification rule",
      content:
        "Click \"New Rule\" to open the rule editor. Give your rule a descriptive name like \"Critical Vulnerability Alert\" so your team can identify it at a glance.",
    },
    {
      title: "Write a trigger function for critical vulnerabilities",
      content:
        "In the trigger editor, write a JavaScript function that receives the event payload. Check the vulnerability severity and return true to fire the notification. For example, return event.vulnerability.severity === \"critical\" to alert only on critical findings.",
    },
    {
      title: "Select destinations",
      content:
        "Choose where notifications are delivered. Connect a Slack workspace to post to a channel, add email addresses for inbox delivery, or configure a webhook URL for custom integrations.",
    },
    {
      title: "Use \"Test Rule\" to verify your trigger logic",
      content:
        "Click \"Test Rule\" to simulate events against your trigger function. The preview shows which recent events would have matched, so you can verify your logic before going live.",
    },
    {
      title: "Check the notification history",
      content:
        "After events fire in production, return to the Notification Rules page to review the history log. Each entry shows the event that triggered it, the matched rule, and the delivery status for each destination.",
    },
  ],

  "compliance-sbom": [
    {
      title: "Navigate to Organization Settings → Statuses",
      content:
        "Open your organization settings and go to the Statuses section. Here you define the custom status labels that policies can assign to projects, such as Compliant, Review Required, or Blocked.",
    },
    {
      title: "Create custom statuses",
      content:
        "Click \"New Status\" and define a name, color, and rank for each status. The rank determines ordering in the UI — higher ranks appear first and typically represent more urgent states.",
    },
    {
      title: "Set up a compliance policy using your custom statuses",
      content:
        "Navigate to the Policies section and write a projectStatus function that returns your custom status names. For example, return \"Blocked\" when critical license violations exist and \"Compliant\" when the violation list is empty.",
    },
    {
      title: "Navigate to a project's Compliance tab",
      content:
        "Open any project and click the Compliance tab. This view shows the project's current compliance status, active violations, and a breakdown of which policy rules contributed to the current state.",
    },
    {
      title: "Export an SBOM in CycloneDX format",
      content:
        "From the Compliance tab, click \"Export SBOM\" and select CycloneDX as the format. The generated document includes every dependency, its version, license, and known vulnerabilities — ready for regulatory submission.",
    },
    {
      title: "Generate a legal notice document",
      content:
        "Click \"Legal Notice\" to generate a document listing all open-source licenses used in your project. This is useful for fulfilling attribution requirements in software distribution.",
    },
    {
      title: "Review the compliance overview",
      content:
        "Return to your organization's Compliance page for a bird's-eye view. The dashboard aggregates status counts across all projects and highlights those requiring attention.",
    },
  ],

  "advanced-policies": [
    {
      title: "Understanding the fetch() built-in function",
      content:
        "Deptex policy functions have access to a built-in fetch() function that can make HTTP requests to external APIs. This enables policies that check packages against internal registries, approved-package lists, or third-party intelligence feeds.",
    },
    {
      title: "Create a policy that queries an external approved-packages API",
      content:
        "Write a packagePolicy function that calls fetch() to query your internal API with the package name and version. If the API responds with an approval status, allow the package; otherwise, return a violation flagging it for review.",
    },
    {
      title: "Handle network errors gracefully with try/catch",
      content:
        "Wrap your fetch() calls in a try/catch block. If the external API is unreachable, decide whether to fail open (allow the package with a warning) or fail closed (block it until the API is available). Document your choice in the violation message.",
    },
    {
      title: "Return different statuses based on violation severity",
      content:
        "In your projectStatus function, inspect the violations array and categorize them. Return \"Blocked\" for any critical-severity violations, \"Review Required\" for warnings, and \"Compliant\" when all packages pass.",
    },
    {
      title: "Test the policy with the policy preview",
      content:
        "Use the policy test panel to run your fetch-based policy against real project data. The preview executes the actual HTTP requests so you can verify external API integration works correctly before saving.",
    },
    {
      title: "Review multi-tier compliance in action",
      content:
        "Save the policy and navigate to your organization's Compliance page. Projects now display statuses determined by both local rule checks and external API validations, giving you a comprehensive multi-tier compliance view.",
    },
  ],
};

const difficultyStyles: Record<string, string> = {
  Beginner: "bg-emerald-500/10 text-emerald-400",
  Intermediate: "bg-blue-500/10 text-blue-400",
  Advanced: "bg-purple-500/10 text-purple-400",
};

export default function LearnTutorialPage() {
  const { tutorial: slug } = useParams<{ tutorial: string }>();
  const tutorial = tutorials.find((t) => t.slug === slug);
  const steps = slug ? tutorialContent[slug] : undefined;

  if (!tutorial || !steps) {
    return (
      <div className="min-h-screen pt-14">
        <div className="max-w-3xl mx-auto px-8 pt-12 pb-16">
          <Link
            to="/docs/learn"
            className="inline-flex items-center gap-1.5 text-sm text-foreground-secondary hover:text-foreground transition-colors mb-8"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to tutorials
          </Link>
          <div className="rounded-lg border border-border bg-background-card p-8 text-center">
            <h2 className="text-lg font-semibold text-foreground mb-2">
              Tutorial not found
            </h2>
            <p className="text-sm text-foreground-secondary mb-4">
              The tutorial you're looking for doesn't exist or has been moved.
            </p>
            <Link
              to="/docs/learn"
              className="text-sm font-medium text-primary hover:underline"
            >
              Browse all tutorials &rarr;
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen pt-14">
      <div className="max-w-3xl mx-auto px-8 pt-12 pb-16">
        <Link
          to="/docs/learn"
          className="inline-flex items-center gap-1.5 text-sm text-foreground-secondary hover:text-foreground transition-colors mb-8"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to tutorials
        </Link>

        <div className="mb-10">
          <div className="flex items-center gap-3 mb-3">
            <span
              className={`text-xs font-medium px-2 py-0.5 rounded-full ${difficultyStyles[tutorial.difficulty]}`}
            >
              {tutorial.difficulty}
            </span>
            <span className="flex items-center gap-1.5 text-xs text-foreground-muted">
              <Clock className="h-3.5 w-3.5" />
              {tutorial.time}
            </span>
          </div>
          <h1 className="text-2xl font-semibold text-foreground mb-2">
            {tutorial.title}
          </h1>
          <p className="text-foreground-secondary leading-relaxed">
            {tutorial.description}
          </p>
        </div>

        <div className="space-y-4">
          {steps.map((step, i) => (
            <div
              key={i}
              className="rounded-lg border border-border bg-background-card overflow-hidden"
            >
              <div className="px-4 py-3 border-b border-border bg-background-card-header flex items-center gap-3">
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/15 text-xs font-semibold text-primary">
                  {i + 1}
                </span>
                <h3 className="text-sm font-semibold text-foreground">
                  {step.title}
                </h3>
              </div>
              <div className="p-4">
                <p className="text-sm text-foreground-secondary leading-relaxed">
                  {step.content}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

import { Link } from "react-router-dom";
import {
  ArrowRight,
  GitBranch,
  ScanSearch,
  Crosshair,
  GitPullRequest,
  Package,
  MessageSquare,
  FolderGit2,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Step {
  label: string;
  icon: LucideIcon;
  body: string;
}

const steps: Step[] = [
  {
    label: "Connect",
    icon: GitBranch,
    body: "Link your repositories from GitHub, GitLab, or Bitbucket. Deptex clones each one and keeps scanning as you push.",
  },
  {
    label: "Scan",
    icon: ScanSearch,
    body: "Every scan covers your dependencies, source code (SAST + secrets), containers, and infrastructure-as-code — and can actively test your running app with DAST.",
  },
  {
    label: "Score",
    icon: Crosshair,
    body: "Each finding gets a Depscore based on reachability — confirmed, data-flow, function, or module level — so genuinely exploitable issues rise to the top and noise drops to the bottom.",
  },
  {
    label: "Fix",
    icon: GitPullRequest,
    body: "Aegis investigates the findings worth acting on, writes the fix, and opens a draft pull request for you to review and merge.",
  },
];

interface StartCard {
  label: string;
  to: string;
  icon: LucideIcon;
  body: string;
}

const startHere: StartCard[] = [
  {
    label: "Reachability & Depscore",
    to: "/docs/reachability-depscore",
    icon: Crosshair,
    body: "Understand how every finding is scored by what's actually exploitable.",
  },
  {
    label: "Dependencies",
    to: "/docs/dependencies",
    icon: Package,
    body: "Dependency CVEs, supply-chain signals, and malicious package detection.",
  },
  {
    label: "Aegis",
    to: "/docs/aegis",
    icon: MessageSquare,
    body: "Let the autonomous agent investigate a finding and open the fix PR.",
  },
  {
    label: "Projects",
    to: "/docs/projects",
    icon: FolderGit2,
    body: "Connect a repository and run your first scan in minutes.",
  },
];

export default function IntroductionContent() {
  return (
    <>
      <div className="space-y-4 mb-12">
        <p className="text-foreground/90 leading-relaxed">
          Deptex is an AI-powered security platform for the code you ship and the dependencies it
          pulls in. Connect a repository and Deptex continuously scans your dependencies, source
          code, and infrastructure for vulnerabilities, secrets, and misconfigurations.
        </p>
        <p className="text-foreground/90 leading-relaxed">
          What makes it different is what it does with those findings. Deptex scores each one by
          whether it&apos;s actually reachable in your code — so you fix what&apos;s genuinely
          exploitable instead of drowning in a list — and Aegis, the autonomous security agent,
          investigates the ones that matter and opens the fix as a pull request you review.
        </p>
      </div>

      <div className="mb-12">
        <h2 className="text-lg font-semibold text-foreground mb-4">How it works</h2>
        <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
          {steps.map((step) => {
            const Icon = step.icon;
            return (
              <div key={step.label} className="flex gap-4 p-5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background-subtle">
                  <Icon className="h-5 w-5 text-foreground" />
                </span>
                <div>
                  <h3 className="font-medium text-foreground">{step.label}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-foreground/80">{step.body}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold text-foreground mb-4">Start here</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {startHere.map((card) => {
            const Icon = card.icon;
            return (
              <Link
                key={card.to}
                to={card.to}
                className="group rounded-lg border border-border bg-background-card p-5 transition-colors hover:border-white/20 hover:bg-background-subtle/40"
              >
                <div className="flex items-center gap-3 mb-2">
                  <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-background-subtle">
                    <Icon className="h-5 w-5 text-foreground" />
                  </span>
                  <h3 className="font-medium text-foreground flex-1">{card.label}</h3>
                  <ArrowRight className="h-4 w-4 text-foreground-muted transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
                </div>
                <p className="text-sm leading-relaxed text-foreground/80">{card.body}</p>
              </Link>
            );
          })}
        </div>
      </div>
    </>
  );
}

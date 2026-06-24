import { Settings, GitBranch, Users, Globe } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Tab {
  label: string;
  icon: LucideIcon;
  body: string;
}

const tabs: Tab[] = [
  {
    label: "General",
    icon: Settings,
    body: "Rename the project, set its scan frequency, and manage or delete it.",
  },
  {
    label: "Repository",
    icon: GitBranch,
    body: "The connected repo, branch, and the manifest paths Deptex resolves dependencies from.",
  },
  {
    label: "Access",
    icon: Users,
    body: "Which team owns the project and who can see it.",
  },
  {
    label: "DAST",
    icon: Globe,
    body: "Configure dynamic testing targets — the URLs and authentication Deptex uses to test your running app.",
  },
];

export default function ProjectsAdminContent() {
  return (
    <div className="space-y-12">
      <section>
        <p className="text-foreground/90 leading-relaxed">
          A project is one repository Deptex watches. Connect a repo and Deptex clones it, runs the
          full scan pipeline, and keeps it up to date as your code changes. Projects belong to teams,
          which control who can see them.
        </p>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-2">Connecting &amp; scanning</h2>
        <p className="text-foreground/90 leading-relaxed">
          Connect a repository through the GitHub App, GitLab, or Bitbucket. Deptex clones it, builds
          a software bill of materials, and runs every scanner — dependencies, code, and
          infrastructure — producing a single prioritised list of findings.
        </p>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-2">Keeping projects in sync</h2>
        <p className="text-foreground/90 leading-relaxed">
          Each project can rescan automatically on every push (via your provider&apos;s webhooks) and
          on a periodic schedule — daily or weekly — so findings stay current even when a repository
          is quiet. You can also trigger a scan manually at any time.
        </p>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-4">Project settings</h2>
        <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <div key={tab.label} className="flex gap-4 p-5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background-subtle">
                  <Icon className="h-5 w-5 text-foreground" />
                </span>
                <div>
                  <h3 className="font-medium text-foreground">{tab.label}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-foreground/80">{tab.body}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

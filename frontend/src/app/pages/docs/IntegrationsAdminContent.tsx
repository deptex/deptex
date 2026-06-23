import { GitBranch, Ticket, MessageSquare, Webhook } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Category {
  label: string;
  icon: LucideIcon;
  body: string;
}

const categories: Category[] = [
  {
    label: "Source control",
    icon: GitBranch,
    body: "Connect repositories from GitHub, GitLab, or Bitbucket. Deptex scans on every push and posts checks and comments on your pull requests.",
  },
  {
    label: "Issue tracking",
    icon: Ticket,
    body: "File a finding as a ticket in Jira, Linear, or GitHub Issues and keep its status in sync — when the ticket closes, the finding reflects it.",
  },
  {
    label: "Chat & notifications",
    icon: MessageSquare,
    body: "Send alerts to Slack or Discord. The Aegis Slack bot also lets your team chat with the agent and approve actions without leaving Slack.",
  },
  {
    label: "Custom webhooks",
    icon: Webhook,
    body: "Forward events to any endpoint to wire Deptex into your own tooling and workflows.",
  },
];

export default function IntegrationsAdminContent() {
  return (
    <div className="space-y-12">
      <section>
        <p className="text-foreground/90 leading-relaxed">
          Deptex connects to the tools you already use — to pull in your code, push findings into
          your tracker, and keep your team notified.
        </p>
      </section>

      <section>
        <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
          {categories.map((cat) => {
            const Icon = cat.icon;
            return (
              <div key={cat.label} className="flex gap-4 p-5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background-subtle">
                  <Icon className="h-5 w-5 text-foreground" />
                </span>
                <div>
                  <h3 className="font-medium text-foreground">{cat.label}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-foreground/80">{cat.body}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

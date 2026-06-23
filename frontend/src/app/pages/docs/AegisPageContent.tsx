import {
  MessageSquare,
  ScanSearch,
  ClipboardList,
  GitPullRequest,
  Clock,
  Brain,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Capability {
  label: string;
  icon: LucideIcon;
  body: string;
}

const capabilities: Capability[] = [
  {
    label: "Chat about your posture",
    icon: MessageSquare,
    body: "Ask about your projects, findings, and risk in plain language. Conversations live in threads you can pin, rename, and revisit.",
  },
  {
    label: "Investigate a finding",
    icon: ScanSearch,
    body: "Hand Aegis any finding — from the Findings view or a routine — and it digs into the code, the dependency, and the exploit path to work out what's really going on.",
  },
  {
    label: "Plan before it acts",
    icon: ClipboardList,
    body: "For anything consequential, Aegis proposes a step-by-step plan first. Nothing risky runs without your approval.",
  },
  {
    label: "Open the fix as a PR",
    icon: GitPullRequest,
    body: "Aegis implements the fix on a branch and opens a draft pull request for you to review and merge — you stay in control of what actually lands.",
  },
  {
    label: "Run on a schedule",
    icon: Clock,
    body: "Routines let Aegis run on a cron schedule — triage new findings, draft fixes, or report on posture — without anyone kicking it off.",
  },
  {
    label: "Remember context",
    icon: Brain,
    body: "Aegis keeps memory across sessions, so decisions and context carry from one conversation to the next.",
  },
];

interface Permission {
  key: string;
  desc: string;
}

const permissions: Permission[] = [
  { key: "interact_with_aegis", desc: "Chat with Aegis and use the Fix-with-AI / Explain actions." },
  { key: "manage_aegis", desc: "Configure Aegis, routines, budgets, tool permissions, and memory." },
  { key: "trigger_fix", desc: "Request AI fixes and approve fix plans." },
  { key: "view_ai_spending", desc: "View AI usage and cost (read-only)." },
  { key: "manage_incidents", desc: "Declare and resolve incidents." },
];

export default function AegisPageContent() {
  return (
    <div className="space-y-12">
      <section>
        <div className="space-y-4">
          <p className="text-foreground/90 leading-relaxed">
            Aegis is Deptex&apos;s autonomous security agent. It&apos;s less a chatbot than a
            teammate: it understands your security posture, investigates the findings that matter,
            and — when you approve — writes the fix and opens a pull request for you to review.
          </p>
          <p className="text-foreground/90 leading-relaxed">
            It runs on Deptex-managed AI models, so there are no keys for you to bring. You decide
            how much autonomy it has: every consequential action is gated behind a plan you approve.
          </p>
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-4">What Aegis does</h2>
        <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
          {capabilities.map((cap) => {
            const Icon = cap.icon;
            return (
              <div key={cap.label} className="flex gap-4 p-5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background-subtle">
                  <Icon className="h-5 w-5 text-foreground" />
                </span>
                <div>
                  <h3 className="font-medium text-foreground">{cap.label}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-foreground/80">{cap.body}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-2">How a fix works</h2>
        <p className="text-foreground/90 leading-relaxed">
          You (or a routine) hand Aegis a finding. It investigates the code, the dependency, and the
          reachability path, then proposes a fix plan you can approve, revise, or reject. On approval
          the fix agent writes the change on a branch and opens a <strong className="text-foreground">draft
          pull request</strong> — so you review, run CI, and merge on your terms. Nothing ships
          without a human in the loop.
        </p>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-2">Working with Aegis</h2>
        <p className="text-foreground/90 leading-relaxed">
          Open Aegis from the sidebar to start a thread or manage routines, send a specific finding
          to Aegis straight from the Findings view, or @mention the Aegis bot in Slack to chat and
          approve actions without leaving your workflow. Models are managed by Deptex — pick which
          ones are enabled for your org under <strong className="text-foreground">Settings → AI &amp;
          Automation</strong>, and usage is metered against your prepaid balance.
        </p>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-4">Permissions</h2>
        <div className="overflow-hidden rounded-lg border border-border bg-background-card">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left">
                <th className="px-4 py-3 font-semibold text-foreground">Permission</th>
                <th className="px-4 py-3 font-semibold text-foreground">Grants</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {permissions.map((perm) => (
                <tr key={perm.key}>
                  <td className="px-4 py-3 align-top whitespace-nowrap">
                    <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono text-foreground">
                      {perm.key}
                    </code>
                  </td>
                  <td className="px-4 py-3 text-foreground/80 align-top">{perm.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

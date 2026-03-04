export default function AegisContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            <strong className="text-foreground">Aegis</strong> is Deptex&apos;s autonomous security agent. It can chat about your security posture,
            run tasks (trigger fixes, generate reports), execute scheduled automations, and integrate with Slack. Aegis uses your
            organization&apos;s AI provider (OpenAI, Anthropic, or Google) and has access to tools for projects, vulnerabilities,
            policies, compliance, and reporting.
          </p>
          <p>
            Access Aegis from the organization sidebar or from context panels in the Security tab. You need{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">interact_with_aegis</code> to chat;{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_aegis</code> for the management console.
          </p>
        </div>
      </div>

      {/* Chat and Threads */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Chat and Threads</h2>
        <p className="text-foreground/90 leading-relaxed">
          Conversations are organized in <strong className="text-foreground">threads</strong>. Start a new thread or resume an existing one.
          The agent can call tools in a multi-turn loop and show you results. Thread history is persisted. You can attach context
          (project, vulnerability) when opening Aegis from the Security tab.
        </p>
      </div>

      {/* Tasks and Approvals */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Tasks and Approvals</h2>
        <p className="text-foreground/90 leading-relaxed">
          For high-impact actions, Aegis may create an <strong className="text-foreground">approval request</strong>. Users with the right
          permissions can approve or reject from the Management Console. Long-running <strong className="text-foreground">tasks</strong> (e.g. security
          sprints with multiple fix steps) are broken into steps; you can pause, cancel, or approve as needed.{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">trigger_fix</code> controls who can create fix tasks.
        </p>
      </div>

      {/* Automations */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Automations</h2>
        <p className="text-foreground/90 leading-relaxed">
          Define <strong className="text-foreground">scheduled automations</strong> that run on a cron schedule (daily, weekly). Each automation
          has a prompt and optional event triggers. Aegis runs it with the same tool set and logs results. Manage from the
          Management Console. After repeated failures, an automation may be auto-disabled.
        </p>
      </div>

      {/* Memory */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Memory</h2>
        <p className="text-foreground/90 leading-relaxed">
          Aegis can store and recall <strong className="text-foreground">memory</strong> so that important decisions or context persist across
          sessions. Manage memory entries from the Management Console.
        </p>
      </div>

      {/* Slack Bot */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Slack Bot</h2>
        <p className="text-foreground/90 leading-relaxed">
          Connect a <strong className="text-foreground">Slack workspace</strong> to Aegis. @mention the Aegis app in Slack and the message is
          processed by the same agent; responses post in the channel. Approval buttons in Slack can approve or reject pending actions.
        </p>
      </div>

      {/* PR Security Review */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">PR Security Review</h2>
        <p className="text-foreground/90 leading-relaxed">
          Aegis can perform <strong className="text-foreground">security reviews</strong> on pull requests — risk assessment, policy checks,
          and a structured comment on the PR. Configure auto-review or on-demand from the management console.
        </p>
      </div>

      {/* BYOK and AI Configuration */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">AI Configuration</h2>
        <p className="text-foreground/90 leading-relaxed">
          Aegis uses your organization&apos;s AI provider under <strong className="text-foreground">Settings &rarr; AI &amp; Automation &rarr; AI Configuration</strong>.
          Connect OpenAI, Anthropic, or Google; keys are encrypted. Without a configured provider, Aegis chat and fix features are unavailable.
          Usage is logged; optional monthly cost caps and per-task budgets help control spend.
        </p>
      </div>

      {/* Management Console */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Management Console</h2>
        <p className="text-foreground/90 leading-relaxed mb-3">
          <strong className="text-foreground">Settings &rarr; AI &amp; Automation &rarr; Aegis AI</strong> opens the Management Console (requires{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_aegis</code>). Tabs: Configuration (operating mode, tool permissions, budgets),
          Active Work (tasks and approvals), Automations, Memory, Usage Analytics, Audit Log.
        </p>
      </div>

      {/* Permissions */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Key Permissions</h2>
        </div>
        <div className="p-4">
          <table className="w-full text-sm">
            <thead className="border-b border-border">
              <tr>
                <th className="text-left py-2 font-semibold text-foreground">Permission</th>
                <th className="text-left py-2 text-foreground-secondary">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr><td className="py-2 font-mono text-xs text-foreground">interact_with_aegis</td><td className="py-2 text-foreground/90">Chat, copilot, Fix with AI / Explain with Aegis buttons</td></tr>
              <tr><td className="py-2 font-mono text-xs text-foreground">manage_aegis</td><td className="py-2 text-foreground/90">Management Console, AI Configuration, budgets, tool overrides, memory, automations</td></tr>
              <tr><td className="py-2 font-mono text-xs text-foreground">trigger_fix</td><td className="py-2 text-foreground/90">Create security sprints and approve fix tasks</td></tr>
              <tr><td className="py-2 font-mono text-xs text-foreground">view_ai_spending</td><td className="py-2 text-foreground/90">View usage and cost (read-only)</td></tr>
              <tr><td className="py-2 font-mono text-xs text-foreground">manage_incidents</td><td className="py-2 text-foreground/90">Declare and resolve incidents</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

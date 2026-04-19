import { Link } from "react-router-dom";

export default function AegisContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            <strong className="text-foreground">Aegis</strong> is Deptex&apos;s autonomous security agent. It can chat with you about your organization&apos;s security posture, run tasks (e.g. trigger fixes, generate reports), execute scheduled automations, and integrate with Slack. Aegis uses your organization&apos;s configured AI provider (BYOK: OpenAI, Anthropic, or Google) and has access to a large set of tools (projects, vulnerabilities, policies, compliance, reporting, and more).
          </p>
          <p>
            Access Aegis from the organization sidebar (<strong className="text-foreground">Aegis</strong>) or from context panels in the Security tab. Permission <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">interact_with_aegis</code> is required to chat; <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_aegis</code> is required for the management console and settings.
          </p>
        </div>
      </div>

      {/* Chat and Threads */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Chat and Threads</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Conversations are organized in <strong className="text-foreground">threads</strong>. You can start a new thread or resume an existing one. Messages are streamed via SSE; the agent can call tools in a multi-turn loop (ReAct) and show you tool results. Thread history is persisted so you can switch context and return later. You can optionally attach context (e.g. project, vulnerability) when opening Aegis from the Security tab.
        </p>
      </div>

      {/* Tasks and Approvals */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Tasks and Approvals</h2>
        <p className="text-foreground-secondary leading-relaxed mb-3">
          For high-impact or dangerous actions, Aegis may create an <strong className="text-foreground">approval request</strong>. Users with the right permissions can approve or reject from the Management Console or from the Aegis UI. Long-running <strong className="text-foreground">tasks</strong> (e.g. security sprints with multiple fix steps) are broken into steps and executed via an internal queue; you can pause, cancel, or approve steps as needed.
        </p>
        <p className="text-foreground-secondary leading-relaxed text-sm">
          Permissions like <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">trigger_fix</code> control who can create fix tasks; <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_aegis</code> controls access to budgets, tool overrides, and the audit log.
        </p>
      </div>

      {/* Automations */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Automations</h2>
        <p className="text-foreground-secondary leading-relaxed">
          You can define <strong className="text-foreground">scheduled automations</strong> that run on a cron schedule (e.g. daily or weekly). Each automation has a prompt and optional event triggers. Aegis runs the automation with the same tool set and logs results. Automations can be enabled/disabled and tuned from the Management Console. Failed runs are tracked; after repeated failures an automation may be auto-disabled.
        </p>
      </div>

      {/* Memory */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Memory</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Aegis can store and recall <strong className="text-foreground">memory</strong> (semantic snippets) so that important decisions or context persist across sessions. Memory is stored with embeddings and queried when building the agent context. You can manage memory entries from the Management Console (view, add, delete).
        </p>
      </div>

      {/* Slack Bot */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Slack Bot</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Organizations can connect a <strong className="text-foreground">Slack workspace</strong> to Aegis. When someone @mentions the Aegis app in Slack, the message is processed by the same agent; responses are posted in the channel. Approval buttons in Slack can be used to approve or reject pending actions. Configuration (bot token, signing secret) is stored encrypted and managed in the Aegis Management Console.
        </p>
      </div>

      {/* PR Security Review */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">PR Security Review</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Aegis can perform <strong className="text-foreground">security reviews</strong> on pull requests. The review assesses risk, checks against policy, and posts a structured comment on the PR. This can be configured (e.g. auto-review on open or on-demand) from the management console.
        </p>
      </div>

      {/* BYOK and AI Configuration */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">BYOK and AI Configuration</h2>
        <p className="text-foreground-secondary leading-relaxed mb-3">
          Aegis uses your organization&apos;s AI provider configured under <strong className="text-foreground">Settings &rarr; AI &amp; Automation &rarr; AI Configuration</strong>. You can connect OpenAI, Anthropic, or Google; API keys are encrypted at rest. Without a configured provider (BYOK), Aegis chat and fix features are unavailable. Usage is logged for cost and audit; optional monthly cost caps and per-task budgets help control spend.
        </p>
        <p className="text-foreground-secondary leading-relaxed text-sm">
          The same provider is used for Aegis chat, automations, and (when triggered from Aegis) AI-powered vulnerability fixes. See <Link to="/docs/integrations" className="text-primary hover:underline">Integrations</Link> for AI-Powered Fixing and <Link to="/docs/policies" className="text-primary hover:underline">Policies</Link> for policy-as-code.
        </p>
      </div>

      {/* Management Console */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Management Console</h2>
        <p className="text-foreground-secondary leading-relaxed mb-3">
          <strong className="text-foreground">Settings &rarr; AI &amp; Automation &rarr; Aegis AI</strong> opens the Management Console (requires <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_aegis</code>). Tabs include:
        </p>
        <ul className="list-disc list-inside space-y-1 text-sm text-foreground-secondary">
          <li><strong className="text-foreground">Configuration</strong> — operating mode, tool permissions, budgets</li>
          <li><strong className="text-foreground">Active Work</strong> — tasks and approval requests</li>
          <li><strong className="text-foreground">Automations</strong> — create and manage scheduled automations</li>
          <li><strong className="text-foreground">Memory</strong> — view and manage semantic memory</li>
          <li><strong className="text-foreground">Usage Analytics</strong> — spending, token usage, cost by feature</li>
          <li><strong className="text-foreground">Audit Log</strong> — history of requests and tool executions</li>
        </ul>
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
              <tr><td className="py-2 font-mono text-xs text-foreground">interact_with_aegis</td><td className="py-2 text-foreground-secondary">Chat with Aegis, use copilot and &quot;Fix with AI&quot; / &quot;Explain with Aegis&quot; buttons</td></tr>
              <tr><td className="py-2 font-mono text-xs text-foreground">manage_aegis</td><td className="py-2 text-foreground-secondary">Access Management Console, AI Configuration, operating mode, budgets, tool overrides, memory, automations</td></tr>
              <tr><td className="py-2 font-mono text-xs text-foreground">trigger_fix</td><td className="py-2 text-foreground-secondary">Create security sprints and approve fix tasks</td></tr>
              <tr><td className="py-2 font-mono text-xs text-foreground">view_ai_spending</td><td className="py-2 text-foreground-secondary">View usage and cost in the console (read-only)</td></tr>
              <tr><td className="py-2 font-mono text-xs text-foreground">manage_incidents</td><td className="py-2 text-foreground-secondary">Declare and resolve incidents (future use)</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

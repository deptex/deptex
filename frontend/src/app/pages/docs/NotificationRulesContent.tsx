export default function NotificationRulesContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            <strong className="text-foreground">Notification Rules</strong> let you define automated alerts that fire when specific events occur
            across your projects and dependencies. Each rule has a <strong className="text-foreground">trigger function</strong> (JavaScript) and
            one or more <strong className="text-foreground">destinations</strong> (Slack, Discord, Jira, Linear, Asana, PagerDuty, email, or custom webhooks).
          </p>
          <p>
            When an event occurs, Deptex evaluates your trigger function with a context object. Return{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">true</code> to send a notification or{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">false</code> to skip. For richer control, return{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">{`{ notify, message, title, priority }`}</code>.
          </p>
          <p>
            Use the <strong className="text-foreground">AI assistant</strong> in the rule editor to describe what you want in plain English — it
            generates the trigger code. Built-in templates are available for common patterns (critical vulns, supply chain alerts, compliance).
          </p>
        </div>
      </div>

      {/* Trigger Events */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Trigger Events</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          Deptex supports 30+ event types. Your trigger function receives{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context.event.type</code> and can filter on it.
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Category</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Event Types</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-medium text-foreground">Security</td>
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">vulnerability_discovered</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">vulnerability_resolved</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">malicious_package_detected</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">ai_fix_completed</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">risk_score_changed</code></td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-medium text-foreground">Dependencies</td>
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">dependency_added</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">dependency_updated</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">dependency_removed</code></td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-medium text-foreground">Compliance</td>
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">status_changed</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">compliance_violation</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">pr_check_completed</code></td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-medium text-foreground">Extraction</td>
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">extraction_completed</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">extraction_failed</code></td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-medium text-foreground">Organization</td>
                <td className="px-4 py-3 text-foreground/90"><code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">member_invited</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">member_joined</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">integration_connected</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">project_created</code></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Destinations */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Destinations</h2>
        <p className="text-foreground/90 leading-relaxed mb-3">
          Each rule can send to one or more destinations. Connect integrations in Organization Settings first.
        </p>
        <ul className="list-disc list-inside space-y-1 text-foreground/90 text-sm">
          <li><strong className="text-foreground">Slack, Discord</strong> — OAuth; send to channels or DMs</li>
          <li><strong className="text-foreground">Email</strong> — In-app; users opt in per org</li>
          <li><strong className="text-foreground">Jira, Linear, Asana</strong> — Create tickets or tasks</li>
          <li><strong className="text-foreground">PagerDuty</strong> — Routing key; incident alerts</li>
          <li><strong className="text-foreground">Custom Webhook</strong> — Any URL with HMAC signing</li>
        </ul>
      </div>

      {/* Context */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Context Object</h2>
        <p className="text-foreground/90 leading-relaxed">
          Your trigger function receives a <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context</code> object with{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">event</code> (type, timestamp),{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">project</code> (name, status, health_score, etc.),{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">dependency</code> (when applicable),{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">vulnerability</code> (for vuln events),{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pr</code> (for PR events),{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">batch</code> (when multiple events are batched), and{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">previous</code> (for change-type events). Fields not applicable to the event are null.
        </p>
      </div>

      {/* Example */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Example: High Depscore Alert</h2>
        <pre className="rounded-lg border border-border bg-background-card p-4 text-sm text-foreground overflow-x-auto font-mono">
{`// Alert when a vulnerability with depscore above 75 is discovered
if (context.event.type !== 'vulnerability_discovered') return false;
if (!context.vulnerability) return false;
return context.vulnerability.depscore > 75;`}
        </pre>
        <p className="text-foreground/90 leading-relaxed mt-3 text-sm">
          Copy and adapt when creating notification rules. Create rules from Settings → Notification Rules.
        </p>
      </div>
    </div>
  );
}

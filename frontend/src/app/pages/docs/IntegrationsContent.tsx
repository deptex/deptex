import { useState } from "react";
import { Github, GitBranch, Slack, Mail, Webhook, FileCode, Code } from "lucide-react";

const availableIntegrations = [
  { name: "GitHub", icon: "/images/integrations/github.png", IconFallback: Github, category: "CI/CD", description: "Connect repositories for dependency scanning and security monitoring." },
  { name: "GitLab", icon: "/images/integrations/gitlab.png", IconFallback: GitBranch, category: "CI/CD", description: "Integrate with GitLab repos and CI/CD pipelines." },
  { name: "Bitbucket", icon: "/images/integrations/bitbucket.png", IconFallback: GitBranch, category: "CI/CD", description: "Connect Bitbucket repositories for scanning." },
  { name: "Slack", icon: "/images/integrations/slack.png", IconFallback: Slack, category: "Notifications", description: "Real-time security alerts and vulnerability notifications." },
  { name: "Discord", icon: "/images/integrations/discord.png", IconFallback: Slack, category: "Notifications", description: "Send alerts to Discord channels." },
  { name: "Email", icon: null, IconFallback: Mail, category: "Notifications", description: "Email notifications for critical vulnerabilities." },
  { name: "Jira", icon: "/images/integrations/jira.png", IconFallback: FileCode, category: "Ticketing", description: "Create tickets for security issues." },
  { name: "Linear", icon: "/images/integrations/linear.png", IconFallback: Code, category: "Ticketing", description: "Sync issues with Linear." },
  { name: "Asana", icon: "/images/integrations/asana.png", IconFallback: FileCode, category: "Ticketing", description: "Track remediation in Asana." },
  { name: "Custom Webhook", icon: null, IconFallback: Webhook, category: "Custom", description: "Receive events at any URL with HMAC signing." },
];

function IntegrationIcon({ icon, IconFallback, name }: { icon: string | null; IconFallback: React.ComponentType<{ className?: string }>; name: string }) {
  const [imgError, setImgError] = useState(false);
  if (icon && !imgError) {
    return (
      <img src={icon} alt={name} className="h-5 w-5 rounded-sm flex-shrink-0 object-contain" onError={() => setImgError(true)} />
    );
  }
  return <IconFallback className="h-5 w-5 text-foreground/70 flex-shrink-0" aria-hidden />;
}

export default function IntegrationsContent() {
  return (
    <div className="space-y-12">
      {/* Available Integrations */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Available Integrations</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          Deptex connects with your existing tools.
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full table-fixed">
            <colgroup>
              <col className="w-[200px]" />
              <col className="w-[120px]" />
              <col />
            </colgroup>
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Integration</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Category</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {availableIntegrations.map((int) => (
                <tr key={int.name} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <IntegrationIcon icon={int.icon} IconFallback={int.IconFallback} name={int.name} />
                      <span className="text-sm font-medium text-foreground">{int.name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-foreground/90 bg-background-subtle px-2 py-1 rounded">{int.category}</span>
                  </td>
                  <td className="px-4 py-3 text-sm text-foreground/90">{int.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pull Request Checks */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Pull Request Checks</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground/90 leading-relaxed">
            When a PR or merge request changes dependencies, Deptex runs your{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pullRequestCheck</code> policy function.
            Return <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">&#123; passed: true, violations: [] &#125;</code> to pass the check, or <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">passed: false</code> to block the merge.
            The summary shows the status name and violations so developers know what to fix.
          </p>
        </div>
      </div>

      {/* GitLab and Bitbucket */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">GitLab and Bitbucket</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground/90 leading-relaxed">
            <strong className="text-foreground">GitLab:</strong> Connect via OAuth. Deptex can register webhooks for Push and Merge Request events.
            Push triggers extraction when the project&rsquo;s sync setting allows it; MR events run PR checks and post status updates.
          </p>
          <p className="text-foreground/90 leading-relaxed">
            <strong className="text-foreground">Bitbucket:</strong> Connect via OAuth. Webhooks for <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">repo:push</code> and{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">pullrequest:*</code> trigger extraction and PR checks.
          </p>
          <p className="text-foreground/90 leading-relaxed text-sm">
            Sync frequency (manual, on commit, daily, weekly) is configured per project.
          </p>
        </div>
      </div>

      {/* AI-Powered Fixing */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">AI-Powered Fixing</h2>
        </div>
        <div className="p-6">
          <p className="text-foreground/90 leading-relaxed">
            Deptex can generate vulnerability fixes automatically. When you request a fix from the Security tab or Aegis, Deptex clones the repo,
            runs a fix strategy tailored to the vulnerability type, validates the fix, and creates a pull request. Fixes are always draft PRs for
            human review. Your organization must have an AI provider configured in Settings → AI Configuration.
          </p>
        </div>
      </div>

      {/* Custom Webhooks */}
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-4 py-3 border-b border-border bg-background-card-header">
          <h2 className="text-lg font-semibold text-foreground">Custom Webhooks</h2>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-foreground/90 leading-relaxed">
            Add <strong className="text-foreground">Custom Webhook Integrations</strong> from Settings → Integrations → Add Custom. Enter a name and webhook URL
            (must start with <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">https://</code>). On creation, you receive a signing secret — copy it immediately.
            Deptex sends HTTP POST requests signed with HMAC-SHA256 when events fire.
          </p>
          <div className="rounded-lg border border-border bg-background-subtle p-4 space-y-2 text-sm">
            <p className="text-foreground/90"><strong className="text-foreground">Request format:</strong> POST with JSON body. Headers include <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">X-Deptex-Signature</code> (HMAC-SHA256 of body) and <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">X-Deptex-Event</code> (event type). Verify the signature using your webhook secret before processing.</p>
            <p className="text-foreground/90"><strong className="text-foreground">Payload:</strong> <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">event</code> (type, timestamp), <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">project</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">dependency</code>, <code className="rounded bg-background-subtle px-1 py-0.5 text-xs font-mono">vulnerability</code> — fields vary by event type.</p>
          </div>
        </div>
      </div>
    </div>
  );
}

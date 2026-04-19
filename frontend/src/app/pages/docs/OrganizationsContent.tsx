import { Link } from "react-router-dom";

const permissions = [
  { permission: "manage_organization", description: "Edit organization name, logo, and general settings." },
  { permission: "manage_members", description: "Invite, remove, and change roles for organization members." },
  { permission: "manage_teams", description: "Create, edit, and delete teams and their project assignments." },
  { permission: "manage_projects", description: "Create, archive, and configure projects." },
  { permission: "manage_integrations", description: "Connect and remove third-party integrations (GitHub, Slack, etc.)." },
  { permission: "manage_policies", description: "Edit the organization-wide policy code." },
  { permission: "manage_compliance", description: "Review and approve policy exception applications." },
  { permission: "manage_statuses", description: "Create, edit, reorder, and delete custom vulnerability statuses." },
  { permission: "manage_notification_rules", description: "Create, edit, and delete notification rules." },
  { permission: "view_audit_logs", description: "View the organization audit log." },
];

export default function OrganizationsContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            An <strong className="text-foreground">Organization</strong> is the top-level
            container in Deptex. It holds your projects, teams, members, integrations,
            policies, and settings. Each user can belong to multiple organizations, and
            every resource is scoped to exactly one org.
          </p>
          <p>
            When you first sign up, you create or are invited to an organization.
            Switch between organizations at any time from the sidebar.
          </p>
        </div>
      </div>

      {/* Organization Settings */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Organization Settings</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Access settings from the sidebar under <strong className="text-foreground">Settings</strong>.
          The General tab lets you update the organization name, avatar, and default configurations
          such as the default asset tier for new projects and the default branch to track.
        </p>
        <div className="rounded-lg border border-border bg-background-card p-4">
          <p className="text-sm text-foreground-secondary leading-relaxed">
            Only members with the{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_organization</code>{" "}
            permission can modify general settings.
          </p>
        </div>
      </div>

      {/* Custom Statuses */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Custom Statuses</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            The <strong className="text-foreground">Statuses</strong> tab in organization settings
            lets you define custom vulnerability statuses that appear throughout the platform.
            Each status has a name, color, numeric rank (lower ranks sort first), and an{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">is_passing</code>{" "}
            flag that determines whether a vulnerability with that status counts as resolved.
          </p>
          <p>
            Drag and drop to reorder statuses. System statuses (e.g.{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">Open</code>,{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">Resolved</code>)
            cannot be deleted but can be reordered. Custom statuses can be edited or removed at any time.
          </p>
        </div>
        <div className="mt-4 rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Field</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">name</td>
                <td className="px-4 py-3 text-foreground-secondary">Display label shown on vulnerability cards and filters.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">color</td>
                <td className="px-4 py-3 text-foreground-secondary">Hex color used for the status badge.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">rank</td>
                <td className="px-4 py-3 text-foreground-secondary">Numeric sort order. Lower ranks appear first in dropdowns and lists.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-foreground">is_passing</td>
                <td className="px-4 py-3 text-foreground-secondary">
                  If <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">true</code>, vulnerabilities with this status are treated as resolved in compliance checks.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Roles and Permissions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Roles and Permissions</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed mb-4">
          <p>
            Deptex uses <strong className="text-foreground">role-based access control (RBAC)</strong>.
            Each organization can define custom roles, each with a set of permissions. Members are
            assigned one role per organization. The built-in <strong className="text-foreground">Owner</strong>{" "}
            role has all permissions and cannot be deleted.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-background-card-header">
            <h3 className="text-sm font-semibold text-foreground">Available Permissions</h3>
          </div>
          <table className="w-full text-sm">
            <thead className="border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[240px]">Permission</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {permissions.map((p) => (
                <tr key={p.permission} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs text-foreground">{p.permission}</td>
                  <td className="px-4 py-2.5 text-foreground-secondary">{p.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Members */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Members</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Invite members by email from the <strong className="text-foreground">Members</strong> page.
            Each invitation includes a role assignment. Pending invitations can be resent or revoked.
            Once accepted, the member appears in the active list where their role can be changed or
            they can be removed.
          </p>
          <p>
            Members can also be added to one or more{" "}
            <Link to="/docs/teams" className="text-primary hover:underline">Teams</Link>{" "}
            for scoped project visibility and notification routing.
          </p>
        </div>
      </div>

      {/* Teams */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Teams</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Teams let you group members and scope their view to a subset of projects.
          Notifications and alerts can be routed to specific teams. See the{" "}
          <Link to="/docs/teams" className="text-primary hover:underline">Teams documentation</Link>{" "}
          for details on creating teams, assigning projects, and configuring team-level settings.
        </p>
      </div>

      {/* Integrations Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Integrations Overview</h2>
        <p className="text-foreground-secondary leading-relaxed">
          Integrations connect Deptex to your existing tools. Source-code providers
          (GitHub, GitLab, Bitbucket) enable repository scanning, while notification
          channels (Slack, Discord, email) and ticketing systems (Jira, Linear, Asana)
          let you route alerts where your team already works. See the{" "}
          <Link to="/docs/integrations" className="text-primary hover:underline">Integrations documentation</Link>{" "}
          for the full list and setup instructions.
        </p>
      </div>
    </div>
  );
}

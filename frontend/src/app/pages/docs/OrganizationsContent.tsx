import { Link } from "react-router-dom";

const permissions = [
  { permission: "manage_organization", description: "Edit organization name, logo, and general settings." },
  { permission: "manage_members", description: "Invite, remove, and change roles for organization members." },
  { permission: "manage_teams", description: "Create, edit, and delete teams and their project assignments." },
  { permission: "manage_projects", description: "Create, archive, and configure projects." },
  { permission: "manage_integrations", description: "Connect and remove third-party integrations (GitHub, Slack, etc.)." },
  { permission: "manage_policies", description: "Edit the organization-wide policy code." },
  { permission: "manage_compliance", description: "Manage policies, compliance, custom statuses, and asset tiers (bundled as Manage Policies in the role editor)." },
  { permission: "manage_notification_rules", description: "Create, edit, and delete notification rules." },
  { permission: "view_audit_logs", description: "View the organization audit log." },
];

export default function OrganizationsContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            An <strong className="text-foreground">Organization</strong> is the top-level container in Deptex. It holds your projects,
            teams, members, integrations, policies, and settings. Each user can belong to multiple organizations.
            Switch between organizations from the sidebar.
          </p>
        </div>
      </div>

      {/* Organization Settings */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Organization Settings</h2>
        <p className="text-foreground/90 leading-relaxed">
          Access settings from the sidebar under <strong className="text-foreground">Settings</strong>. The General tab lets you update
          the organization name, avatar, and default configurations (default asset tier for new projects, default branch to track).
          Requires <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_organization</code>.
        </p>
      </div>

      {/* Asset Tiers */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Asset Tiers</h2>
        <p className="text-foreground/90 leading-relaxed">
          The <strong className="text-foreground">Asset Tiers</strong> sub-tab (under Statuses) defines tiers such as Crown Jewels, External, Internal, and Non-Production. Each tier has an <strong className="text-foreground">environmental multiplier</strong> that weights Depscore by project criticality. Every project is assigned a tier; <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">packagePolicy</code> receives <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">context.tier</code> so you can apply stricter rules to higher tiers. See <Link to="/docs/policies" className="text-foreground underline hover:no-underline">Policies</Link> for how tier-aware package policy works.
        </p>
      </div>

      {/* Custom Statuses */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Custom Statuses</h2>
        <p className="text-foreground/90 leading-relaxed">
          The <strong className="text-foreground">Statuses</strong> tab lets you define custom project statuses: <strong className="text-foreground">name</strong>,{" "}
          <strong className="text-foreground">color</strong>, and <strong className="text-foreground">rank</strong> (ordering). Your <strong className="text-foreground">Status Code</strong> (<code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">projectStatus</code>) returns one of these names as a string — that is how a project gets its badge. See <Link to="/docs/policies" className="text-foreground underline hover:no-underline">Policies</Link> for examples. System statuses cannot be deleted but can be reordered.
        </p>
      </div>

      {/* Roles and Permissions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Roles and Permissions</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          Deptex uses <strong className="text-foreground">role-based access control</strong>. Each organization can define custom roles
          with a set of permissions. Members are assigned one role per organization. The built-in <strong className="text-foreground">Owner</strong> role
          has all permissions and cannot be deleted.
        </p>
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
                  <td className="px-4 py-2.5 text-foreground/90">{p.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Members */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Members</h2>
        <p className="text-foreground/90 leading-relaxed">
          Invite members by email from the <strong className="text-foreground">Members</strong> page. Each invitation includes a role assignment.
          Pending invitations can be resent or revoked. Once accepted, members can be added to{" "}
          <Link to="/docs/teams" className="text-foreground underline hover:no-underline">Teams</Link> for scoped project visibility.
        </p>
      </div>

      {/* Teams */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Teams</h2>
        <p className="text-foreground/90 leading-relaxed">
          Teams let you group members and scope their view to a subset of projects. Notifications can be routed to specific teams.
          See the <Link to="/docs/teams" className="text-foreground underline hover:no-underline">Teams</Link> documentation for details.
        </p>
      </div>

      {/* Integrations Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Integrations</h2>
        <p className="text-foreground/90 leading-relaxed">
          Integrations connect Deptex to your tools. Source-code providers (GitHub, GitLab, Bitbucket) enable repository scanning.
          Notification channels (Slack, Discord, email) and ticketing (Jira, Linear, Asana) route alerts. See{" "}
          <Link to="/docs/integrations" className="text-foreground underline hover:no-underline">Integrations</Link> for the full list and setup.
        </p>
      </div>
    </div>
  );
}

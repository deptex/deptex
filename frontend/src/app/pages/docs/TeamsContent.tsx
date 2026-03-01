import { Link } from "react-router-dom";

const rolePermissions = [
  { role: "Admin", scope: "All teams and projects regardless of membership", access: "Full access" },
  { role: "Member", scope: "Projects in assigned teams only", access: "View & manage" },
  { role: "Viewer", scope: "Projects in assigned teams only", access: "Read-only" },
  { role: "Billing", scope: "No project access", access: "Billing only" },
];

export default function TeamsContent() {
  return (
    <div className="space-y-12">
      {/* Overview */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Overview</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            <strong className="text-foreground">Teams</strong> provide scoped visibility within an{" "}
            <Link to="/docs/organizations" className="text-primary hover:underline">organization</Link>.
            Members of a team see only the{" "}
            <Link to="/docs/projects" className="text-primary hover:underline">projects</Link>{" "}
            assigned to that team, keeping dashboards focused and noise-free.
          </p>
          <p>
            This is especially useful for large organizations with multiple product teams —
            each team gets its own view of dependencies, vulnerabilities, and compliance
            without seeing unrelated projects.
          </p>
        </div>
      </div>

      {/* Creating a Team */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Creating a Team</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Navigate to the <strong className="text-foreground">Teams</strong> page from your
            organization sidebar and click{" "}
            <strong className="text-foreground">Create Team</strong>. Enter a name and an
            optional description to help members understand the team's scope.
          </p>
          <p>
            Team creation requires a role with the{" "}
            <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_teams</code>{" "}
            permission. See{" "}
            <Link to="/docs/organizations" className="text-primary hover:underline">Organizations → Roles and Permissions</Link>{" "}
            for details on configuring custom roles.
          </p>
        </div>
      </div>

      {/* Team Membership */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Team Membership</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            Add or remove members from a team on its detail page. Members can belong to
            multiple teams simultaneously — there is no limit.
          </p>
          <p>
            Team membership is <strong className="text-foreground">independent of org roles</strong>.
            A member's organization role (Admin, Member, Viewer, etc.) determines{" "}
            <em>what actions</em> they can perform, while team membership determines{" "}
            <em>which projects</em> they see.
          </p>
        </div>
        <div className="mt-4 rounded-lg border border-border bg-background-card p-4">
          <p className="text-sm text-foreground-secondary leading-relaxed">
            Removing a member from a team does not remove them from the organization.
            They retain access to any other teams they belong to.
          </p>
        </div>
      </div>

      {/* Project Assignment */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Project Assignment</h2>
        <div className="space-y-3 text-foreground-secondary leading-relaxed">
          <p>
            <Link to="/docs/projects" className="text-primary hover:underline">Projects</Link>{" "}
            can be assigned to a team during creation or later from{" "}
            <strong className="text-foreground">Project Settings</strong>. Each project belongs
            to at most one team. Projects without a team assignment remain visible to all
            organization members (org-wide visibility).
          </p>
          <p>
            The team page displays aggregated stats — dependency counts, vulnerability
            summaries, and compliance status — across all of its assigned projects.
          </p>
        </div>
      </div>

      {/* Team Dashboard */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Team Dashboard</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Selecting a team from the Teams page opens its dashboard with an at-a-glance
          view of everything the team owns.
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-background-card-header">
            <h3 className="text-sm font-semibold text-foreground">Dashboard Sections</h3>
          </div>
          <table className="w-full text-sm">
            <thead className="border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[200px]">Section</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-medium text-foreground">Members</td>
                <td className="px-4 py-3 text-foreground-secondary">List of team members with their org roles and avatars.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-medium text-foreground">Projects</td>
                <td className="px-4 py-3 text-foreground-secondary">Assigned projects with current status, health indicators, and last-scan timestamps.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-medium text-foreground">Vulnerabilities</td>
                <td className="px-4 py-3 text-foreground-secondary">Aggregated vulnerability counts by severity across all team projects.</td>
              </tr>
              <tr className="hover:bg-table-hover transition-colors">
                <td className="px-4 py-3 font-medium text-foreground">Compliance</td>
                <td className="px-4 py-3 text-foreground-secondary">Combined compliance summary showing policy pass/fail rates for the team's projects.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Permissions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Permissions</h2>
        <p className="text-foreground-secondary leading-relaxed mb-4">
          Team membership controls <em>visibility</em>, while{" "}
          <Link to="/docs/organizations" className="text-primary hover:underline">organization roles</Link>{" "}
          control <em>capabilities</em>. The table below shows how each role interacts with
          team-scoped resources.
        </p>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[120px]">Role</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">Project Scope</th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-foreground-secondary uppercase tracking-wider w-[140px]">Access Level</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rolePermissions.map((r) => (
                <tr key={r.role} className="hover:bg-table-hover transition-colors">
                  <td className="px-4 py-3 font-medium text-foreground">{r.role}</td>
                  <td className="px-4 py-3 text-foreground-secondary">{r.scope}</td>
                  <td className="px-4 py-3 text-foreground-secondary">{r.access}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

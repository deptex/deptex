import { Link } from "react-router-dom";

const rolePermissions = [
  { role: "Admin", scope: "All teams and projects", access: "Full access" },
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
        <div className="space-y-3 text-foreground/90 leading-relaxed">
          <p>
            <strong className="text-foreground">Teams</strong> provide scoped visibility within an{" "}
            <Link to="/docs/organizations" className="text-foreground underline hover:no-underline">organization</Link>.
            Members of a team see only the{" "}
            <Link to="/docs/projects" className="text-foreground underline hover:no-underline">projects</Link> assigned to that team.
          </p>
          <p>
            Useful for large organizations — each team gets its own view of dependencies, vulnerabilities, and compliance
            without seeing unrelated projects.
          </p>
        </div>
      </div>

      {/* Creating a Team */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Creating a Team</h2>
        <p className="text-foreground/90 leading-relaxed">
          Go to the <strong className="text-foreground">Teams</strong> page from your organization sidebar and click{" "}
          <strong className="text-foreground">Create Team</strong>. Enter a name and optional description. Requires{" "}
          <code className="rounded bg-background-subtle px-1.5 py-0.5 text-xs font-mono">manage_teams</code>.
        </p>
      </div>

      {/* Team Membership */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Team Membership</h2>
        <p className="text-foreground/90 leading-relaxed">
          Add or remove members from a team on its detail page. Members can belong to multiple teams. Team membership is{" "}
          <strong className="text-foreground">independent of org roles</strong> — org role determines what actions they can perform,
          team membership determines which projects they see. Removing a member from a team does not remove them from the organization.
        </p>
      </div>

      {/* Project Assignment */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Project Assignment</h2>
        <p className="text-foreground/90 leading-relaxed">
          <Link to="/docs/projects" className="text-foreground underline hover:no-underline">Projects</Link> can be assigned to a team
          during creation or from <strong className="text-foreground">Project Settings</strong>. Each project belongs to at most one team.
          Projects without a team assignment remain visible to all org members. The team page shows aggregated stats across its projects.
        </p>
      </div>

      {/* Team Dashboard */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Team Dashboard</h2>
        <p className="text-foreground/90 leading-relaxed">
          Selecting a team opens its dashboard: members, assigned projects with status and health indicators, aggregated vulnerability counts,
          and compliance summary.
        </p>
      </div>

      {/* Permissions */}
      <div>
        <h2 className="text-lg font-semibold text-foreground mb-3">Permissions</h2>
        <p className="text-foreground/90 leading-relaxed mb-4">
          Team membership controls <em>visibility</em>;{" "}
          <Link to="/docs/organizations" className="text-foreground underline hover:no-underline">organization roles</Link> control{" "}
          <em>capabilities</em>.
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
                  <td className="px-4 py-3 text-foreground/90">{r.scope}</td>
                  <td className="px-4 py-3 text-foreground/90">{r.access}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

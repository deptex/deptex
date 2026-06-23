import { Building2, Users, FolderGit2 } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Level {
  label: string;
  icon: LucideIcon;
  body: string;
}

const hierarchy: Level[] = [
  {
    label: "Organization",
    icon: Building2,
    body: "The top-level container for your members, teams, projects, billing, and settings.",
  },
  {
    label: "Teams",
    icon: Users,
    body: "Group members and projects together with scoped access, so people only see the work that's theirs.",
  },
  {
    label: "Projects",
    icon: FolderGit2,
    body: "The individual repositories Deptex scans, each owned by a team.",
  },
];

export default function OrganizationsRolesContent() {
  return (
    <div className="space-y-12">
      <section>
        <p className="text-foreground/90 leading-relaxed">
          Your organization is the top-level container for everything in Deptex. Inside it, teams
          group people and projects together, and roles decide what each person can do.
        </p>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-4">The hierarchy</h2>
        <div className="rounded-lg border border-border bg-background-card divide-y divide-border">
          {hierarchy.map((level) => {
            const Icon = level.icon;
            return (
              <div key={level.label} className="flex gap-4 p-5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-background-subtle">
                  <Icon className="h-5 w-5 text-foreground" />
                </span>
                <div>
                  <h3 className="font-medium text-foreground">{level.label}</h3>
                  <p className="mt-1 text-sm leading-relaxed text-foreground/80">{level.body}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-2">Roles &amp; permissions</h2>
        <div className="space-y-4 text-foreground/90 leading-relaxed">
          <p>
            Roles in Deptex are bundles of permissions you define yourself — not a fixed ladder.
            Every organization starts with two: <strong className="text-foreground">owner</strong>,
            which holds every permission and can&apos;t be removed, and{" "}
            <strong className="text-foreground">member</strong>. From there you can add, rename, and
            delete your own roles, granting each exactly the permissions it needs.
          </p>
          <p>
            Permissions are granular — managing members, editing policies, configuring integrations,
            triggering AI fixes, viewing billing, and more. You authorize by what a role can do, not
            by its name, so there&apos;s no special &ldquo;admin&rdquo; role to reason about. Owner
            is the only role guaranteed to exist.
          </p>
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-foreground mb-2">Members &amp; teams</h2>
        <p className="text-foreground/90 leading-relaxed">
          Invite members by email and assign them an organization role. Members can also belong to
          teams, which carry their own team-scoped roles — so someone can manage one team&apos;s
          projects without gaining access across the whole organization.
        </p>
      </section>
    </div>
  );
}

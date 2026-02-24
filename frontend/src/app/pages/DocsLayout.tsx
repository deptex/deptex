import { Link, useParams } from "react-router-dom";
import { cn } from "../../lib/utils";
import DocsPage from "./DocsPage";

interface DocNavItem {
  label: string;
  slug: string;
}

interface DocNavGroup {
  title: string;
  items: DocNavItem[];
}

const docNavGroups: DocNavGroup[] = [
  {
    title: "Getting Started",
    items: [
      { label: "Introduction", slug: "introduction" },
      { label: "Quick Start", slug: "quick-start" },
    ],
  },
  {
    title: "Core Concepts",
    items: [
      { label: "Projects", slug: "projects" },
      { label: "Dependencies", slug: "dependencies" },
      { label: "Vulnerabilities", slug: "vulnerabilities" },
      { label: "Compliance", slug: "compliance" },
    ],
  },
  {
    title: "Features",
    items: [
      { label: "Dependency Tracking", slug: "dependency-tracking" },
      { label: "Vulnerability Intelligence", slug: "vulnerability-intelligence" },
      { label: "SBOM Compliance", slug: "sbom-compliance" },
      { label: "Anomaly Detection", slug: "anomaly-detection" },
      { label: "Security Agent", slug: "security-agent" },
    ],
  },
  {
    title: "Administration",
    items: [
      { label: "Organizations", slug: "organizations" },
      { label: "Teams", slug: "teams" },
      { label: "Policies", slug: "policies" },
      { label: "Integrations", slug: "integrations" },
    ],
  },
];

export default function DocsLayout() {
  const { section } = useParams<{ section: string }>();

  return (
    <div className={cn("flex min-h-screen", "pt-14")}>
      {/* Sidebar */}
      <aside
        className={cn(
          "hidden lg:flex flex-col w-64 shrink-0 border-r border-border bg-background sticky overflow-y-auto custom-scrollbar",
          "top-14 h-[calc(100vh-3.5rem)]"
        )}
      >
        <div className="px-4 pt-5 pb-8 space-y-6">
          {docNavGroups.map((group) => (
            <div key={group.title}>
              <p className="px-2 mb-1.5 text-xs font-semibold uppercase tracking-wider text-foreground-muted">
                {group.title}
              </p>
              <ul className="space-y-0.5">
                {group.items.map((item) => {
                  const isActive = section === item.slug;
                  return (
                    <li key={item.slug}>
                      <Link
                        to={`/docs/${item.slug}`}
                        className={cn(
                          "block rounded-md px-2 py-1.5 text-sm transition-colors",
                          isActive
                            ? "bg-background-card text-foreground font-medium"
                            : "text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50"
                        )}
                      >
                        {item.label}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
      </aside>

      {/* Content */}
      <main className="flex-1 min-w-0 px-8 pt-12 pb-10 max-w-3xl">
        <DocsPage section={section} />
      </main>
    </div>
  );
}

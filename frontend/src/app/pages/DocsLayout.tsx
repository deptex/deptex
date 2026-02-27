import { Link, useParams } from "react-router-dom";
import { Rocket, BookOpen, Sparkles, Settings } from "lucide-react";
import { cn } from "../../lib/utils";
import DocsPage from "./DocsPage";
import { docNavGroups } from "./docsConfig";

const groupIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  Rocket,
  BookOpen,
  Sparkles,
  Settings,
};

export default function DocsLayout() {
  const { section } = useParams<{ section: string }>();

  return (
    <div className={cn("flex min-h-screen", "pt-14")}>
      {/* Sidebar - fixed so it stays put, only content scrolls */}
      <aside
        className={cn(
          "hidden lg:flex flex-col w-64 shrink-0 border-r border-border bg-background-card-header fixed overflow-y-auto custom-scrollbar",
          "left-0 top-14 h-[calc(100vh-3.5rem)] z-40"
        )}
      >
        <div className="px-4 pt-5 pb-8 space-y-6">
          {docNavGroups.map((group) => {
            const Icon = groupIcons[group.icon];
            return (
              <div key={group.title}>
                <p className="px-2 mb-1.5 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-foreground">
                  {Icon && <Icon className="h-3.5 w-3.5 shrink-0 opacity-70" />}
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
                              ? "bg-white/[0.06] text-foreground font-medium"
                              : "text-foreground hover:text-foreground hover:bg-white/[0.04]"
                          )}
                        >
                          {item.label}
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              </div>
            );
          })}
        </div>
      </aside>

      {/* Content - offset for fixed sidebar on lg+, centered in remaining space */}
      <main className="flex-1 min-w-0 flex justify-center lg:ml-64">
        <div className="w-full max-w-5xl px-8 pt-12 pb-10">
          <DocsPage section={section} />
        </div>
      </main>
    </div>
  );
}

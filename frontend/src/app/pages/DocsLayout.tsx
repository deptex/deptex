import { useEffect, useMemo, useState } from "react";
import type { ComponentType } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { cn } from "../../lib/utils";
import {
  docSections,
  docPagesBySlug,
  groupLabelForSlug,
  type DocSection,
} from "./docsConfig";
import IntroductionContent from "./docs/IntroductionContent";
import ReachabilityDepscoreContent from "./docs/ReachabilityDepscoreContent";
import FindingTypesContent from "./docs/FindingTypesContent";
import DependencyScanningContent from "./docs/DependencyScanningContent";
import CodeScanningContent from "./docs/CodeScanningContent";
import InfrastructureDastContent from "./docs/InfrastructureDastContent";
import AegisPageContent from "./docs/AegisPageContent";
import ProjectsAdminContent from "./docs/ProjectsAdminContent";
import OrganizationsRolesContent from "./docs/OrganizationsRolesContent";
import IntegrationsAdminContent from "./docs/IntegrationsAdminContent";
import BillingUsageContent from "./docs/BillingUsageContent";
import HelpContent from "./docs/HelpContent";
import TermsContent from "./docs/TermsContent";
import PrivacyContent from "./docs/PrivacyContent";
import SecurityContent from "./docs/SecurityContent";

// Slugs with a real page built. Everything else renders the "coming soon"
// placeholder until its page lands.
const docsContent: Record<string, ComponentType> = {
  introduction: IntroductionContent,
  "reachability-depscore": ReachabilityDepscoreContent,
  "finding-types": FindingTypesContent,
  dependencies: DependencyScanningContent,
  code: CodeScanningContent,
  "infrastructure-dast": InfrastructureDastContent,
  aegis: AegisPageContent,
  projects: ProjectsAdminContent,
  organizations: OrganizationsRolesContent,
  integrations: IntegrationsAdminContent,
  billing: BillingUsageContent,
  help: HelpContent,
  terms: TermsContent,
  privacy: PrivacyContent,
  security: SecurityContent,
};

const navBtn = (active: boolean) =>
  cn(
    "nav-btn flex w-full items-center gap-3 overflow-hidden rounded-md px-3 h-9 text-sm text-left font-medium transition-colors",
    active
      ? "bg-background-subtle/85 text-foreground"
      : "text-foreground-secondary hover:bg-background-subtle/85 hover:text-foreground",
  );

export default function DocsLayout() {
  const { section } = useParams<{ section: string }>();
  const navigate = useNavigate();
  const activeSlug = section ?? "introduction";
  const page = docPagesBySlug[activeSlug];

  // Which top-level group is drilled into. null = showing the top-level list.
  // Defaults to the top-level list so the first thing you see is the category
  // list (like the app's main nav) — you click through to open sub-options.
  const parentGroup = useMemo(() => groupLabelForSlug(activeSlug), [activeSlug]);
  const [openGroup, setOpenGroup] = useState<string | null>(null);

  // Keep the drilldown coherent with the active page when navigating across
  // groups (browser back/forward, deep links). Once backed out to the top
  // level (null) we stay there until the user clicks into a group.
  useEffect(() => {
    setOpenGroup((prev) => (prev === null ? null : parentGroup));
  }, [activeSlug, parentGroup]);

  const activeGroup = useMemo<DocSection | undefined>(
    () => docSections.find((s) => s.type === "group" && s.label === openGroup),
    [openGroup],
  );

  const enterGroup = (sectionDef: Extract<DocSection, { type: "group" }>) => {
    setOpenGroup(sectionDef.label);
    navigate(`/docs/${sectionDef.items[0].slug}`);
  };

  return (
    <div className={cn("flex min-h-screen", "pt-14")}>
      {/* Sidebar — fixed under the header, app-style drilldown nav */}
      <aside
        className={cn(
          "hidden lg:block w-64 shrink-0 border-r border-border bg-background fixed overflow-hidden",
          "left-0 top-14 h-[calc(100vh-3.5rem)] z-40",
        )}
      >
        <div className="relative h-full">
          {/* Top-level sections — fades out left when a group is open */}
          <div
            className={cn(
              "absolute inset-0 px-3 py-4 overflow-y-auto custom-scrollbar transition-[opacity,transform] duration-150 ease-out",
              openGroup
                ? "opacity-0 -translate-x-2 pointer-events-none"
                : "opacity-100 translate-x-0",
            )}
          >
            <ul className="flex w-full min-w-0 flex-col gap-0.5">
              {docSections.map((sectionDef) => {
                const Icon = sectionDef.icon;
                if (sectionDef.type === "page") {
                  const isActive = activeSlug === sectionDef.slug;
                  return (
                    <li key={sectionDef.slug}>
                      <Link to={`/docs/${sectionDef.slug}`} className={navBtn(isActive)}>
                        <Icon className="h-5 w-5 shrink-0 tab-icon-shake" />
                        <span className="truncate">{sectionDef.label}</span>
                      </Link>
                    </li>
                  );
                }
                const ownsActive = sectionDef.items.some((i) => i.slug === activeSlug);
                return (
                  <li key={sectionDef.label}>
                    <button
                      type="button"
                      onClick={() => enterGroup(sectionDef)}
                      className={navBtn(ownsActive)}
                    >
                      <Icon className="h-5 w-5 shrink-0 tab-icon-shake" />
                      <span className="truncate">{sectionDef.label}</span>
                      <ChevronRight className="ml-auto h-4 w-4 shrink-0 text-foreground-secondary" />
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>

          {/* Drilldown — fades in from the right when a group is open */}
          <div
            className={cn(
              "absolute inset-0 px-3 py-4 overflow-y-auto custom-scrollbar transition-[opacity,transform] duration-150 ease-out",
              openGroup
                ? "opacity-100 translate-x-0"
                : "opacity-0 translate-x-2 pointer-events-none",
            )}
          >
            {activeGroup?.type === "group" && (
              <ul className="flex w-full min-w-0 flex-col gap-0.5">
                <li>
                  <button
                    type="button"
                    onClick={() => setOpenGroup(null)}
                    className="nav-btn relative w-full flex items-center justify-center h-9 rounded-md px-3 text-sm font-medium text-foreground-secondary hover:bg-background-subtle/75 hover:text-foreground transition-colors"
                  >
                    <ChevronLeft className="absolute left-3 h-5 w-5 tab-icon-shake" />
                    <span>{activeGroup.label}</span>
                  </button>
                </li>
                {activeGroup.items.map((item) => {
                  const ItemIcon = item.icon;
                  const isActive = activeSlug === item.slug;
                  return (
                    <li key={item.slug}>
                      <Link to={`/docs/${item.slug}`} className={navBtn(isActive)}>
                        <ItemIcon className="h-5 w-5 shrink-0 tab-icon-shake" />
                        <span className="truncate">{item.label}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      </aside>

      {/* Content — offset for the fixed sidebar on lg+, centered in remaining space */}
      <main className="flex-1 min-w-0 flex justify-center lg:ml-64">
        <div className="w-full max-w-4xl px-8 pt-12 pb-10">
          {page ? (
            (() => {
              const Content = docsContent[activeSlug];
              return (
                <article>
                  <div className="mb-8 pb-8 border-b border-border">
                    <p className="text-xs font-semibold uppercase tracking-wider text-foreground/60 mb-3">
                      Documentation
                    </p>
                    <h1 className="text-3xl font-semibold text-foreground mb-3">{page.label}</h1>
                    <p className="text-base text-foreground/85 leading-relaxed">{page.description}</p>
                  </div>

                  {Content ? (
                    <Content />
                  ) : (
                    <div className="rounded-lg border border-dashed border-border bg-background-card px-6 py-20 text-center">
                      <p className="text-sm text-foreground-muted">This page is coming soon.</p>
                    </div>
                  )}
                </article>
              );
            })()
          ) : (
            <article>
              <div className="mb-8 pb-8 border-b border-border">
                <h1 className="text-3xl font-semibold text-foreground mb-3">Page not found</h1>
                <p className="text-base text-foreground/85 leading-relaxed">
                  This documentation page doesn&apos;t exist.{" "}
                  <Link to="/docs/introduction" className="text-accent-text hover:underline">
                    Back to Introduction
                  </Link>
                  .
                </p>
              </div>
            </article>
          )}
        </div>
      </main>
    </div>
  );
}

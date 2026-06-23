import {
  BookOpen,
  Lightbulb,
  Crosshair,
  Bug,
  ScanSearch,
  Package,
  Code,
  Server,
  MessageSquare,
  Building2,
  FolderGit2,
  Users,
  Plug,
  CreditCard,
  LifeBuoy,
  Scale,
  FileText,
  Lock,
  Shield,
  type LucideIcon,
} from "lucide-react";

/** A single documentation page (a leaf in the nav). */
export interface DocPage {
  label: string;
  slug: string;
  icon: LucideIcon;
  description: string;
}

/**
 * A top-level entry in the docs sidebar. Either a `group` that drills down into
 * sub-pages (like Settings/Aegis in the app sidebar) or a `page` that links
 * straight to a single doc (like Overview/Findings).
 */
export type DocSection =
  | { type: "group"; label: string; icon: LucideIcon; items: DocPage[] }
  | { type: "page"; label: string; icon: LucideIcon; slug: string; description: string };

export const docSections: DocSection[] = [
  {
    type: "page",
    label: "Introduction",
    icon: BookOpen,
    slug: "introduction",
    description: "What Deptex is and how it secures your dependencies, code, and infrastructure.",
  },
  {
    type: "group",
    label: "Concepts",
    icon: Lightbulb,
    items: [
      {
        label: "Reachability & Depscore",
        slug: "reachability-depscore",
        icon: Crosshair,
        description: "How Deptex scores each finding by what's actually exploitable in your code.",
      },
      {
        label: "Finding types",
        slug: "finding-types",
        icon: Bug,
        description: "The categories of issues Deptex surfaces and how they're triaged.",
      },
    ],
  },
  {
    type: "group",
    label: "Scanning",
    icon: ScanSearch,
    items: [
      {
        label: "Dependencies",
        slug: "dependencies",
        icon: Package,
        description: "Dependency CVEs, supply-chain signals, and malicious package detection.",
      },
      {
        label: "Code",
        slug: "code",
        icon: Code,
        description: "Static analysis (SAST) and live-verified secret detection across your codebase.",
      },
      {
        label: "Infrastructure & DAST",
        slug: "infrastructure-dast",
        icon: Server,
        description: "IaC misconfigurations, container image CVEs, and active runtime testing.",
      },
    ],
  },
  {
    type: "page",
    label: "Aegis",
    icon: MessageSquare,
    slug: "aegis",
    description: "The autonomous security agent that investigates findings and ships fixes.",
  },
  {
    type: "group",
    label: "Administration",
    icon: Building2,
    items: [
      {
        label: "Projects",
        slug: "projects",
        icon: FolderGit2,
        description: "How Deptex models repositories, runs scans, and tracks their status.",
      },
      {
        label: "Organizations & roles",
        slug: "organizations",
        icon: Users,
        description: "Members, role-based permissions, and team-scoped project access.",
      },
      {
        label: "Integrations",
        slug: "integrations",
        icon: Plug,
        description: "Connect GitHub, GitLab, Bitbucket, Slack, Jira, Linear, and more.",
      },
      {
        label: "Billing & usage",
        slug: "billing",
        icon: CreditCard,
        description: "Prepaid balance, usage metering, top-ups, and auto-recharge.",
      },
    ],
  },
  {
    type: "page",
    label: "Help",
    icon: LifeBuoy,
    slug: "help",
    description: "Troubleshooting, frequently asked questions, and how to reach us.",
  },
  {
    type: "group",
    label: "Legal",
    icon: Scale,
    items: [
      {
        label: "Terms of Service",
        slug: "terms",
        icon: FileText,
        description: "The terms governing your use of Deptex.",
      },
      {
        label: "Privacy Policy",
        slug: "privacy",
        icon: Lock,
        description: "How we collect, use, and protect your data.",
      },
      {
        label: "Security",
        slug: "security",
        icon: Shield,
        description: "Our security practices and commitments.",
      },
    ],
  },
];

/** Flattened page metadata keyed by slug — leaves and single pages alike. */
export const docPagesBySlug: Record<string, DocPage> = Object.fromEntries(
  docSections.flatMap((section) =>
    section.type === "group"
      ? section.items
      : [{ label: section.label, slug: section.slug, icon: section.icon, description: section.description }],
  ).map((page) => [page.slug, page]),
);

/** The group label that owns a given slug, or null for top-level single pages. */
export function groupLabelForSlug(slug: string): string | null {
  for (const section of docSections) {
    if (section.type === "group" && section.items.some((i) => i.slug === slug)) {
      return section.label;
    }
  }
  return null;
}

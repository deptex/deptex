export interface DocNavItem {
  label: string;
  slug: string;
  description?: string;
}

export interface DocNavGroup {
  title: string;
  icon: string; // Lucide icon name
  items: DocNavItem[];
}

export const docNavGroups: DocNavGroup[] = [
  {
    title: "Getting Started",
    icon: "Rocket",
    items: [
      { label: "Introduction", slug: "introduction", description: "Learn what Deptex is and how it helps manage dependency security." },
      { label: "Quick Start", slug: "quick-start", description: "Get up and running with Deptex in minutes." },
    ],
  },
  {
    title: "Core Concepts",
    icon: "BookOpen",
    items: [
      { label: "Projects", slug: "projects", description: "Understand how Deptex models repositories as projects." },
      { label: "Dependencies", slug: "dependencies", description: "Explore dependency resolution and monitoring." },
      { label: "Vulnerabilities", slug: "vulnerabilities", description: "See how Deptex surfaces CVEs and advisories." },
      { label: "Compliance", slug: "compliance", description: "Learn compliance frameworks and license policies." },
      { label: "SBOM Compliance", slug: "sbom-compliance", description: "Generate and track Software Bills of Materials." },
    ],
  },
  {
    title: "Administration",
    icon: "Settings",
    items: [
      { label: "Organizations", slug: "organizations", description: "Manage organization and settings." },
      { label: "Teams", slug: "teams", description: "Organize members with scoped visibility." },
      { label: "Policies", slug: "policies", description: "Define security and compliance policies." },
      { label: "Integrations", slug: "integrations", description: "Connect with GitHub, Slack, CI/CD, and more." },
      { label: "Notification Rules", slug: "notification-rules", description: "Configure automated alerts and notification triggers." },
    ],
  },
  {
    title: "Legal",
    icon: "FileCheck",
    items: [
      { label: "Terms of Service", slug: "terms", description: "Terms governing your use of Deptex." },
      { label: "Privacy Policy", slug: "privacy", description: "How we collect, use, and protect your data." },
      { label: "Security", slug: "security", description: "Our security practices and commitment." },
    ],
  },
];

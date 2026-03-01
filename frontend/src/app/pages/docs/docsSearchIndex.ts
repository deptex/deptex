export interface SearchEntry {
  slug: string;
  section: string;
  heading: string;
  content: string;
  keywords: string[];
}

export const docsSearchIndex: SearchEntry[] = [
  // Getting Started
  {
    slug: "introduction",
    section: "Getting Started",
    heading: "Introduction",
    content: "Deptex is a security and compliance platform for your dependency supply chain. It connects to your repositories, tracks every dependency, and gives you a single place to see risks and enforce policies.",
    keywords: ["overview", "what is deptex", "getting started", "dependency", "security", "supply chain"],
  },
  {
    slug: "quick-start",
    section: "Getting Started",
    heading: "Quick Start",
    content: "Get up and running with Deptex in minutes. Create an organization, connect an integration, create a project, and explore your dashboard.",
    keywords: ["setup", "onboarding", "first steps", "connect", "github", "create project"],
  },

  // Core Concepts - Projects
  {
    slug: "projects",
    section: "Core Concepts",
    heading: "Projects Overview",
    content: "A project in Deptex represents a monitored repository. Each project tracks dependencies, vulnerabilities, compliance status, and extraction history.",
    keywords: ["repository", "repo", "project", "monitor"],
  },
  {
    slug: "projects",
    section: "Core Concepts",
    heading: "Extraction Pipeline",
    content: "During extraction: clone repository, generate SBOM with cdxgen, scan vulnerabilities with dep-scan, run SAST analysis with Semgrep, detect secrets with TruffleHog, compute scores.",
    keywords: ["extraction", "scan", "cdxgen", "dep-scan", "semgrep", "trufflehog", "sbom", "pipeline"],
  },
  {
    slug: "projects",
    section: "Core Concepts",
    heading: "Live Extraction Logs",
    content: "Real-time extraction progress with color-coded log levels. View historical extraction runs and stream logs live via Supabase Realtime.",
    keywords: ["logs", "realtime", "extraction progress", "live"],
  },
  {
    slug: "projects",
    section: "Core Concepts",
    heading: "Asset Tiers",
    content: "Projects are assigned an asset tier: Crown Jewels (1.5x), External (1.2x), Internal (1.0x), or Non-Production (0.6x). Tiers affect vulnerability risk scoring.",
    keywords: ["asset tier", "crown jewels", "criticality", "classification"],
  },

  // Core Concepts - Dependencies
  {
    slug: "dependencies",
    section: "Core Concepts",
    heading: "Dependencies Overview",
    content: "How Deptex discovers and tracks dependencies from manifest files and lockfiles. Supports npm, pip, Go, Maven, Cargo, Bundler, and more.",
    keywords: ["dependency", "package", "manifest", "lockfile", "npm", "pip", "maven", "cargo"],
  },
  {
    slug: "dependencies",
    section: "Core Concepts",
    heading: "Dependency Score",
    content: "Package reputation score (0-100). Based on OpenSSF Scorecard (40%), popularity and downloads (30%), maintenance and releases (30%). SLSA bonus for verified provenance, penalty for malicious flags.",
    keywords: ["dependency score", "reputation", "openssf", "scorecard", "score", "rating"],
  },
  {
    slug: "dependencies",
    section: "Core Concepts",
    heading: "Direct vs Transitive Dependencies",
    content: "Direct dependencies appear in your manifest. Transitive dependencies are pulled in by other packages. Transitive deps get a 0.75x multiplier in Depscore.",
    keywords: ["direct", "transitive", "indirect", "dependency tree"],
  },
  {
    slug: "dependencies",
    section: "Core Concepts",
    heading: "Supply Chain Signals",
    content: "Registry integrity checks, install script analysis, and entropy/obfuscation detection. Each returns pass, warning, or fail status.",
    keywords: ["supply chain", "registry", "install scripts", "entropy", "obfuscation", "integrity"],
  },
  {
    slug: "dependencies",
    section: "Core Concepts",
    heading: "Malicious Package Detection",
    content: "Deptex checks packages against known malicious package databases. Flagged packages include source, confidence level, and reason.",
    keywords: ["malicious", "malware", "flagged", "suspicious", "compromised"],
  },
  {
    slug: "dependencies",
    section: "Core Concepts",
    heading: "SLSA Provenance",
    content: "SLSA (Supply chain Levels for Software Artifacts) verification. Levels 0-4 indicate build provenance guarantees.",
    keywords: ["slsa", "provenance", "build", "verification", "supply chain levels"],
  },

  // Core Concepts - Vulnerabilities
  {
    slug: "vulnerabilities",
    section: "Core Concepts",
    heading: "Vulnerabilities Overview",
    content: "How Deptex discovers, enriches, and prioritizes vulnerabilities using dep-scan, OSV, and NVD databases.",
    keywords: ["vulnerability", "cve", "advisory", "osv", "nvd", "dep-scan"],
  },
  {
    slug: "vulnerabilities",
    section: "Core Concepts",
    heading: "Depscore",
    content: "Composite risk score (0-100). Formula: baseImpact × threatMultiplier × environmentalMultiplier × dependencyContextMultiplier. Combines CVSS, EPSS, KEV, reachability, and asset tier.",
    keywords: ["depscore", "risk score", "cvss", "epss", "kev", "scoring", "formula"],
  },
  {
    slug: "vulnerabilities",
    section: "Core Concepts",
    heading: "Reachability Analysis",
    content: "Static analysis determines if vulnerable code paths are reachable. Tiers: Reachable (confirmed call path), Potentially Reachable, Unreachable (0.4x multiplier), Unknown.",
    keywords: ["reachability", "reachable", "static analysis", "code path", "semgrep"],
  },
  {
    slug: "vulnerabilities",
    section: "Core Concepts",
    heading: "EPSS Scoring",
    content: "Exploit Prediction Scoring System estimates probability of exploitation in the next 30 days. Differs from CVSS by measuring likelihood rather than severity.",
    keywords: ["epss", "exploit prediction", "probability", "exploitation"],
  },
  {
    slug: "vulnerabilities",
    section: "Core Concepts",
    heading: "CISA KEV",
    content: "Known Exploited Vulnerabilities catalog. Vulnerabilities actively exploited in the wild. Adds a 1.3x boost to Depscore.",
    keywords: ["cisa", "kev", "known exploited", "actively exploited"],
  },
  {
    slug: "vulnerabilities",
    section: "Core Concepts",
    heading: "AI-Powered Fixing",
    content: "Aider integration generates patches: clones repo, analyzes vulnerable code, generates fix, creates a pull request. Fixes are always created as draft PRs for human review.",
    keywords: ["ai fix", "aider", "patch", "automated fix", "pull request", "remediation"],
  },

  // Core Concepts - Compliance
  {
    slug: "compliance",
    section: "Core Concepts",
    heading: "Compliance Overview",
    content: "Custom statuses, policy-as-code, and license tracking. Organizations define their own compliance workflow.",
    keywords: ["compliance", "status", "license", "policy"],
  },
  {
    slug: "compliance",
    section: "Core Concepts",
    heading: "Custom Statuses",
    content: "Organizations define statuses in Settings with name, color, rank, and is_passing flag. Policy code returns status names to classify projects.",
    keywords: ["custom status", "is_passing", "status label", "compliant", "non-compliant"],
  },
  {
    slug: "compliance",
    section: "Core Concepts",
    heading: "SBOM Export",
    content: "Export SBOMs in CycloneDX 1.5 or SPDX format from the Compliance tab. Generated by cdxgen during extraction.",
    keywords: ["sbom", "cyclonedx", "spdx", "export", "bill of materials"],
  },
  {
    slug: "compliance",
    section: "Core Concepts",
    heading: "Policy Changes",
    content: "Git-like policy versioning. Projects can deviate from org policy through a commit-chain model with conflict resolution, AI merge, and revert capabilities.",
    keywords: ["policy changes", "versioning", "override", "exception", "merge", "revert"],
  },
  {
    slug: "compliance",
    section: "Core Concepts",
    heading: "Preflight Check",
    content: "Test whether adding a package would affect your project's compliance status before committing the change.",
    keywords: ["preflight", "preview", "test", "simulate", "check package"],
  },

  // Core Concepts - SBOM
  {
    slug: "sbom-compliance",
    section: "Core Concepts",
    heading: "SBOM Compliance",
    content: "Software Bill of Materials generation and compliance tracking. Supports CycloneDX 1.5 and SPDX formats with legal notice generation.",
    keywords: ["sbom", "bill of materials", "cyclonedx", "spdx", "legal notice"],
  },
  {
    slug: "sbom-compliance",
    section: "Core Concepts",
    heading: "Compliance Frameworks",
    content: "SBOMs support compliance with Executive Order 14028, NTIA minimum elements, and the EU Cyber Resilience Act.",
    keywords: ["eo 14028", "ntia", "eu cra", "cyber resilience", "executive order", "regulation"],
  },

  // Administration - Organizations
  {
    slug: "organizations",
    section: "Administration",
    heading: "Organizations",
    content: "Manage your organization, members, teams, roles, and settings. Multi-org support for managing multiple organizations.",
    keywords: ["organization", "org", "settings", "manage"],
  },
  {
    slug: "organizations",
    section: "Administration",
    heading: "Roles and Permissions",
    content: "Role-based access control with permissions like manage_statuses, manage_compliance, manage_integrations, manage_teams, manage_members.",
    keywords: ["role", "permission", "rbac", "access control", "admin", "member", "viewer"],
  },

  // Administration - Teams
  {
    slug: "teams",
    section: "Administration",
    heading: "Teams",
    content: "Organize members into teams with scoped project visibility. Team membership determines which projects a member can see.",
    keywords: ["team", "scope", "visibility", "group", "membership"],
  },

  // Administration - Policies
  {
    slug: "policies",
    section: "Administration",
    heading: "Policy-as-Code",
    content: "Define organization-wide rules as JavaScript functions. Policy code evaluates against real dependency and vulnerability data.",
    keywords: ["policy", "code", "javascript", "rules", "compliance"],
  },
  {
    slug: "policies",
    section: "Administration",
    heading: "Policy Functions",
    content: "Three functions: packagePolicy (per-dependency), projectStatus (project compliance), pullRequestCheck (PR guardrails). Each receives a context object with rich data.",
    keywords: ["packagePolicy", "projectStatus", "pullRequestCheck", "function", "context"],
  },
  {
    slug: "policies",
    section: "Administration",
    heading: "Built-in Functions",
    content: "fetch() for HTTP requests, isLicenseAllowed() for license checks, semverGt() for version comparison, daysSince() for date calculations.",
    keywords: ["fetch", "isLicenseAllowed", "semverGt", "daysSince", "built-in", "helper"],
  },

  // Administration - Integrations
  {
    slug: "integrations",
    section: "Administration",
    heading: "Integrations",
    content: "Connect with GitHub, GitLab, Bitbucket, Slack, Discord, Jira, Linear, Asana, email, and custom webhooks.",
    keywords: ["integration", "github", "gitlab", "bitbucket", "slack", "discord", "jira", "linear", "webhook"],
  },
  {
    slug: "integrations",
    section: "Administration",
    heading: "Custom Webhooks",
    content: "Bring-your-own-endpoint webhooks with HMAC-SHA256 signing. Receive events at any HTTPS URL.",
    keywords: ["webhook", "custom", "hmac", "signing", "endpoint"],
  },

  // Administration - Notification Rules
  {
    slug: "notification-rules",
    section: "Administration",
    heading: "Notification Rules",
    content: "Automated alerts with JavaScript trigger functions and multiple destinations. Events include vulnerability discovered, dependency changes, compliance violations, and more.",
    keywords: ["notification", "alert", "trigger", "rule", "event"],
  },
  {
    slug: "notification-rules",
    section: "Administration",
    heading: "Trigger Events",
    content: "20 event types including vulnerability_discovered, dependency_added, compliance_violation, malicious_package_detected, pr_check_completed, ai_fix_completed.",
    keywords: ["event", "trigger", "vulnerability_discovered", "malicious_package_detected", "pr_check"],
  },

  // Legal
  {
    slug: "terms",
    section: "Legal",
    heading: "Terms of Service",
    content: "Terms governing your use of Deptex. By using our platform, you agree to these terms.",
    keywords: ["terms", "service", "legal", "agreement"],
  },
  {
    slug: "privacy",
    section: "Legal",
    heading: "Privacy Policy",
    content: "How Deptex collects, uses, and protects your information. We do not sell your personal information.",
    keywords: ["privacy", "data", "personal information", "gdpr"],
  },
  {
    slug: "security",
    section: "Legal",
    heading: "Security Practices",
    content: "Security is at the core of Deptex. Encryption in transit and at rest, role-based access control, SSO and MFA support.",
    keywords: ["security", "encryption", "sso", "mfa", "soc2"],
  },
];

import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Rocket,
  Shield,
  FileCode,
  Plug,
  Scale,
  Bell,
  Mail,
  Github,
  ChevronDown,
  ExternalLink,
  Bot,
  TowerControl,
} from "lucide-react";

const quickLinks = [
  {
    icon: Rocket,
    title: "Getting Started",
    description: "Set up your first project and start scanning dependencies in minutes.",
    to: "/docs/quick-start",
  },
  {
    icon: Shield,
    title: "Vulnerabilities",
    description: "Understand how Deptex detects, scores, and triages security issues.",
    to: "/docs/vulnerabilities",
  },
  {
    icon: FileCode,
    title: "Policies",
    description: "Write policy-as-code rules to automate compliance decisions.",
    to: "/docs/policies",
  },
  {
    icon: Plug,
    title: "Integrations",
    description: "Connect GitHub, GitLab, Bitbucket, and other tools to Deptex.",
    to: "/docs/integrations",
  },
  {
    icon: Scale,
    title: "Compliance",
    description: "Track license compliance, custom statuses, and SBOM exports.",
    to: "/docs/compliance",
  },
  {
    icon: Bell,
    title: "Notifications",
    description: "Configure alert rules triggered by vulnerability and policy events.",
    to: "/docs/notification-rules",
  },
  {
    icon: Bot,
    title: "Aegis",
    description: "Autonomous security agent: chat, tasks, automations, Slack, and PR review.",
    to: "/docs/aegis",
  },
  {
    icon: TowerControl,
    title: "Watchtower",
    description: "Supply chain monitoring and forensic analysis per dependency.",
    to: "/docs/watchtower",
  },
];

interface FaqItem {
  category: string;
  question: string;
  answer: string;
}

const faqItems: FaqItem[] = [
  {
    category: "Getting Started",
    question: "What is Deptex?",
    answer:
      "Deptex is a dependency security platform that continuously monitors your software supply chain. It extracts dependency trees from your repositories, enriches them with vulnerability, license, and supply-chain risk data, and lets you enforce custom policies to stay compliant.",
  },
  {
    category: "Getting Started",
    question: "What ecosystems are supported?",
    answer:
      "Deptex supports npm, pip, Go modules, Maven, Cargo, Bundler, NuGet, and many more through cdxgen. If your ecosystem produces a lockfile or manifest, chances are Deptex can parse it.",
  },
  {
    category: "Getting Started",
    question: "How do I connect my repository?",
    answer:
      "Navigate to Settings \u2192 Integrations and connect your source-code provider. GitHub is the most common starting point, but GitLab and Bitbucket are also supported. Once connected, you can import repositories as projects.",
  },
  {
    category: "Security",
    question: "How does Depscore work?",
    answer:
      "Depscore is a composite risk score that combines CVSS severity, EPSS exploit probability, KEV (Known Exploited Vulnerabilities) status, reachability analysis, and your asset tier into a single prioritized number. Higher scores indicate more urgent action.",
  },
  {
    category: "Security",
    question: "What is reachability analysis?",
    answer:
      "Reachability analysis uses static analysis to determine whether the vulnerable code paths in a dependency are actually reachable from your application code. This helps you focus remediation on vulnerabilities that can truly be exploited in your context.",
  },
  {
    category: "Security",
    question: "How are vulnerabilities detected?",
    answer:
      "During extraction, Deptex runs dep-scan against your resolved dependency tree and cross-references results with the OSV and NVD databases. Vulnerabilities are matched by package name and version range, then enriched with CVSS, EPSS, and KEV data.",
  },
  {
    category: "Policies",
    question: "How do I write a policy?",
    answer:
      "Policies are JavaScript functions you define in Settings \u2192 Policies. Each function receives a context object with dependency data and returns a compliance result. See the Policies documentation for the full API reference and examples.",
  },
  {
    category: "Policies",
    question: "What are custom statuses?",
    answer:
      "Custom statuses are organization-defined labels (like \u201cCompliant\u201d, \u201cAction Required\u201d, \u201cExempted\u201d) with colors and ranks. Policies assign these statuses to projects automatically. See the Compliance documentation for setup details.",
  },
  {
    category: "Policies",
    question: "Can I override policies per project?",
    answer:
      "Yes. The policy changes system allows project-level overrides. You can request exceptions, adjust thresholds, or disable specific rules for individual projects while keeping the organization-wide baseline intact.",
  },
  {
    category: "Account",
    question: "How do I invite team members?",
    answer:
      "Go to your Organization Settings \u2192 Members and click Invite. Enter the email address and select a role. The invitee will receive an email with a link to join your organization.",
  },
  {
    category: "Account",
    question: "How do I change my email?",
    answer:
      "Visit your Personal Settings page from the user menu in the top-right corner. You can update your email address, display name, and other profile details there.",
  },
  {
    category: "Account",
    question: "What roles are available?",
    answer:
      "Deptex ships with four built-in roles: Admin, Member, Viewer, and Billing. Admins can also create custom roles with granular permissions tailored to your team structure.",
  },
  {
    category: "General",
    question: "Is Deptex open source?",
    answer:
      "The core platform is open source under the MIT license. Enterprise features\u2014such as advanced RBAC, SSO, and audit logging\u2014are available as a commercial add-on.",
  },
  {
    category: "General",
    question: "Where is my data stored?",
    answer:
      "Deptex stores data in Supabase (PostgreSQL) with encryption at rest and in transit. All database connections use TLS, and row-level security policies restrict access to authorized users.",
  },
  {
    category: "General",
    question: "How often are vulnerabilities updated?",
    answer:
      "Vulnerability data is updated continuously via the OSV and NVD feeds. When a new advisory is published, Deptex matches it against your dependency inventory and surfaces affected packages within minutes.",
  },
];

const categories = [...new Set(faqItems.map((item) => item.category))];

export default function HelpCenterPage() {
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  return (
    <div className="min-h-screen pt-14">
      {/* Hero */}
      <div className="w-full px-6 sm:px-8 pt-12 pb-10">
        <div className="max-w-2xl mx-auto text-center">
          <h1 className="text-2xl font-semibold text-foreground mb-2">Help &amp; Support</h1>
          <p className="text-foreground/90 leading-relaxed">
            Find answers, get help, and connect with the Deptex community.
          </p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 pb-16">
        {/* Quick Links */}
        <section className="mb-14">
          <h2 className="text-lg font-semibold text-foreground mb-5">Popular Topics</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {quickLinks.map((link) => (
              <Link
                key={link.to}
                to={link.to}
                className="group rounded-lg border border-border bg-background-card p-5 hover:border-foreground/30 transition-colors"
              >
                <link.icon className="h-5 w-5 text-foreground/80 mb-3 group-hover:text-foreground transition-colors" />
                <h3 className="text-sm font-semibold text-foreground mb-1">{link.title}</h3>
                <p className="text-xs text-foreground/90 leading-relaxed">
                  {link.description}
                </p>
              </Link>
            ))}
          </div>
        </section>

        {/* FAQ */}
        <section className="mb-14">
          <h2 className="text-lg font-semibold text-foreground mb-5">
            Frequently Asked Questions
          </h2>
          <div className="space-y-8">
            {categories.map((category) => (
              <div key={category}>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-foreground/80 mb-3">
                  {category}
                </h3>
                <div className="space-y-2">
                  {faqItems
                    .filter((item) => item.category === category)
                    .map((item) => {
                      const globalIndex = faqItems.indexOf(item);
                      const isOpen = openFaq === globalIndex;
                      return (
                        <div
                          key={globalIndex}
                          className="rounded-lg border border-border bg-background-card overflow-hidden"
                        >
                          <button
                            onClick={() => setOpenFaq(isOpen ? null : globalIndex)}
                            className="flex w-full items-center justify-between px-5 py-3.5 text-left hover:bg-background-subtle/50 transition-colors"
                          >
                            <span className="text-sm font-medium text-foreground">
                              {item.question}
                            </span>
                            <ChevronDown
                              className={`h-4 w-4 text-foreground/70 shrink-0 ml-4 transition-transform duration-200 ${
                                isOpen ? "rotate-180" : ""
                              }`}
                            />
                          </button>
                          <div
                            className={`grid transition-[grid-template-rows] duration-200 ${
                              isOpen ? "grid-rows-[1fr]" : "grid-rows-[0fr]"
                            }`}
                          >
                            <div className="overflow-hidden">
                              <p className="px-5 pb-4 text-sm text-foreground/90 leading-relaxed">
                                {item.answer}
                              </p>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Contact & Community */}
        <section className="mb-14">
          <h2 className="text-lg font-semibold text-foreground mb-5">Get in Touch</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="rounded-lg border border-border bg-background-card p-6">
              <div className="flex items-center gap-3 mb-3">
                <Mail className="h-5 w-5 text-foreground/80" />
                <h3 className="text-sm font-semibold text-foreground">Contact Support</h3>
              </div>
              <p className="text-sm text-foreground/90 leading-relaxed mb-3">
                Have a question that isn&rsquo;t answered here? Reach out to the team directly.
              </p>
              <a
                href="mailto:deptex.app@gmail.com"
                className="inline-flex items-center gap-1.5 text-sm text-foreground underline hover:no-underline"
              >
                deptex.app@gmail.com
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
              <p className="text-xs text-foreground/70 mt-2">
                We typically respond within 24 hours.
              </p>
            </div>

            <div className="rounded-lg border border-border bg-background-card p-6">
              <div className="flex items-center gap-3 mb-3">
                <Github className="h-5 w-5 text-foreground/80" />
                <h3 className="text-sm font-semibold text-foreground">Community</h3>
              </div>
              <p className="text-sm text-foreground/90 leading-relaxed mb-3">
                Join the conversation, report issues, and contribute to the project on GitHub.
              </p>
              <a
                href="https://github.com/deptex"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-sm text-foreground underline hover:no-underline"
              >
                github.com/deptex
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

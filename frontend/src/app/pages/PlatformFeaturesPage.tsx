import { Link, useParams, useNavigate, Navigate } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "../../components/ui/tabs";
import {
  Bot,
  ScanSearch,
  Scale,
  Bell,
  Telescope,
  ListChecks,
  MessageSquare,
  ClipboardCheck,
  Calendar,
  GitPullRequest,
  Key,
} from "lucide-react";

const FEATURES = [
  {
    slug: "ai-security-agent",
    label: "AI Security Agent",
    intro: "Your AI security engineer. Chat in natural language, run tasks and automations, and get PR reviews and Slack support—with your own AI provider and full control.",
    docsSlug: "aegis",
    cards: [
      { title: "Plan with AI", icon: ListChecks, description: "Multi-step plans you can pause, approve, or cancel. Security sprints and fix batches." },
      { title: "Chat & command center", icon: MessageSquare, description: "50+ tools, streaming answers, and persistent threads for vulnerability and policy questions." },
      { title: "Tasks & approvals", icon: ClipboardCheck, description: "Human-in-the-loop for high-impact actions. Approve from the console or in Slack." },
      { title: "Automations & memory", icon: Calendar, description: "Cron schedules, event triggers, and semantic memory so context persists." },
      { title: "Slack & PR review", icon: GitPullRequest, description: "@mention Aegis in Slack. PR security reviews with risk and policy checks." },
      { title: "BYOK & control", icon: Key, description: "OpenAI, Anthropic, or Google. Encrypted keys, usage caps, and per-task budgets." },
    ],
    icon: Bot,
  },
  {
    slug: "vulnerability-intelligence",
    label: "Vulnerability Intelligence",
    intro: "Depscore, reachability, and smart version recommendations. See which vulnerabilities affect your code and get upgrade paths that stay compliant.",
    docsSlug: "vulnerabilities",
    cards: [
      { title: "Depscore", description: "Risk score per dependency and version—severity, EPSS, CISA KEV, and code-level reachability (data-flow, function, module)." },
      { title: "Reachability analysis", description: "Understand which vulns are reachable in your code. Data-flow and usage slices from the atom engine." },
      { title: "Version recommendations", description: "Safe upgrade candidates with OSV verification, release notes, and policy checks. Respects banned versions and org policy." },
      { title: "Suppress & accept risk", description: "Suppress findings or accept risk with reason and audit trail. Keeps the graph clean while you track exceptions." },
    ],
    icon: ScanSearch,
  },
  {
    slug: "customizable-compliance",
    label: "Customizable Compliance",
    intro: "Policy-as-code, SBOM, and license compliance. Define rules in JavaScript; get legal notices, preflight checks, and AI-powered exception suggestions.",
    docsSlug: "compliance",
    cards: [
      { title: "Policy-as-code", description: "Package policy, project status, and PR check code in the org. Run per-dependency and per-project with version history." },
      { title: "SBOM & legal notice", description: "Export CycloneDX SBOM and generate license notices from your dependencies. Cached and rate-limited." },
      { title: "Preflight & exceptions", description: "Check a hypothetical package against policy before adding. Apply for license exceptions with AI-generated policy tweaks." },
      { title: "Registry search", description: "Search npm, Maven, Cargo, PyPI, and more from the app. See license and basic metadata before you add." },
    ],
    icon: Scale,
  },
  {
    slug: "customizable-notifications",
    label: "Customizable Notifications",
    intro: "Define notifications as code. Event-driven rules with org, team, and project cascade; send to Slack, Jira, email, PagerDuty, and more.",
    docsSlug: "notification-rules",
    cards: [
      { title: "Rules as code", description: "Trigger type and custom code in a sandbox. Syntax and shape validated on save; test and dry-run before going live." },
      { title: "Destinations", description: "Slack, Discord, Jira, Linear, Asana, Email, custom webhooks, PagerDuty. OAuth and rate limits per destination." },
      { title: "Delivery & history", description: "Track deliveries, retry failed, view history. In-app inbox and user preferences (email opt-out, muted events)." },
    ],
    icon: Bell,
  },
  {
    slug: "advanced-upstream-insights",
    label: "Advanced Upstream Insights",
    intro: "Supply-chain forensics and contributor anomalies. Watch packages, analyze commits and contributors, and detect suspicious behavior upstream.",
    docsSlug: "watchtower",
    cards: [
      { title: "Package watchlist", description: "Add packages to the org watchlist. Full analysis: registry integrity, scripts, entropy, commits, contributors." },
      { title: "Commits & anomalies", description: "See commits that touch your imported code. Anomaly scores for new contributors and unusual patterns." },
      { title: "Quarantine & PRs", description: "Quarantine new versions until reviewed. Create bump or removal PRs from the supply-chain view." },
    ],
    icon: Telescope,
  },
] as const;

const slugList = FEATURES.map((f) => f.slug);
type FeatureSlug = (typeof slugList)[number];

const FEATURE_HERO_IMAGES: Record<FeatureSlug, string> = {
  "ai-security-agent": "/images/aisecurityimage.png",
  "vulnerability-intelligence": "/images/vulnerabilitiesimage.png",
  "customizable-compliance": "/images/complianceimage.png",
  "customizable-notifications": "/images/notificationsimage.png",
  "advanced-upstream-insights": "/images/upstreaminsightsimage.png",
};

export default function PlatformFeaturesPage() {
  const navigate = useNavigate();
  const { featureSlug } = useParams<{ featureSlug?: string }>();
  const validSlug = featureSlug && slugList.includes(featureSlug as FeatureSlug);
  if (!featureSlug || !validSlug) {
    return <Navigate to={`/platform-features/${slugList[0]}`} replace />;
  }
  const currentSlug = featureSlug as FeatureSlug;
  const feature = FEATURES.find((f) => f.slug === currentSlug)!;
  const FeatureIcon = feature.icon;

  return (
    <div className="min-h-screen bg-background">
      {/* Hero */}
      <section className="container mx-auto px-4 pt-28 pb-10 lg:pt-36 lg:pb-14">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-3xl md:text-4xl lg:text-5xl font-bold text-foreground mb-3">
            Platform features
          </h1>
          <p className="text-lg text-foreground-secondary mb-8 leading-relaxed">
            Deptex brings dependency security, compliance, and AI automation into one place. Pick a feature below to see what it does.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <Button
              asChild
              className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 font-semibold text-sm px-4 py-2 rounded-lg"
            >
              <Link to="/login">Get started</Link>
            </Button>
            <Button
              asChild
              variant="outline"
              className="border-border hover:bg-background-subtle text-sm px-4 py-2 rounded-lg"
            >
              <Link to="/get-demo">Book a demo</Link>
            </Button>
          </div>
        </div>
      </section>

      {/* Tabs */}
      <section className="border-b border-border/60">
        <div className="container mx-auto px-4">
          <Tabs value={currentSlug} onValueChange={(v) => navigate(`/platform-features/${v}`)}>
            <TabsList variant="line" className="h-auto w-full justify-stretch rounded-none border-0 bg-transparent p-0">
              {FEATURES.map((f) => (
                <TabsTrigger key={f.slug} value={f.slug} className="flex-1">
                  {f.label}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </div>
      </section>

      {/* Selected feature: intro + cards */}
      <section className="container mx-auto px-4 py-12 lg:py-16">
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 lg:gap-12 items-center mb-12">
            <img
              src={FEATURE_HERO_IMAGES[currentSlug]}
              alt={`${feature.label}`}
              className="w-full max-w-md mx-auto lg:max-w-none rounded-lg object-contain"
            />
            <div>
              <h2 className="text-2xl font-semibold text-foreground mb-3">{feature.label}</h2>
              <p className="text-foreground/80 leading-relaxed max-w-xl">
                {feature.intro}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {feature.cards.map((card) => {
              const CardIcon = "icon" in card ? card.icon : FeatureIcon;
              return (
                <div
                  key={card.title}
                  className="rounded-2xl border border-border bg-background-card/50 p-6 flex flex-col items-start text-left transition-all duration-200 hover:bg-background-card/70 hover:shadow-[0_0_20px_rgba(255,255,255,0.04)]"
                >
                  <div className="rounded-xl bg-[#1e382e] p-3 mb-4">
                    <CardIcon className="h-6 w-6 text-white/90" />
                  </div>
                  <h3 className="text-base font-semibold text-foreground">
                    {card.title}
                  </h3>
                  <p className="text-sm text-foreground/70 leading-relaxed mt-2">
                    {card.description}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </section>
    </div>
  );
}

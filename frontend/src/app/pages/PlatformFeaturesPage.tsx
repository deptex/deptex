import { Link, useParams, useNavigate, Navigate } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "../../components/ui/tabs";
import {
  Bot,
  Package,
  Braces,
  Layers,
  ListChecks,
  MessageSquare,
  ClipboardCheck,
  Calendar,
  GitPullRequest,
  Key,
} from "lucide-react";
import DependencyScanningPage from "../../components/landing/feature-pages/DependencyScanningPage";

const FEATURES = [
  {
    slug: "ai-security-agent",
    label: "AI Security Agent",
    intro: "Your AI security engineer. Chat in natural language, run tasks and automations, and get fixes as draft pull requests you approve.",
    docsSlug: "aegis",
    cards: [
      { title: "Plan with AI", icon: ListChecks, description: "Multi-step plans you can approve, revise, or reject before anything runs." },
      { title: "Chat & command center", icon: MessageSquare, description: "24 tools, streaming answers, and persistent threads for vulnerability and policy questions." },
      { title: "Tasks & approvals", icon: ClipboardCheck, description: "Human-in-the-loop for high-impact actions. Approve every dangerous step from the console." },
      { title: "Automations & memory", icon: Calendar, description: "Cron schedules, event triggers, and semantic memory so context persists." },
      { title: "Guardrails", icon: GitPullRequest, description: "Draft PRs always, hard caps on every run, and honest refusals when no safe fix exists." },
      { title: "Models & cost control", icon: Key, description: "Pick which models Aegis can use. Usage logging and prepaid spend controls per org." },
    ],
    icon: Bot,
  },
  {
    slug: "dependency-scanning",
    label: "Dependency scanning",
    intro: "Every dependency CVE, scored by whether it's actually reachable in your code — not raw CVSS — plus malicious-package detection across 8 ecosystems.",
    docsSlug: "vulnerabilities",
    cards: [
      { title: "Depscore", description: "A risk score per dependency and version — severity, EPSS, CISA KEV, and code-level reachability (data-flow, function, module)." },
      { title: "Reachability analysis", description: "See which CVEs are actually reachable in your code. Data-flow and usage slices from the taint engine cut the noise." },
      { title: "Malicious packages", description: "Malicious-package feeds, behavioral heuristics, and a capability fingerprint for every package you install." },
      { title: "Version recommendations", description: "Safe upgrade candidates with OSV verification and release notes, respecting banned versions and org policy." },
      { title: "Suppress & accept risk", description: "Suppress findings or accept risk with a reason and audit trail. Keeps the graph clean while you track exceptions." },
    ],
    icon: Package,
  },
  {
    slug: "code-scanning",
    label: "Code scanning",
    intro: "Static analysis and secret detection across your whole codebase — deduped, CWE-scored, and caught before they merge.",
    docsSlug: "sast",
    cards: [
      { title: "SAST", description: "Static analysis across your whole workspace, deduped and CWE-scored, so risks are caught before they merge." },
      { title: "Secret detection", description: "Leaked keys and tokens, caught and live-verified — a working credential outranks a dormant one." },
      { title: "PR checks & merge gating", description: "Findings surface as PR checks with sticky comments; block merges on GitHub and GitLab." },
    ],
    icon: Braces,
  },
  {
    slug: "infrastructure-dast",
    label: "Infrastructure & DAST",
    intro: "Misconfigurations across Terraform, Kubernetes and Dockerfiles, image CVEs with base-image fixes, and active runtime testing of your live app.",
    docsSlug: "dast",
    cards: [
      { title: "IaC misconfigurations", description: "Misconfigs across Terraform, Kubernetes, Helm, CloudFormation and Dockerfiles, mapped to the files that introduce them." },
      { title: "Container & image CVEs", description: "Image CVEs with base-image upgrade advice, and a bridge linking OS-package CVEs to the code that loads them." },
      { title: "DAST", description: "Your running app gets actively attacked, guided by an OpenAPI spec synthesized from your detected routes." },
    ],
    icon: Layers,
  },
] as const;

const slugList = FEATURES.map((f) => f.slug);
type FeatureSlug = (typeof slugList)[number];

// Optional: only the features with a real screenshot get a hero image. The
// rest render single-column (no placeholder/misleading art).
const FEATURE_HERO_IMAGES: Partial<Record<FeatureSlug, string>> = {
  "ai-security-agent": "/images/aisecurityimage.png",
  "dependency-scanning": "/images/vulnerabilitiesimage.png",
  // TODO: real screenshots for code-scanning + infrastructure-dast
};

export default function PlatformFeaturesPage() {
  const navigate = useNavigate();
  const { featureSlug } = useParams<{ featureSlug?: string }>();
  const validSlug = featureSlug && slugList.includes(featureSlug as FeatureSlug);
  if (!featureSlug || !validSlug) {
    return <Navigate to={`/platform-features/${slugList[0]}`} replace />;
  }
  const currentSlug = featureSlug as FeatureSlug;

  // Dedicated full pages take over their slug entirely (no shared shell/tabs).
  if (currentSlug === "dependency-scanning") return <DependencyScanningPage />;

  const feature = FEATURES.find((f) => f.slug === currentSlug)!;
  const FeatureIcon = feature.icon;
  const heroImage = FEATURE_HERO_IMAGES[currentSlug];

  return (
    <div className="min-h-screen bg-background">
      {/* Hero */}
      <section className="container mx-auto px-4 pt-28 pb-10 lg:pt-36 lg:pb-14">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-3xl md:text-4xl lg:text-5xl font-bold text-foreground mb-3">
            Platform features
          </h1>
          <p className="text-lg text-foreground-secondary mb-8 leading-relaxed">
            Deptex brings dependency, code, and infrastructure security into one place — with an AI agent that ships the fixes. Pick a feature below to see what it does.
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <Button asChild variant="green">
              <Link to="/login">Try for free</Link>
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
          <div
            className={`grid grid-cols-1 gap-10 lg:gap-12 items-center mb-12 ${
              heroImage ? "lg:grid-cols-2" : "max-w-2xl"
            }`}
          >
            {heroImage && (
              <img
                src={heroImage}
                alt={feature.label}
                className="w-full max-w-md mx-auto lg:max-w-none rounded-lg object-contain"
              />
            )}
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

/**
 * Pipeline showcase: vertical line + four content sections you scroll through + CTA card.
 * Each section has category badge, title, description, bullet points, and a card.
 * Text always left, card always right. Line extends through CTA card.
 * Sections fade in on scroll.
 */
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  ChevronRight,
  Webhook,
  Layers,
  FileCode,
  Code2,
  BarChart3,
  Shield,
  FileCheck,
  FileText,
  Search,
  Zap,
  Wand2,
  TrendingUp,
} from "lucide-react";
import LandingCTACard from "./LandingCTACard";

const STEPS = [
  {
    id: "connect",
    category: "Connect and sync",
    title: "Connect your repositories",
    description:
      "Link GitHub, GitLab, or Bitbucket in minutes. Deptex ingests your repos and builds SBOMs so you can secure every dependency across your stack.",
    bullets: [
      { icon: Webhook, text: "Webhooks trigger extraction on every push", description: "Connect once and stay in sync. Push events automatically queue full SBOM and dependency analysis." },
      { icon: Layers, text: "11 ecosystems — npm, PyPI, Maven, Go, Cargo, and more", description: "From JavaScript to Rust, Python to Java. One platform for your entire stack." },
      { icon: FileCode, text: "Full SBOM generation with CycloneDX", description: "Industry-standard SBOMs ready for compliance, audit, and supply chain visibility." },
    ],
  },
  {
    id: "intelligence",
    category: "Vulnerability intelligence",
    title: "Get detailed vulnerability intelligence",
    description:
      "See which dependencies are affected, severity, EPSS scores, and CISA KEV status. Prioritize what matters with code-level reachability — data-flow, function, and module tracing.",
    learnMore: "/platform-features/vulnerability-intelligence",
    bullets: [
      { icon: Code2, text: "Code-level reachability — fix what's actually used", description: "Data-flow and call-graph analysis so you prioritize vulnerabilities that touch your code." },
      { icon: BarChart3, text: "Depscore, EPSS, and CISA KEV for smart prioritization", description: "Risk-weighted scoring so critical and actively exploited issues surface first." },
      { icon: Shield, text: "Semgrep and TruffleHog for code and secret findings", description: "Code security and secret scanning integrated into every extraction run." },
    ],
  },
  {
    id: "compliance",
    category: "Policy and compliance",
    title: "Enforce custom compliance policies",
    description:
      "Policy-as-code, license checks, and custom statuses. Stay compliant and ship with confidence using a single source of truth for your security posture.",
    learnMore: "/platform-features/customizable-compliance",
    bullets: [
      { icon: FileCheck, text: "Package policy, project status, and PR check editors", description: "Policy-as-code in JavaScript. Define rules once, enforce everywhere." },
      { icon: FileText, text: "License obligations and SBOM export", description: "Legal notice generation and SBOM export for audits and customer requests." },
      { icon: Search, text: "Preflight checks before adding new dependencies", description: "Check hypothetical packages against policy before you add." },
    ],
  },
  {
    id: "fix",
    category: "Remediation",
    title: "Fix and automate with AI",
    description:
      "Aegis suggests fixes, creates bump PRs, and learns from outcomes. Automate remediation so your team can focus on building.",
    learnMore: "/autonomous-agent",
    bullets: [
      { icon: Zap, text: "Aegis: 50+ tools, memory, tasks, and automations", description: "Chat, automate, and fix. Your autonomous security engineer." },
      { icon: Wand2, text: "AI-powered fixes with 7 strategies across all ecosystems", description: "Version bumps, patches, and removals. Aider-powered with BYOK." },
      { icon: TrendingUp, text: "Outcome-based learning — gets smarter over time", description: "Tracks fix outcomes and recommends the best strategy per org." },
    ],
  },
];

/** One node per step, positioned at the vertical center of each section. */
const NODE_POSITIONS = ["12.5%", "37.5%", "62.5%", "87.5%"] as const;

export default function PipelineShowcaseSection() {
  const [visibleSteps, setVisibleSteps] = useState<Set<number>>(new Set());
  const [ctaVisible, setCtaVisible] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  const stepRefs = useRef<(HTMLDivElement | null)[]>([]);
  const ctaRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setReducedMotion(window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }, []);

  useEffect(() => {
    const observers: IntersectionObserver[] = [];
    stepRefs.current.forEach((el, index) => {
      if (!el) return;
      const observer = new IntersectionObserver(
        ([entry]) => {
          if (entry.isIntersecting) {
            setVisibleSteps((prev) => new Set(prev).add(index));
          }
        },
        { threshold: 0.15, rootMargin: "0px 0px -80px 0px" }
      );
      observer.observe(el);
      observers.push(observer);
    });
    if (ctaRef.current) {
      const ctaObserver = new IntersectionObserver(
        ([entry]) => {
          if (entry.isIntersecting) setCtaVisible(true);
        },
        { threshold: 0.15, rootMargin: "0px 0px -80px 0px" }
      );
      ctaObserver.observe(ctaRef.current);
      observers.push(ctaObserver);
    }
    return () => observers.forEach((o) => o.disconnect());
  }, []);

  const animateClass = reducedMotion
    ? ""
    : "transition-all duration-700 ease-out";
  const visibleClass = (visible: boolean) =>
    reducedMotion ? "" : visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8";

  return (
    <section
      className="relative w-screen max-w-none left-1/2 -ml-[50vw] flex min-h-0"
      aria-labelledby="pipeline-showcase-heading"
    >
      <h2 id="pipeline-showcase-heading" className="sr-only">
        How Deptex works
      </h2>

      {/* Full-height line (thicker) + four nodes, one beside each section. */}
      <div
        className="absolute top-0 bottom-0 left-[12vw] w-1 -ml-0.5 pointer-events-none"
        aria-hidden
      >
        <div className="w-1 rounded-full bg-foreground/15 h-full min-h-full" />
        {NODE_POSITIONS.map((topPct) => (
          <div
            key={topPct}
            className="absolute left-1/2 top-0 -translate-x-1/2 -translate-y-1/2 w-4 h-4 rounded-full bg-border shrink-0"
            style={{ top: topPct }}
            aria-hidden
          />
        ))}
      </div>

      {/* Spacer so content stays to the right of the line. */}
      <div className="w-[12vw] flex-shrink-0 min-w-0" aria-hidden />

      {/* Four scroll-through sections — text left, card right */}
      <div className="flex-1 flex flex-col min-w-0 gap-0">
        {STEPS.map((step, index) => (
          <div
            key={step.id}
            ref={(el) => { stepRefs.current[index] = el; }}
            className={`min-h-[65vh] flex items-center justify-center py-6 px-4 sm:px-6 lg:px-8 ${animateClass} ${visibleClass(visibleSteps.has(index))}`}
          >
            <div className="w-full max-w-6xl mx-auto grid gap-8 lg:gap-12 items-center lg:grid-cols-[1fr,minmax(420px,1fr)]">
              {/* Left: badge, title, description, learn more, bullets with vertical accents */}
              <div>
                <span className="inline-flex items-center rounded-md border border-[#2eb37c]/40 bg-[#2eb37c]/10 px-3 py-1 text-xs font-medium uppercase tracking-wider text-[#2eb37c] mb-4">
                  {step.category}
                </span>
                <h3 className="text-2xl sm:text-3xl font-semibold text-foreground mb-3">
                  {step.title}
                </h3>
                <p className="text-foreground text-base sm:text-lg leading-relaxed max-w-xl mb-4">
                  {step.description}
                </p>
                {step.learnMore && (
                  <Link
                    to={step.learnMore}
                    className="inline-flex items-center gap-1 text-foreground text-sm font-medium mb-8"
                  >
                    Learn more
                    <ChevronRight className="h-4 w-4" />
                  </Link>
                )}
                <ul className="divide-y divide-border/50">
                  {step.bullets.map((bullet, i) => {
                    const Icon = bullet.icon;
                    return (
                      <li key={i} className="flex items-start gap-3 py-4 first:pt-0 last:pb-0">
                        <Icon className="h-4 w-4 shrink-0 mt-0.5 text-muted-foreground" />
                        <div>
                          <p className="text-foreground font-medium text-sm sm:text-base">{bullet.text}</p>
                          <p className="text-muted-foreground text-sm mt-1">{bullet.description}</p>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </div>

              {/* Right: card — blank for image/video */}
              <div
                className="relative rounded-xl overflow-hidden"
                style={{
                  background: "linear-gradient(180deg, rgba(28, 31, 36, 0.95) 0%, rgba(22, 25, 29, 0.98) 100%)",
                  boxShadow: "0 0 0 1px rgba(255,255,255,0.06), 0 8px 32px -8px rgba(0,0,0,0.5)",
                }}
              >
                <div className="min-h-[280px] sm:min-h-[360px] lg:min-h-[400px]" />
              </div>
              </div>
            </div>
        ))}
        <div
          ref={ctaRef}
          className={`${animateClass} ${visibleClass(ctaVisible)}`}
        >
          <LandingCTACard />
        </div>
      </div>
    </section>
  );
}

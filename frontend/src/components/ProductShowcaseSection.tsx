import { useState, useEffect } from "react";
import {
  LayoutGrid,
  Bot,
  BarChart3,
  Layers,
  ShieldCheck,
  GitBranch,
  ShieldAlert,
  Bell,
} from "lucide-react";

const features = [
  {
    title: "Connect Your Project",
    navLabel: "Connect",
    icon: GitBranch,
    headline: "Connect once — stay in sync.",
    subtext:
      "Connect GitHub, GitLab, or Bitbucket. Extraction runs on push or on a schedule. Live sync status and webhook-driven updates keep your dependency data current.",
    imagePath: "/images/showcase/slide-1.png",
    videoPath: "/videos/showcase/slide-1.mp4",
  },
  {
    title: "Organization & Security Standards",
    navLabel: "Organization",
    icon: LayoutGrid,
    headline: "Your security foundation — unified in one place.",
    subtext:
      "Define custom roles, bring your team onboard, connect integrations, and set policy-as-code across every project.",
    imagePath: "/images/showcase/slide-2.png",
    videoPath: "/videos/showcase/slide-2.mp4",
  },
  {
    title: "Aegis — Your Autonomous Security Engineer",
    navLabel: "Aegis AI",
    icon: Bot,
    headline: "Aegis — chat, automate, and fix.",
    subtext:
      "Chat with Aegis to investigate vulnerabilities, run automations, trigger fixes, and get PR reviews. Fifty-plus tools, memory, and scheduled tasks.",
    imagePath: "/images/showcase/slide-3.png",
    videoPath: "/videos/showcase/slide-3.mp4",
  },
  {
    title: "Project Overview & Health Score",
    navLabel: "Project Health",
    icon: BarChart3,
    headline: "Instant visibility into your project's health.",
    subtext:
      "Real-time score from vulnerabilities, package freshness, supply-chain risk, policy violations, and code findings. Stats and activity feed.",
    imagePath: "/images/showcase/slide-4.png",
    videoPath: "/videos/showcase/slide-4.mp4",
  },
  {
    title: "Dependencies & Supply Chain",
    navLabel: "Dependencies",
    icon: Layers,
    headline: "Go beyond scanning — understand your supply chain.",
    subtext:
      "Supply chain graph, Watchtower monitoring for commits and anomalies, version tracking, and safe upgrade recommendations.",
    imagePath: "/images/showcase/slide-5.png",
    videoPath: "/videos/showcase/slide-5.mp4",
  },
  {
    title: "Security & Code-Level Reachability",
    navLabel: "Security",
    icon: ShieldAlert,
    headline: "Vulnerabilities with context that matters.",
    subtext:
      "Depscore-based prioritization, Semgrep and secret findings, and code-level reachability (data-flow and call graphs) so you fix what's actually used.",
    imagePath: "/images/showcase/slide-6.png",
    videoPath: "/videos/showcase/slide-6.mp4",
  },
  {
    title: "Policy-as-Code & Compliance",
    navLabel: "Compliance",
    icon: ShieldCheck,
    headline: "Continuous protection — fixes included.",
    subtext:
      "Package and PR policy editors, SBOM export, license obligations, preflight checks, and AI-powered fix PRs. Stay compliant across the stack.",
    imagePath: "/images/showcase/slide-7.png",
    videoPath: "/videos/showcase/slide-7.mp4",
  },
  {
    title: "Custom Notifications & Integrations",
    navLabel: "Notifications",
    icon: Bell,
    headline: "Alert the right people, the way you want.",
    subtext:
      "Custom notification rules, Slack, Discord, Jira, Linear, email, PagerDuty, and webhooks. Weekly digests and delivery history.",
    imagePath: "/images/showcase/slide-8.png",
    videoPath: "/videos/showcase/slide-8.mp4",
  },
];

const AUTO_ADVANCE_DURATION_MS = 8000;

export default function ProductShowcaseSection() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [progress, setProgress] = useState(0);
  const [imageErrors, setImageErrors] = useState<Record<number, boolean>>({});
  const [videoErrors, setVideoErrors] = useState<Record<number, boolean>>({});

  useEffect(() => {
    setProgress(0);
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) return 0;
        return prev + (100 / (AUTO_ADVANCE_DURATION_MS / 50));
      });
    }, 50);
    const advanceInterval = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % features.length);
    }, AUTO_ADVANCE_DURATION_MS);
    return () => {
      clearInterval(progressInterval);
      clearInterval(advanceInterval);
    };
  }, [currentIndex]);

  const goToSlide = (index: number) => {
    setCurrentIndex(index);
    setProgress(0);
  };

  const currentFeature = features[currentIndex];
  const useVideo =
    currentFeature.videoPath &&
    !videoErrors[currentIndex];
  const useImage = !useVideo && !imageErrors[currentIndex];
  const showPlaceholder = !useVideo && !useImage;

  return (
    <section className="container mx-auto px-4 pt-4 pb-20 lg:pb-32">
      <div className="max-w-6xl mx-auto">
        <div className="relative">
          {/* Larger card: min height so it feels bigger, aspect-video for ratio */}
          <div className="relative rounded-xl border border-border bg-background-card overflow-visible aspect-video min-h-[340px] sm:min-h-[400px] md:min-h-[460px] flex items-center justify-center shadow-xl">
            <div className="absolute inset-0 rounded-xl overflow-hidden flex items-center justify-center bg-background-card">
              {showPlaceholder ? (
                <div className="w-full h-full flex flex-col items-center justify-center gap-2 p-8 text-center bg-background-subtle/50">
                  <p className="text-foreground-secondary text-sm">
                    Add your screenshot or video for this slide.
                  </p>
                  <p className="text-foreground-muted text-xs max-w-md">
                    Images:{" "}
                    <code className="bg-background-card px-1 rounded">
                      public/images/showcase/slide-{currentIndex + 1}.png
                    </code>
                    . Videos:{" "}
                    <code className="bg-background-card px-1 rounded">
                      public/videos/showcase/slide-{currentIndex + 1}.mp4
                    </code>
                    . Video is used if present, otherwise image.
                  </p>
                </div>
              ) : useVideo ? (
                <video
                  key={currentIndex}
                  src={currentFeature.videoPath}
                  className="w-full h-full object-contain bg-background-card"
                  autoPlay
                  muted
                  loop
                  playsInline
                  onError={() =>
                    setVideoErrors((prev) => ({ ...prev, [currentIndex]: true }))
                  }
                />
              ) : (
                <img
                  src={currentFeature.imagePath}
                  alt=""
                  className="w-full h-full object-contain bg-background-card"
                  onError={() =>
                    setImageErrors((prev) => ({ ...prev, [currentIndex]: true }))
                  }
                />
              )}
            </div>

            {/* Bottom card bar: half overlapping video edge */}
            <div className="absolute left-1/2 -translate-x-1/2 translate-y-1/2 bottom-0 w-full max-w-3xl rounded-xl border border-border bg-background-card/95 backdrop-blur-sm px-1 py-1.5 flex items-stretch shadow-lg z-10">
              {features.map((feature, index) => {
                const Icon = feature.icon;
                const isActive = index === currentIndex;
                const showSeparatorRight =
                  index < features.length - 1 &&
                  index !== currentIndex &&
                  index + 1 !== currentIndex;

                return (
                  <div
                    key={index}
                    className="relative flex flex-1 items-stretch min-w-0"
                  >
                    <button
                      onClick={() => goToSlide(index)}
                      className={`
                        relative flex-1 flex items-center justify-center gap-1.5 sm:gap-2 py-2.5 px-1.5 sm:px-2 rounded-lg min-w-0
                        transition-colors duration-300 ease-out
                        ${
                          isActive
                            ? "text-[#2eb37c]"
                            : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                        }
                      `}
                      aria-label={`Go to ${feature.title}`}
                      aria-current={isActive ? "true" : undefined}
                    >
                      {isActive && (
                        <span
                          className="absolute inset-0 rounded-lg overflow-hidden bg-primary/15"
                          aria-hidden
                        >
                          <span
                            className="absolute inset-0 bg-primary/65 transition-[width] duration-75 ease-linear"
                            style={{ width: `${progress}%` }}
                          />
                        </span>
                      )}
                      <Icon className="relative h-4 w-4 shrink-0" />
                      <span className="relative text-xs font-medium truncate">
                        {feature.navLabel}
                      </span>
                    </button>
                    {showSeparatorRight && (
                      <div
                        className="absolute right-0 top-1/2 -translate-y-1/2 w-px h-3 bg-border shrink-0 z-10 pointer-events-none"
                        aria-hidden
                      />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

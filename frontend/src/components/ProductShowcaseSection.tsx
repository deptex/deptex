import { useState, useEffect } from "react";
import { Building2, Bot, HeartPulse, Network, Zap } from "lucide-react";

const features = [
  {
    title: "Create Your Organization & Define Your Security Standards",
    navLabel: "Organization",
    icon: Building2,
    headline: "Your security foundation — unified in one place.",
    subtext: "Define custom roles, bring your team onboard, import your open-source policy, and instantly create a security baseline across every project.",
  },
  {
    title: "Hire Your Deptex AI Employee",
    navLabel: "AI Employee",
    icon: Bot,
    headline: "Meet your autonomous security engineer.",
    subtext: "Assign tasks, review completed actions, track activity logs — and let your AI employee investigate, fix, explain, and report issues automatically.",
  },
  {
    title: "Project Overview & Health Score",
    navLabel: "Project Health",
    icon: HeartPulse,
    headline: "Instant visibility into your project's health.",
    subtext: "Get a real-time score based on vulnerabilities, package freshness, supply-chain risk, policy violations, and agent findings.",
  },
  {
    title: "Deep Dependency Insights & Watchlist Tracking",
    navLabel: "Dependencies Insights",
    icon: Network,
    headline: "Go beyond scanning — understand your supply chain.",
    subtext: "Track critical dependencies on your watchlist, visualize their connections, detect anomalies, and get actionable explanations for every risk.",
  },
  {
    title: "Automated Remediation & Continuous Compliance",
    navLabel: "Compliance",
    icon: Zap,
    headline: "Continuous protection — fixes included.",
    subtext: "Deptex automatically proposes safe upgrades, generates PRs, enforces policies, and keeps your organization compliant and secure in the background.",
  },
];

const AUTO_ADVANCE_DURATION = 28000; // 28 seconds (matches video length)

export default function ProductShowcaseSection() {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    // Reset progress when index changes
    setProgress(0);
    
    // Progress bar animation
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          return 0;
        }
        return prev + (100 / (AUTO_ADVANCE_DURATION / 50)); // Update every 50ms
      });
    }, 50);

    // Auto-advance to next slide
    const advanceInterval = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % features.length);
    }, AUTO_ADVANCE_DURATION);

    return () => {
      clearInterval(progressInterval);
      clearInterval(advanceInterval);
    };
  }, [currentIndex]);

  const goToSlide = (index: number) => {
    setCurrentIndex(index);
    setProgress(0);
  };

  return (
    <section className="container mx-auto px-4 py-20 lg:py-32">
      <div className="max-w-7xl mx-auto">
        {/* Navigation Bar with Progress */}
        <div className="mb-8">
          <div className="relative">
            {/* Navigation Items */}
            <div className="flex items-center justify-between pb-6">
              {features.map((feature, index) => {
                const Icon = feature.icon;
                const isActive = index === currentIndex;
                const segmentWidth = 100 / features.length;
                
                return (
                  <button
                    key={index}
                    onClick={() => goToSlide(index)}
                    className={`relative flex items-center gap-2 transition-all duration-300 ${
                      isActive
                        ? "text-[#059669]"
                        : "text-foreground-secondary hover:text-foreground"
                    }`}
                    aria-label={`Go to ${feature.title}`}
                    style={{ width: `${segmentWidth}%`, justifyContent: 'center' }}
                  >
                    {/* Icon */}
                    <Icon className={`h-5 w-5 transition-all duration-300 ${
                      isActive
                        ? "text-[#059669]"
                        : "text-foreground-secondary"
                    }`} />
                    
                    {/* Title */}
                    <span className="text-base font-medium">
                      {feature.navLabel}
                    </span>
                  </button>
                );
              })}
            </div>
            
            {/* Individual Progress Bars */}
            <div className="flex items-center gap-3">
              {features.map((_, index) => {
                const isActive = index === currentIndex;
                
                return (
                  <div
                    key={index}
                    className="relative flex-1 rounded-full overflow-hidden bg-border/30 transition-all duration-300"
                    style={{ height: isActive ? '6px' : '2px' }}
                  >
                    {isActive && (
                      <div
                        className="absolute top-0 left-0 bottom-0 rounded-full transition-all duration-50 ease-linear"
                        style={{
                          width: `${progress}%`,
                          backgroundColor: '#059669',
                        }}
                      />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Main Carousel */}
        <div className="relative">
          {/* Video/Content Display */}
          <div className="relative rounded-lg border border-border/30 bg-background-card/35 backdrop-blur-lg overflow-hidden aspect-video mb-6">
            <video
              key={currentIndex}
              className="w-full h-full object-cover"
              autoPlay
              muted
              loop
              playsInline
            >
              <source src="https://xguihxuzqibwxjnimxev.supabase.co/storage/v1/object/public/videos/marketing/website/supabase-table-editor.webm" type="video/webm" />
              Your browser does not support the video tag.
            </video>
          </div>
          
          {/* Headline and Subtext */}
          <div className="text-center">
            <h3 className="text-3xl md:text-4xl font-semibold text-foreground mb-3">
              {features[currentIndex].headline}
            </h3>
            <p className="text-lg text-foreground-secondary max-w-3xl mx-auto">
              {features[currentIndex].subtext}
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

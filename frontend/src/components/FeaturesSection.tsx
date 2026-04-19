import {
  FolderGit2,
  Bot,
  Eye,
  FileCheck,
  Radio,
  HeartPulse,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { cn } from "../lib/utils";
import PipelineVisualization from "./PipelineVisualization";
import AnomalyDetectionVisualization from "./AnomalyDetectionVisualization";

interface Feature {
  icon: React.ReactNode;
  title: string;
  description: string;
  highlights: string[];
  showPipeline?: boolean;
  showLottie?: boolean;
  showAnomalyDetection?: boolean;
  showImage?: boolean;
  imagePath?: string;
  spanColumns?: number;
  route: string;
}

const features: Feature[] = [
  // Row 1: double, single, single
  {
    icon: <Bot className="h-6 w-6" />,
    title: "Autonomous Security Agent",
    description: "An AI security engineer that monitors your codebase, fixes vulnerabilities, and maintains compliance.",
    highlights: [],
    showLottie: true,
    spanColumns: 2,
    route: "/autonomous-agent",
  },
  {
    icon: <FolderGit2 className="h-6 w-6" />,
    title: "Repository Tracking",
    description: "Link your codebase for automatic security updates.",
    highlights: [],
    showPipeline: true,
    route: "/repository-tracking",
  },
  {
    icon: <Eye className="h-6 w-6" />,
    title: "Anomaly Detection",
    description:
      "Detection of suspicious package behavior.",
    highlights: [],
    showAnomalyDetection: true,
    route: "/anomaly-detection",
  },
  // Row 2: single, single, double
  {
    icon: <Radio className="h-6 w-6" />,
    title: "Vulnerability Intelligence",
    description:
      "CVE monitoring, and reachability analysis.",
    highlights: [],
    showImage: true,
    imagePath: "/images/vulnerability_intelligence.png",
    route: "/vulnerability-intelligence",
  },
  {
    icon: <FileCheck className="h-6 w-6" />,
    title: "SBOM & Compliance",
    description:
      "SBOM generation, and compliance tracking.",
    highlights: [],
    showImage: true,
    imagePath: "/images/sbom_compliance.png",
    route: "/sbom-compliance",
  },
  {
    icon: <HeartPulse className="h-6 w-6" />,
    title: "Project Health & Dependency Insights",
    description:
      "A unified health score for each project with comprehensive dependency analysis.",
    highlights: [
    ],
    showImage: true,
    imagePath: "/images/project_health.png",
    spanColumns: 2,
    route: "/project-health",
  },
];

export default function FeaturesSection() {
  const [visibleCards, setVisibleCards] = useState<Set<number>>(new Set());
  const cardRefs = useRef<(HTMLElement | null)[]>([]);

  useEffect(() => {
    const observers: IntersectionObserver[] = [];

    cardRefs.current.forEach((ref, index) => {
      if (ref) {
        const observer = new IntersectionObserver(
          (entries) => {
            entries.forEach((entry) => {
              if (entry.isIntersecting) {
                setVisibleCards((prev) => new Set(prev).add(index));
              }
            });
          },
          { threshold: 0.1, rootMargin: "0px 0px -100px 0px" }
        );
        observer.observe(ref);
        observers.push(observer);
      }
    });

    return () => {
      observers.forEach((observer) => observer.disconnect());
    };
  }, []);

  return (
    <section className="container mx-auto px-4 py-20 lg:py-32">
      <div className="max-w-7xl mx-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((feature, index) => (
            <Link
              key={index}
              to={feature.route}
              ref={(el) => (cardRefs.current[index] = el)}
              className={cn(
                "group relative rounded-lg border border-border/30 bg-background-card/35 backdrop-blur-lg p-4 transition-all duration-500 flex flex-col",
                "hover:border-primary/50 hover:bg-background-card/60 hover:shadow-lg hover:shadow-primary/10 hover:-translate-y-1",
                "cursor-pointer",
                feature.spanColumns === 2 && "md:col-span-2 lg:col-span-2",
                visibleCards.has(index)
                  ? "opacity-100 translate-y-0"
                  : "opacity-0 translate-y-8"
              )}
              style={{
                transitionDelay: `${index * 100}ms`,
              }}
            >
              {feature.showLottie ? (
                <div className="relative">
                  {/* Full width edge-to-edge image behind content */}
                  <div className="flex items-center justify-center -mx-4 -mb-4 overflow-hidden rounded-lg">
                    <img
                      src={feature.imagePath || "/images/autonomous_agents.png"}
                      alt={feature.title}
                      className="w-full h-auto transition-transform duration-500 group-hover:scale-105 group-hover:brightness-110"
                    />
                  </div>

                  {/* Text content - positioned on top */}
                  <div className="absolute top-0 left-0 right-0 p-4 z-10 flex flex-col">
                    {/* Icon and Title */}
                    <div className="flex items-center gap-3 mb-4">
                      <div className="text-foreground-secondary shrink-0">
                        {feature.icon}
                      </div>
                      <h3 className="text-xl font-semibold text-foreground">
                        {feature.title}
                      </h3>
                    </div>

                    {/* Description */}
                    <p className="text-foreground-secondary leading-relaxed mb-6">
                      {feature.description}
                    </p>

                    {/* Highlights - only show if they exist */}
                    {feature.highlights.length > 0 && (
                      <ul className="space-y-2 mt-4">
                        {feature.highlights.map((highlight, idx) => (
                          <li
                            key={idx}
                            className="text-sm text-foreground-secondary flex items-center gap-2"
                          >
                            <span className="text-foreground-muted">•</span>
                            <span>{highlight.replace("✓", "").trim()}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              ) : (
                <>
                  {/* Icon and Title */}
                  <div className="flex items-center gap-3 mb-4">
                    <div className="text-foreground-secondary shrink-0">
                      {feature.icon}
                    </div>
                    <h3 className="text-xl font-semibold text-foreground">
                      {feature.title}
                    </h3>
                  </div>

                  {/* Description */}
                  <p className="text-foreground-secondary leading-relaxed mb-6">
                    {feature.description}
                  </p>

                  {/* Highlights - only show if they exist */}
                  {feature.highlights.length > 0 && (
                    <ul className="space-y-2 mt-4">
                      {feature.highlights.map((highlight, idx) => (
                        <li
                          key={idx}
                          className="text-sm text-foreground-secondary flex items-center gap-2"
                        >
                          <span className="text-foreground-muted">•</span>
                          <span>{highlight.replace("✓", "").trim()}</span>
                        </li>
                      ))}
                    </ul>
                  )}

                  {/* Pipeline Visualization - extends to edges */}
                  {feature.showPipeline && <PipelineVisualization />}

                  {/* Anomaly Detection Visualization - extends to edges */}
                  {feature.showAnomalyDetection && <AnomalyDetectionVisualization />}

                  {/* Image at bottom - extends to edges */}
                  {feature.showImage && feature.imagePath && (
                    <div className="flex items-center justify-center -mx-4 -mb-4 mt-auto overflow-hidden rounded-lg">
                      <img
                        src={feature.imagePath}
                        alt={feature.title}
                        className="w-full h-auto transition-transform duration-500 group-hover:scale-105 group-hover:brightness-110"
                      />
                    </div>
                  )}
                </>
              )}

            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}


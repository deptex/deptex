import { useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { HeartPulse, Book, ChevronLeft, ChevronRight } from "lucide-react";

const features = [
  {
    title: "Project Health Score",
    description: "Composite metric combining dependency health, vulnerabilities, compliance, and activity. Get a single number that represents your project's security posture.",
  },
  {
    title: "Dependency Flattening Analysis",
    description: "Get a flattening score (0-100) that measures dependency tree health. Detect conflicts, low similarity packages, and get upgrade recommendations.",
  },
  {
    title: "Risk & Reachability Scoring",
    description: "Understand package risk scores and dependency blast-radius analysis. Prioritize fixes based on actual impact to your runtime.",
  },
];

export default function ProjectHealthPage() {
  const [currentSlide, setCurrentSlide] = useState(0);

  const nextSlide = () => {
    setCurrentSlide((prev) => (prev + 1) % features.length);
  };

  const prevSlide = () => {
    setCurrentSlide((prev) => (prev - 1 + features.length) % features.length);
  };

  const goToSlide = (index: number) => {
    setCurrentSlide(index);
  };

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 lg:py-32">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            {/* Left Column - Text Content */}
            <div>
              <div className="flex items-center gap-3 mb-6">
                <div className="rounded-lg bg-background-card/50 p-3 border border-border/30">
                  <HeartPulse className="h-6 w-6 text-foreground" />
                </div>
                <span className="text-lg font-medium text-foreground-secondary">Project Health & Dependency Insights</span>
              </div>
              <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-foreground">
                Project Health & Dependency Insights
              </h1>
              <p className="text-xl text-foreground-secondary mb-8 leading-relaxed">
                Get instant visibility into your project's health with a real-time score based on vulnerabilities, package freshness, supply-chain risk, policy violations, and agent findings.
              </p>
              <div className="flex flex-col sm:flex-row gap-4">
                <Button
                  asChild
                  size="lg"
                  className="bg-primary text-primary-foreground hover:bg-primary/90 text-base px-8 py-6"
                >
                  <Link to="/signup">Create project</Link>
                </Button>
                <Button
                  asChild
                  size="lg"
                  variant="outline"
                  className="text-base px-8 py-6 border-border hover:bg-background-subtle"
                >
                  <Link to="/docs">
                    <Book className="h-5 w-5 mr-2" />
                    See documentation
                  </Link>
                </Button>
              </div>
            </div>

            {/* Right Column - Video */}
            <div className="relative">
              <div className="rounded-lg border border-border/30 bg-background-card/35 backdrop-blur-lg overflow-hidden aspect-video">
                <video
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
            </div>
          </div>
        </div>
      </section>

      {/* Divider */}
      <div className="border-t border-border/30"></div>

      {/* Slideshow Section */}
      <section className="container mx-auto px-4 py-20">
        <div className="max-w-7xl mx-auto">
          <div className="relative">
            {/* Slideshow Container */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center min-h-[500px]">
              {/* Left - Content */}
              <div>
                <h3 className="text-2xl md:text-3xl font-semibold text-foreground mb-4">
                  {features[currentSlide].title}
                </h3>
                <p className="text-lg text-foreground-secondary leading-relaxed">
                  {features[currentSlide].description}
                </p>
              </div>

              {/* Right - Image */}
              <div className="rounded-lg border border-border/30 bg-background-card/35 backdrop-blur-lg overflow-hidden aspect-video">
                <div className="w-full h-full bg-gradient-to-br from-primary/10 to-primary/5 flex items-center justify-center">
                  <span className="text-foreground-secondary">Just a sample image for now</span>
                </div>
              </div>
            </div>

            {/* Navigation Arrows */}
            <button
              onClick={prevSlide}
              className="absolute left-0 top-1/2 -translate-y-1/2 -translate-x-4 lg:-translate-x-12 p-2 rounded-full bg-background-card/80 border border-border/30 hover:bg-background-card hover:border-border transition-colors"
              aria-label="Previous slide"
            >
              <ChevronLeft className="h-6 w-6 text-foreground" />
            </button>
            <button
              onClick={nextSlide}
              className="absolute right-0 top-1/2 -translate-y-1/2 translate-x-4 lg:translate-x-12 p-2 rounded-full bg-background-card/80 border border-border/30 hover:bg-background-card hover:border-border transition-colors"
              aria-label="Next slide"
            >
              <ChevronRight className="h-6 w-6 text-foreground" />
            </button>

            {/* Dots Navigation */}
            <div className="flex justify-center gap-2 mt-12">
              {features.map((_, index) => (
                <button
                  key={index}
                  onClick={() => goToSlide(index)}
                  className={`h-2 rounded-full transition-all ${
                    index === currentSlide
                      ? "w-8 bg-primary"
                      : "w-2 bg-foreground-secondary/30 hover:bg-foreground-secondary/50"
                  }`}
                  aria-label={`Go to slide ${index + 1}`}
                />
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

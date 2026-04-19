import { useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { Bot, Book, ChevronLeft, ChevronRight } from "lucide-react";

const features = [
  {
    title: "Queryable Chat",
    description: "Ask questions in natural language: \"Summarize my project's vulnerabilities\", \"Which projects use lodash across the org?\", or \"List outstanding license violations.\"",
  },
  {
    title: "Automated Reports",
    description: "Generate PDF/HTML compliance reports on-demand or scheduled. Get weekly or monthly summaries of your security posture automatically.",
  },
  {
    title: "Action-Oriented Commands",
    description: "Open upgrade PRs, apply AI patches for CVEs, mark dependencies as approved — all with human-in-the-loop approval for safety.",
  },
  {
    title: "Proactive Suggestions",
    description: "Receive periodic summaries of critical vulnerabilities open for more than 7 days, or high-risk packages across your organization.",
  },
  {
    title: "Integrations",
    description: "Send emails, create Jira tickets, post Slack summaries, and integrate with your existing workflow tools as instructed.",
  },
  {
    title: "Secure by Design",
    description: "All actions require explicit approval from authorized roles. Full audit trail with immutable logs for every query and action.",
  },
];

export default function AutonomousAgentPage() {
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
                  <Bot className="h-6 w-6 text-foreground" />
                </div>
                <span className="text-lg font-medium text-foreground-secondary">Autonomous Security Agent</span>
              </div>
              <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-foreground">
                Autonomous Security Engineer
              </h1>
              <p className="text-xl text-foreground-secondary mb-8 leading-relaxed">
                An AI-driven agent that lives inside your project and can be queried in natural language to perform security and compliance tasks, generate reports, and take automated actions with human approval.
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
                  <Link to="/docs" target="_blank" rel="noopener noreferrer">
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


import { Github } from "lucide-react";

function SinglePipeline() {
  return (
    <div className="flex items-center px-4">
      {/* GitHub Logo */}
      <div className="flex items-center justify-center w-12 h-12 rounded-lg bg-background-subtle/40 shrink-0 border border-white/30">
        <Github className="h-6 w-6 text-white" />
      </div>

      {/* Pipeline with animated dots */}
      <div className="flex-1 relative h-0.5 bg-border/40 overflow-hidden rounded-full">
        {/* Pipeline line background */}
        <div className="absolute inset-0 bg-border/30 rounded-full" />
        
        {/* Animated dots flowing from left to right */}
        {[...Array(3)].map((_, i) => (
          <div
            key={i}
            className="absolute top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-foreground-secondary flow-dot group-hover:animate-flow"
            style={{
              animationDelay: `${i * 0.3}s`,
            }}
          />
        ))}
      </div>

      {/* Deptex Logo */}
      <div className="flex items-center justify-center w-14 h-14 rounded-lg bg-background-subtle/40 shrink-0 border border-primary/40">
        <img
          src="/images/logo.png"
          alt="Deptex"
          className="h-7 w-7 object-contain"
        />
      </div>
    </div>
  );
}

export default function PipelineVisualization() {
  return (
    <div className="mt-8">
      <SinglePipeline />
    </div>
  );
}


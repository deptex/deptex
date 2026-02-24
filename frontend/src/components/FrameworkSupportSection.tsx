import { useState } from "react";

interface Framework {
  name: string;
  logoPath?: string;
  isHighlighted?: boolean;
}

const frameworks: Framework[] = [
  { name: "npm", logoPath: "/images/frameworks/npm.png" },
  { name: "Python", logoPath: "/images/frameworks/python.png" },
  { name: "Go", logoPath: "/images/frameworks/go.png" },
  { name: "Rust", logoPath: "/images/frameworks/rust.png" },
  { name: "Java", logoPath: "/images/frameworks/java.png" },
  { name: "Ruby", logoPath: "/images/frameworks/ruby.png" },
  { name: "PHP", logoPath: "/images/frameworks/php.png" },
];

function FrameworkLogo({ framework }: { framework: Framework }) {
  const [imageError, setImageError] = useState(false);

  if (!framework.logoPath || imageError) {
    return (
      <span className="text-foreground-secondary text-xs font-medium text-center">
        {framework.name}
      </span>
    );
  }

  return (
    <img
      src={framework.logoPath}
      alt={framework.name}
      className="w-10 h-10 object-contain transition-all duration-300 opacity-70"
      style={{ filter: 'brightness(0) invert(1) opacity(0.7)' }}
      onError={() => setImageError(true)}
    />
  );
}

export default function FrameworkSupportSection() {
  return (
    <section className="container mx-auto px-4 py-20 lg:py-32">
      <div className="max-w-7xl mx-auto">
        <div className="flex flex-col lg:flex-row items-center justify-between gap-12">
          {/* Text Content */}
          <div className="flex-1">
            <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold">
              <span className="text-foreground-secondary">Support for</span>
              <br />
              <span className="text-foreground">any package manager</span>
            </h2>
          </div>

          {/* Logos Row */}
          <div className="flex-1 w-full">
            <div className="flex items-center justify-center gap-4 flex-nowrap">
              {frameworks.map((framework, index) => (
                <div
                  key={index}
                  className={`
                    group flex items-center justify-center shrink-0
                    p-3 rounded-lg
                    bg-background-card/35 border border-border/30
                    transition-all duration-300
                    hover:border-primary/50 hover:bg-background-card/60 hover:shadow-lg hover:shadow-primary/10
                    ${framework.isHighlighted ? "ring-2 ring-primary/30" : ""}
                  `}
                  title={framework.name}
                >
                  <FrameworkLogo framework={framework} />
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

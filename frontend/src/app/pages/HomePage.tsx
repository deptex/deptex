import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Button } from "../../components/ui/button";
import PipelineShowcaseSection from "../../components/PipelineShowcaseSection";

const ROTATING_WORDS = ["easy.", "customizable.", "for you."];
const TYPE_MS = 80;

const ECOSYSTEMS = ["npm", "PyPI", "Maven", "Go", "Cargo", "RubyGems", "Composer", "NuGet", "Hex", "Pub", "Swift PM"];
/** One row of items with · between them; trailing · so loop has · between Swift PM and npm. */
const MARQUEE_ROW = [...ECOSYSTEMS.flatMap((name, i) => (i === 0 ? [name] : ["·", name])), "·"];
/** Repeat 4× so content is always wider than viewport; we scroll by 25% (one set) for seamless loop. */
const MARQUEE_FULL = [...MARQUEE_ROW, ...MARQUEE_ROW, ...MARQUEE_ROW, ...MARQUEE_ROW];
const BACKSPACE_MS = 50;
const HOLD_AFTER_TYPED_MS = 2500;

export default function HomePage() {
  const [wordIndex, setWordIndex] = useState(0);
  const [visibleLength, setVisibleLength] = useState(0);
  const [phase, setPhase] = useState<"typing" | "hold" | "backspacing">("typing");
  const currentWord = ROTATING_WORDS[wordIndex];

  // Hold phase: after word typed, wait then backspace (separate effect so cleanup doesn't cancel timeout)
  useEffect(() => {
    if (phase !== "hold") return;
    const t = setTimeout(() => setPhase("backspacing"), HOLD_AFTER_TYPED_MS);
    return () => clearTimeout(t);
  }, [phase]);

  useEffect(() => {
    if (phase === "typing") {
      if (visibleLength >= currentWord.length) {
        setPhase("hold");
        return;
      }
      const t = setTimeout(() => setVisibleLength((n) => n + 1), TYPE_MS);
      return () => clearTimeout(t);
    }
    if (phase === "backspacing") {
      if (visibleLength <= 0) {
        setWordIndex((i) => (i + 1) % ROTATING_WORDS.length);
        setPhase("typing");
        return;
      }
      const t = setTimeout(() => setVisibleLength((n) => n - 1), BACKSPACE_MS);
      return () => clearTimeout(t);
    }
  }, [phase, visibleLength, currentWord.length]);

  return (
    <div className="bg-background">
      <section className="relative min-h-[70vh] w-screen max-w-none left-1/2 -ml-[50vw] flex flex-col items-center justify-center overflow-hidden">
        {/* Undulating wave: chain of overlapping nodes with staggered animation (fluid “shifting” effect) */}
        <div className="wave-gradient" aria-hidden>
          <div className="wave-node node-1" />
          <div className="wave-node node-2" />
          <div className="wave-node node-3" />
          <div className="wave-node node-4" />
          <div className="wave-node node-5" />
        </div>
        {/* Optional: add hero-bg.png to frontend/public/images/ then uncomment next line for a background image */}
        {/* <div className="absolute inset-0 hero-bg-image opacity-90 pointer-events-none" style={{ backgroundImage: "url('/images/hero-bg.png')" }} aria-hidden /> */}
        <div className="container mx-auto px-4 py-0 lg:py-7 relative z-10 w-full">
          <div className="max-w-4xl mx-auto text-center">
            <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold mb-6 leading-tight text-center">
              <span className="inline-block whitespace-nowrap text-foreground">
                Security made{" "}
                <span style={{ color: "#025230" }}>{currentWord.slice(0, visibleLength)}</span>
              </span>
            </h1>
            <p className="text-lg md:text-xl text-foreground mb-10 max-w-2xl mx-auto leading-relaxed">
              An open-source, customizable ASPM platform.
            </p>
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <Button
                asChild
                size="default"
                className="bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 font-semibold text-sm px-5 py-2.5 rounded-lg h-9"
              >
                <Link to="/login">Get started</Link>
              </Button>
              <Button
                asChild
                size="default"
                variant="outline"
                className="text-sm px-5 py-2.5 rounded-lg h-9 border border-border bg-background-card text-foreground hover:bg-background-subtle font-medium"
              >
                <Link to="/get-demo">Get a demo</Link>
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Full-width bridge card: edge-to-edge marquee only, seamless infinite loop */}
      <section
        className="relative w-screen max-w-none left-1/2 -ml-[50vw] pt-8 sm:pt-10 overflow-hidden"
        aria-label="Supported ecosystems"
      >
        <div
          className="hero-bridge-enter w-full border-y border-border bg-[#121418] backdrop-blur-sm px-4 py-6 sm:py-7"
          style={{ boxShadow: "0 0 0 1px rgba(255,255,255,0.03), 0 4px 24px -4px rgba(0,0,0,0.5)" }}
        >
          <div className="relative overflow-hidden">
            <div className="hero-bridge-marquee flex w-max items-center gap-8 whitespace-nowrap text-foreground-muted text-sm font-medium">
              {MARQUEE_FULL.map((item, i) => (
                <span key={i} className={item === "·" ? "text-foreground/30 shrink-0" : "shrink-0"}>
                  {item}
                </span>
              ))}
            </div>
          </div>
        </div>
      </section>

      <PipelineShowcaseSection />
    </div>
  );
}

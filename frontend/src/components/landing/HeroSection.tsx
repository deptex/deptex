/**
 * HeroSection — landing-page-redesign.plan.md §3.2.
 *
 * Motion: H1 + subhead + CTAs render INSTANTLY (LCP candidates — zero
 * entrance animation, no Reveal). The trace panel's one-time draw-on
 * pass lives inside TraceSpecimen. Everything else here is static.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "../ui/button";
import { RepoLink, SpecimenFrame } from "./primitives";
import { REPO_PUBLIC, REPO_URL } from "./repoLinks";
import TraceSpecimen from "./TraceSpecimen";

/**
 * Atmosphere variants — competitors all carry a designed background field
 * (Endor's chevron aurora, Snyk's dot matrix, Socket's pixel blocks); a bare
 * void reads unfinished. Dev-only switcher (keys 1/2/3) until the founder
 * picks one, then this collapses to the winner.
 */
type Atmosphere = "aurora" | "wave" | "grid";

function AtmosphereLayer({ variant }: { variant: Atmosphere }) {
  if (variant === "aurora") {
    return <div className="hero-aurora" aria-hidden />;
  }
  if (variant === "wave") {
    // The original wave-gradient node chain, positioned behind the headline zone.
    return (
      <div className="absolute inset-x-0 top-0 h-[700px] pointer-events-none" aria-hidden>
        <div className="wave-gradient">
          <div className="wave-node node-1" />
          <div className="wave-node node-2" />
          <div className="wave-node node-3" />
          <div className="wave-node node-4" />
          <div className="wave-node node-5" />
        </div>
      </div>
    );
  }
  // grid: dot texture around the headline + a softened aurora behind it
  return (
    <div className="absolute inset-0 pointer-events-none" aria-hidden>
      <div className="hero-aurora hero-aurora--soft" />
      <div className="hero-grid" />
    </div>
  );
}

export default function HeroSection() {
  const [atmosphere, setAtmosphere] = useState<Atmosphere>("aurora");

  // Dev-only variant switcher: 1 = aurora, 2 = wave, 3 = grid.
  useEffect(() => {
    if (!import.meta.env.DEV) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLElement && /INPUT|TEXTAREA|SELECT/.test(e.target.tagName)) return;
      if (e.key === "1") setAtmosphere("aurora");
      if (e.key === "2") setAtmosphere("wave");
      if (e.key === "3") setAtmosphere("grid");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <section className="relative w-full overflow-hidden bg-[#050505]">
      <AtmosphereLayer variant={atmosphere} />
      {import.meta.env.DEV && (
        <div className="absolute right-4 top-4 z-20 font-mono text-[10px] text-foreground-secondary">
          bg: {atmosphere} · press 1/2/3
        </div>
      )}
      <div className="relative z-10 mx-auto max-w-[1200px] px-6 pb-20 pt-28 sm:pb-24 sm:pt-36">
        <div className="mx-auto max-w-[800px] text-center">
          <h1 className="text-[38px] font-semibold leading-[1.1] tracking-[-0.02em] text-foreground sm:text-[60px]">
            Your repo sets the score.
            <span className="block">
              <span className="text-accent-text">Aegis</span> writes the fix.
            </span>
          </h1>
          <p className="mx-auto mt-6 max-w-[640px] text-[15px] leading-[1.6] text-foreground sm:text-[17px]">
            Every finding gets a contextual risk score based on your code, not just CVSS.
            Aegis, your org's own security engineer, investigates and writes the fix.
          </p>

          {/* CTAs — mobile: stack full-width, green first */}
          <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
            <Button variant="green" asChild className="w-full sm:w-auto">
              <Link to="/login">Scan a repo</Link>
            </Button>
            {REPO_PUBLIC ? (
              <Button variant="white" asChild className="w-full sm:w-auto">
                <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
                  Read the code ↗
                </a>
              </Button>
            ) : (
              /* Pre-flight blocker #1 fallback: repo private → docs */
              <Button variant="white" asChild className="w-full sm:w-auto">
                <Link to="/docs">View docs ↗</Link>
              </Button>
            )}
          </div>
          <p className="mt-3 text-xs text-foreground-secondary">
            Free $5 credit · no credit card
          </p>
        </div>

        {/* The trace specimen — the page's focal artifact, one glow */}
        <div className="mx-auto mt-14 max-w-[720px]">
          <SpecimenFrame glow>
            <TraceSpecimen />
          </SpecimenFrame>
          <div className="mt-3 flex flex-col items-center gap-1 text-center">
            <p className="font-mono text-xs text-foreground-secondary">
              ▸ Real scan output from our open dogfood corpus —{" "}
              <RepoLink path="depscanner/test-repos" />
            </p>
            <p className="font-mono text-[11px] text-foreground-muted">
              sample data — real scan output replaces this (asset A1)
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

/**
 * HeroSection — landing-page-redesign.plan.md §3.2.
 *
 * Motion: H1 + subhead + CTAs render INSTANTLY (LCP candidates — zero
 * entrance animation, no Reveal). The trace panel's one-time draw-on
 * pass lives inside TraceSpecimen. Everything else here is static.
 */
import { Link } from "react-router-dom";
import { Button } from "../ui/button";
import { RepoLink, SpecimenFrame } from "./primitives";
import { REPO_PUBLIC, REPO_URL } from "./repoLinks";
import TraceSpecimen from "./TraceSpecimen";

export default function HeroSection() {
  return (
    <section className="relative w-full overflow-hidden bg-[#050505]">
      <div className="mx-auto max-w-[1200px] px-6 pb-20 pt-28 sm:pb-24 sm:pt-36">
        <div className="mx-auto max-w-[800px] text-center">
          <h1 className="text-[38px] font-semibold leading-[1.1] tracking-[-0.02em] text-foreground sm:text-[60px]">
            Security findings that show their work.
          </h1>
          <p className="mx-auto mt-6 max-w-[640px] text-[15px] leading-[1.6] text-foreground-secondary sm:text-[17px]">
            Deptex checks every CVE for a path from your entry points to the vulnerable
            function, in 8 languages. Proven paths ship with the finding, hop by hop;
            unreachable ones score zero.
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

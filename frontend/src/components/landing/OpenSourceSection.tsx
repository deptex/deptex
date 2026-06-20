/**
 * Open source — re-added 2026-06-19 (founder, Supabase "Open source from day
 * one" reference). Cut earlier for its AI-looking fake terminal; rebuilt clean
 * and centered, no facsimile.
 *
 * Security-specific angle (not generic-OSS): every other scanner is a black
 * box; Deptex is AGPL-3.0, readable end to end — a wedge Snyk/Wiz/Endor can't
 * copy. No star count by design (pre-launch; a low count hurts more than it
 * helps) — a plain "Read the code" CTA instead.
 */
import { Button } from "../ui/button";
import { Reveal } from "./primitives";
import { REPO_URL } from "./repoLinks";

export default function OpenSourceSection() {
  return (
    <section className="w-full border-t border-white/[0.08]">
      <div className="mx-auto flex max-w-[760px] flex-col items-center px-6 py-24 text-center md:py-28">
        <Reveal>
          <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
            Open source. Read every line.
          </h2>
        </Reveal>
        <Reveal delayMs={80}>
          <p className="mt-5 text-[15px] leading-relaxed text-foreground md:text-base">
            Every other scanner is a black box. Deptex is open source under{" "}
            <span className="text-accent-text">AGPL-3.0</span> — the scanner, the
            reachability engine, the fix agent, every line. Audit the tool that
            audits you.
          </p>
        </Reveal>
        <Reveal delayMs={160}>
          <div className="mt-8">
            <Button
              variant="outline"
              asChild
              className="!h-9 !rounded-lg !px-4 text-foreground"
            >
              <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
                <img
                  src="/images/integrations/github.png"
                  alt=""
                  className="h-4 w-4 rounded-full"
                  aria-hidden
                />
                deptex/deptex
              </a>
            </Button>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

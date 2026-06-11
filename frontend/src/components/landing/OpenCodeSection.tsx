/**
 * §3.11 Open code & self-host (landing-page-redesign.plan.md).
 * The trust substrate: read it, run it locally, self-host it — license stated
 * honestly. Terminal recording (A6) is click-to-play when the asset lands;
 * PlaceholderCanvas stands in until then.
 */
import { Button } from "../ui/button";
import { PlaceholderCanvas, Reveal, RepoLink, SpecimenFrame } from "./primitives";
import { REPO_PUBLIC, REPO_URL, repoFile } from "./repoLinks";

export default function OpenCodeSection() {
  return (
    <section className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-24 md:py-32">
        <Reveal>
          <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
            Don't trust the scanner. Read it.
          </h2>
        </Reveal>

        <div className="mt-12 grid grid-cols-1 gap-12 lg:grid-cols-[7fr,5fr] lg:gap-16">
          {/* Terminal recording (A6) — SpecimenFrame, no glow */}
          <Reveal delayMs={80}>
            <SpecimenFrame>
              <PlaceholderCanvas
                assetId="A6"
                description="deptex-scan terminal recording — ends on findings table + exit code (click-to-play)"
                className="!rounded-none !border-0"
              />
            </SpecimenFrame>
            <p className="mt-3 font-mono text-xs leading-relaxed text-foreground-secondary">
              deptex-scan: the same scanners, on your machine. No account, no
              cloud. Docker only.
            </p>
          </Reveal>

          {/* Prose column */}
          <Reveal delayMs={160}>
            <div className="flex flex-col gap-7">
              <div>
                <h3 className="text-lg font-semibold text-foreground">
                  One repo. The whole platform.
                </h3>
                <p className="mt-2 text-[15px] leading-relaxed text-foreground-secondary">
                  Scanner, taint engine, fix agent, every migration:
                  source-available in a single repository. No enterprise
                  edition, no withheld code.
                </p>
              </div>

              <div>
                <p className="text-[15px] leading-relaxed text-foreground-secondary">
                  FSL-licensed. Every release becomes{" "}
                  <span className="text-accent-text">Apache 2.0</span> on its
                  second anniversary.
                </p>
                <div className="mt-1.5">
                  <RepoLink path="LICENSE" label="Read the license" />
                </div>
              </div>

              <p className="text-[15px] leading-relaxed text-foreground-secondary">
                Self-host the stack on your infra — guide in the repo. Built on
                the open-source Supabase stack.
              </p>

              <p className="text-[15px] leading-relaxed text-foreground-secondary">
                Scans run in ephemeral workers. The clone is deleted when the
                scan ends; what persists are the findings and the SBOM.
              </p>
            </div>
          </Reveal>
        </div>

        {/* CTAs — drop entirely if the repo flips private (pre-flight #1) */}
        {REPO_PUBLIC && (
          <Reveal delayMs={240}>
            <div className="mt-12 flex flex-col gap-3 sm:flex-row">
              <Button variant="white" asChild>
                <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
                  Read the code ↗
                </a>
              </Button>
              <Button
                variant="outline"
                className="!h-8 !rounded-lg !px-3"
                asChild
              >
                <a
                  href={repoFile("docs/self-hosting.md")}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Self-hosting guide ↗
                </a>
              </Button>
            </div>
          </Reveal>
        )}
      </div>
    </section>
  );
}

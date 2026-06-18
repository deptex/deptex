/**
 * §3.11 Open code & self-host (landing-page-redesign.plan.md).
 * The trust substrate: read it, run it locally, self-host it — license stated
 * honestly.
 *
 * 2026-06-16 (founder): the unbuilt A6 terminal recording was replaced with a
 * static `deptex-scan` terminal rendered as real DOM (same approach as the
 * Aegis chat/PR cards) — crisp, editable, no recorded asset to wait on. Output
 * is category-level (no OSS vendor names, per the BreadthWall decision) and the
 * counts match the rest of the page (141 → 28 after triage · 3 reachable, the
 * real dogfood-express scan).
 */
import { Button } from "../ui/button";
import { Reveal, RepoLink } from "./primitives";
import { REPO_PUBLIC, REPO_URL, repoFile } from "./repoLinks";

const SCAN_STEPS: [string, string][] = [
  ["SBOM", "142 dependencies · 8 ecosystems"],
  ["Dependencies", "17 known CVEs"],
  ["Reachability", "3 reachable · 14 auto-ignored"],
  ["SAST", "2 findings"],
  ["Secrets", "clean"],
  ["Containers", "100 image CVEs"],
  ["IaC", "1 misconfiguration"],
];

function ScanTerminal() {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-[#0a0a0a] shadow-[0_20px_60px_rgba(0,0,0,0.6)]">
      {/* title bar */}
      <div className="flex items-center gap-2 border-b border-border px-4 py-3">
        <span className="h-3 w-3 rounded-full bg-[#ff5f57]" />
        <span className="h-3 w-3 rounded-full bg-[#febc2e]" />
        <span className="h-3 w-3 rounded-full bg-[#28c840]" />
        <span className="ml-2 font-mono text-[11px] text-foreground-secondary">
          deptex-scan — local
        </span>
      </div>

      {/* body */}
      <div className="px-4 py-4 font-mono text-[12px] leading-[1.7]">
        <p>
          <span className="text-foreground-secondary">$</span>{" "}
          <span className="text-foreground">npx deptex-scan .</span>
        </p>
        <p className="mt-2 text-foreground-secondary">
          local mode · no account · no cloud
        </p>

        <div className="mt-3 flex flex-col gap-0.5">
          {SCAN_STEPS.map(([label, result]) => (
            <div
              key={label}
              className="grid grid-cols-[14px_108px_1fr] items-baseline gap-x-2"
            >
              <span className="text-accent-text">✓</span>
              <span className="text-foreground">{label}</span>
              <span className="text-foreground-secondary">{result}</span>
            </div>
          ))}
        </div>

        <p className="mt-3 text-foreground">
          141 findings · 28 after triage · 3 reachable
        </p>
        <p className="mt-1.5 text-foreground-secondary">
          sbom.cdx.json + findings.json written
        </p>
        <p className="mt-2 text-[#ff7b72]">
          ✗ exit 1 — reachable vulnerabilities found
        </p>
      </div>
    </div>
  );
}

export default function OpenCodeSection() {
  return (
    <section className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-24 md:py-32">
        <Reveal>
          <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
            Don&apos;t trust the scanner. Read it.
          </h2>
        </Reveal>

        <div className="mt-12 grid grid-cols-1 gap-12 lg:grid-cols-[7fr,5fr] lg:gap-16">
          {/* deptex-scan terminal — static DOM, replaces the A6 recording */}
          <Reveal delayMs={80}>
            <ScanTerminal />
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

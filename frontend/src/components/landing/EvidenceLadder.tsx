/**
 * §3.6 Reachability deep-dive — the evidence ladder.
 * landing-page-redesign.plan.md: tier rail (5 verdicts, weights verbatim from
 * depscanner/src/depscore.ts), Static proof / Runtime proof cards, honesty line
 * as plain prose. Motion: shared reveal + ONE 300ms in-view badge cross-fade.
 */
import { useEffect, useRef, useState } from "react";
import { Reveal, RepoLink, TierPill } from "./primitives";

const TIERS = [
  { name: "confirmed", weight: "1.0", textClass: "text-accent-text" },
  { name: "data_flow", weight: "0.9", textClass: "text-neutral-200" },
  { name: "function", weight: "0.7", textClass: "text-neutral-400" },
  { name: "module", weight: "0.5", textClass: "text-neutral-500" },
  { name: "unreachable", weight: "0.0", textClass: "text-neutral-600" },
] as const;

/** One-shot in-view cross-fade: data_flow → confirmed · runtime (300ms, never loops). */
function RuntimeBadgeFlip() {
  const ref = useRef<HTMLDivElement>(null);
  const [flipped, setFlipped] = useState(false);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    let timer: number | undefined;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          observer.disconnect();
          // brief beat so the "before" state is actually seen, then flip once
          timer = window.setTimeout(() => setFlipped(true), 700);
        }
      },
      { threshold: 0.5 }
    );
    observer.observe(node);
    return () => {
      observer.disconnect();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, []);

  return (
    <div ref={ref} className="mt-auto pt-5">
      <div className="flex items-center gap-3">
        <span className="font-mono text-xs text-foreground-secondary">verdict</span>
        <span className="inline-grid justify-items-start">
          <span
            aria-hidden={flipped}
            className={`col-start-1 row-start-1 transition-opacity duration-300 motion-reduce:transition-none ${
              flipped ? "opacity-0" : "opacity-100"
            }`}
          >
            <TierPill tier="data_flow" />
          </span>
          <span
            aria-hidden={!flipped}
            className={`col-start-1 row-start-1 transition-opacity duration-300 motion-reduce:transition-none ${
              flipped ? "opacity-100" : "opacity-0"
            }`}
          >
            <TierPill tier="confirmed" label="confirmed · runtime" />
          </span>
        </span>
      </div>
      <p className="mt-3 font-mono text-xs text-foreground-secondary">
        sample data — real scan output replaces this (asset A8)
      </p>
    </div>
  );
}

export default function EvidenceLadder() {
  return (
    <section id="reachability" className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-24">
        <Reveal>
          <h2 className="text-[32px] font-semibold leading-tight tracking-[-0.02em] text-foreground md:text-[40px]">
            Five verdicts. Every one earned.
          </h2>
        </Reveal>

        {/* Tier rail — the legend for every pill on the page */}
        <Reveal delayMs={80} className="mt-10">
          <div className="overflow-x-auto">
            <div className="flex min-w-max rounded-lg border border-white/[0.08] divide-x divide-white/[0.08]">
              {TIERS.map((tier) => (
                <div
                  key={tier.name}
                  className="flex min-w-[128px] flex-1 flex-col items-center gap-1 px-6 py-4"
                >
                  <span className={`font-mono text-sm ${tier.textClass}`}>{tier.name}</span>
                  <span className={`font-mono text-xs tabular-nums opacity-70 ${tier.textClass}`}>
                    {tier.weight}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <p className="mt-3 font-mono text-xs text-foreground-secondary">
            Weights multiply straight into Depscore —{" "}
            <RepoLink path="depscanner/src/depscore.ts" label="depscore.ts" />
          </p>
        </Reveal>

        {/* Static proof / Runtime proof */}
        <div className="mt-12 grid items-stretch gap-4 md:grid-cols-2">
          <Reveal className="h-full">
            <div className="flex h-full flex-col rounded-xl border border-[#262626] bg-[#0a0a0a] p-6">
              <h3 className="text-base font-semibold text-foreground">Static proof.</h3>
              <p className="mt-2 text-[15px] leading-relaxed text-foreground-secondary">
                Confirmed and <span className="font-mono">data_flow</span> verdicts carry the full
                taint trace, file and line per hop, plus the entry-point context: public
                unauthenticated, authenticated internal, or offline worker.
              </p>
            </div>
          </Reveal>
          <Reveal delayMs={80} className="h-full">
            <div className="flex h-full flex-col rounded-xl border border-[#262626] bg-[#0a0a0a] p-6">
              <h3 className="text-base font-semibold text-foreground">Runtime proof.</h3>
              <p className="mt-2 text-[15px] leading-relaxed text-foreground-secondary">
                Two DAST engines attack the running app: OWASP ZAP and Nuclei. A CVE-tagged Nuclei
                hit flips the verdict to <span className="font-mono">confirmed</span>. Not
                predicted reachable: attacked, and it answered.
              </p>
              <RuntimeBadgeFlip />
            </div>
          </Reveal>
        </div>

        {/* Honesty line — plain prose, deliberately NOT quote-styled */}
        <Reveal delayMs={80} className="mt-12">
          <p className="max-w-[640px] text-[15px] leading-relaxed text-foreground">
            When the engine can't be sure, it floors the verdict at{" "}
            <span className="font-mono">module</span>. It never hides a real vulnerability to make
            a number look good.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

/**
 * FindingJourney — the page's flagship argument (replaces honesty-split +
 * pipeline). Follows ONE finding through its life: reported → scored in
 * your context → fixed by Aegis. Step 02 carries both directions: the
 * downgrade (noise dies with reasons) and the upgrade (real danger CVSS
 * undersold). Founder-directed 2026-06-11.
 *
 * Sample data discipline: numbers are obviously-sample until real scan rows
 * replace them (asset A2); step 03 reuses the real Aegis plan capture.
 */
import { Reveal } from "./primitives";

function StepLabel({ n, verb }: { n: string; verb: string }) {
  return (
    <p className="font-mono text-[13px] text-foreground-secondary">
      {n} <span aria-hidden>▸</span> <span className="text-accent-text">{verb}</span>
    </p>
  );
}

/** Score transition row for step 02: CVSS → depscore with reason chips. */
function ScoreRow({
  from,
  to,
  chips,
  hot,
}: {
  from: string;
  to: string;
  chips: string[];
  hot?: boolean;
}) {
  return (
    <div
      className={`flex flex-col gap-3 rounded-xl border p-4 sm:p-5 ${
        hot ? "border-[#404040] bg-[#0d0d0d]" : "border-border bg-[#0a0a0a]"
      }`}
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 font-mono tabular-nums">
        <span className="text-[15px] text-foreground-secondary">
          CVSS <span className="line-through opacity-70">{from}</span>
        </span>
        <span className="text-foreground-secondary" aria-hidden>
          →
        </span>
        <span className={`text-[22px] font-semibold ${hot ? "text-accent-text" : "text-foreground-secondary"}`}>
          {to}
        </span>
        <span className="text-xs uppercase tracking-wider text-foreground-secondary">
          depscore
        </span>
      </div>
      <div className="flex flex-wrap gap-2">
        {chips.map((c) => (
          <span
            key={c}
            className={`rounded-full border px-2.5 py-0.5 font-mono text-[11px] ${
              hot
                ? "border-accent-text/40 bg-accent-text/10 text-accent-text"
                : "border-border bg-[#171717] text-foreground-secondary"
            }`}
          >
            {c}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function FindingJourney() {
  return (
    <section className="w-full bg-[#050505]">
      <div className="mx-auto max-w-[1200px] px-6 py-24 sm:py-32">
        <Reveal>
          <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground sm:text-[40px]">
            Follow a finding from alert to fix.
          </h2>
        </Reveal>

        {/* Timeline: continuous left spine, three steps */}
        <div className="relative mt-14 sm:mt-16">
          <div
            className="absolute bottom-6 left-[5px] top-1 hidden w-px bg-border sm:block"
            aria-hidden
          />
          <ol className="flex flex-col gap-16 sm:gap-20">
            {/* 01 — Reported */}
            <li className="relative sm:pl-10">
              <span
                className="absolute left-0 top-1 hidden h-[11px] w-[11px] rounded-full border border-border bg-[#171717] sm:block"
                aria-hidden
              />
              <Reveal>
                <div className="grid items-center gap-8 lg:grid-cols-[1fr,minmax(380px,1fr)] lg:gap-14">
                  <div>
                    <StepLabel n="01" verb="reported" />
                    <h3 className="mt-3 text-xl font-semibold text-foreground sm:text-2xl">
                      A new advisory lands on your repo.
                    </h3>
                    <p className="mt-3 max-w-md text-[15px] leading-relaxed text-foreground">
                      A dependency you ship just got a CVE. The advisory says critical.
                      Every other scanner pages you now.
                    </p>
                  </div>
                  {/* Artifact: the raw advisory card */}
                  <div className="rounded-xl border border-border bg-[#0a0a0a] p-4 sm:p-5">
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 font-mono text-[13px] tabular-nums">
                      <span className="text-foreground">CVE-XXXX-XXXXX</span>
                      <span className="text-foreground-muted" aria-hidden>·</span>
                      <span className="text-foreground-secondary">lodash@4.17.20</span>
                      <span className="ml-auto rounded-full border border-error/40 bg-error/10 px-2.5 py-0.5 text-[11px] text-[#f87171]">
                        CVSS 9.0 · Critical
                      </span>
                    </div>
                    <p className="mt-3 font-mono text-xs leading-relaxed text-foreground-secondary">
                      Severity from the advisory database. Context from nowhere.
                    </p>
                  </div>
                </div>
              </Reveal>
            </li>

            {/* 02 — Scored in your context */}
            <li className="relative sm:pl-10">
              <span
                className="absolute left-0 top-1 hidden h-[11px] w-[11px] rounded-full bg-accent-text sm:block"
                aria-hidden
              />
              <Reveal>
                <div className="grid items-center gap-8 lg:grid-cols-[1fr,minmax(380px,1fr)] lg:gap-14">
                  <div>
                    <StepLabel n="02" verb="scored" />
                    <h3 className="mt-3 text-xl font-semibold text-foreground sm:text-2xl">
                      Your context sets the real score.
                    </h3>
                    <p className="mt-3 max-w-md text-[15px] leading-relaxed text-foreground">
                      Deptex traces the path before it scores. This one's input is
                      sanitized and the route sits behind auth — the 9.0 was noise.
                      The one below it is reachable from a public route. CVSS couldn't
                      tell them apart.
                    </p>
                  </div>
                  <div className="flex flex-col gap-4">
                    <ScoreRow
                      from="9.0"
                      to="3.2"
                      chips={["input sanitized", "authenticated endpoint"]}
                    />
                    <ScoreRow
                      from="7.5"
                      to="92"
                      chips={["confirmed reachable", "public, unauthenticated route", "KEV-listed"]}
                      hot
                    />
                    <p className="font-mono text-[11px] text-foreground-muted">
                      sample data — real scan rows replace this (asset A2)
                    </p>
                  </div>
                </div>
              </Reveal>
            </li>

            {/* 03 — Fixed by Aegis */}
            <li className="relative sm:pl-10">
              <span
                className="absolute left-0 top-1 hidden h-[11px] w-[11px] rounded-full border border-border bg-[#171717] sm:block"
                aria-hidden
              />
              <Reveal>
                <div className="grid items-center gap-8 lg:grid-cols-[1fr,minmax(380px,1fr)] lg:gap-14">
                  <div>
                    <StepLabel n="03" verb="fixed" />
                    <h3 className="mt-3 text-xl font-semibold text-foreground sm:text-2xl">
                      Aegis opens the fix.
                    </h3>
                    <p className="mt-3 max-w-md text-[15px] leading-relaxed text-foreground">
                      For the one that matters, Aegis investigates, plans the upgrade,
                      and waits for your approval. The fix lands as a draft PR.
                    </p>
                  </div>
                  {/* Artifact: the real Aegis plan capture, lower crop (to-dos +
                      verification) so it reads differently from the hero's crop */}
                  <div className="overflow-hidden rounded-xl border border-border shadow-[0_8px_32px_-8px_rgba(0,0,0,0.7)]">
                    <img
                      src="/images/landing/hero-aegis-plan.png"
                      alt="Aegis fix plan: to-dos and verification steps for bumping lodash to 4.17.21"
                      className="aspect-[16/10] w-full object-cover"
                      style={{ objectPosition: "0 62%" }}
                    />
                  </div>
                </div>
              </Reveal>
            </li>
          </ol>
        </div>
      </div>
    </section>
  );
}

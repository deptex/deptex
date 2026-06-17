/**
 * Verified — "we don't guess, we trace" (2026-06-16, founder).
 *
 * The section that EXPLAINS the 79.6% proof-band stat: reachability is our
 * moat, and until now the page only asserted it. Styled like AegisSection
 * (two-column text header + a layered, vertically-centered card pair), but
 * mirrored — the hero card (the reachability trace) sits front-RIGHT so the
 * page alternates sides down its length.
 *
 * Front card: a data-flow trace, source → sink, with the real TierPill verdict
 * (src/components/aegis/.. uses the same five-tier vocabulary). Back card: the
 * findings list showing the noise auto-ignoring with reasons — one confirmed
 * row bright among auto-ignored unreachable rows. Real dogfood-express data
 * (lodash CVE-2021-23337 confirmed; minimist + python3.5 CVEs auto-ignored).
 */
import { ArrowDown } from "lucide-react";
import { Reveal, TierPill } from "./primitives";

/* one node in the source → sink trace */
function TraceNode({
  kind,
  mono,
  detail,
}: {
  kind?: string;
  mono: string;
  detail: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-background-card px-3 py-2.5">
      <div className="flex items-center gap-2">
        {kind && (
          <span className="rounded bg-background-subtle px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-foreground-secondary">
            {kind}
          </span>
        )}
        <span className="truncate font-mono text-[12px] text-foreground">{mono}</span>
      </div>
      <p className="mt-1 text-[11px] leading-snug text-foreground-secondary">{detail}</p>
    </div>
  );
}

function Connector() {
  return (
    <div className="flex justify-center py-1">
      <ArrowDown className="h-3.5 w-3.5 text-foreground-secondary/50" />
    </div>
  );
}

/* ---------------- front: the reachability trace ---------------- */
function ReachabilityTraceCard() {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-background shadow-[0_28px_80px_rgba(0,0,0,0.78)]">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <span className="font-mono text-[13px] text-foreground">
          CVE-2021-23337 · lodash
        </span>
        <TierPill tier="confirmed" label="Reachable" />
      </div>
      <div className="px-4 py-4">
        <TraceNode
          kind="Source"
          mono="req.body.template"
          detail="untrusted input from POST /report"
        />
        <Connector />
        <TraceNode
          mono="routes/render.js:42"
          detail="_.template(input) — tainted value reaches the call"
        />
        <Connector />
        <TraceNode
          kind="Sink"
          mono="lodash · _.template()"
          detail="prototype pollution → command injection"
        />
      </div>
    </div>
  );
}

/* ---------------- back: the triage outcome ---------------- */
const FINDINGS: { cve: string; pkg: string; tier: string; label: string }[] = [
  { cve: "CVE-2021-23337", pkg: "lodash", tier: "confirmed", label: "Reachable" },
  { cve: "CVE-2021-44906", pkg: "minimist", tier: "unreachable", label: "Auto-ignored" },
  { cve: "CVE-2019-9948", pkg: "python3.5", tier: "unreachable", label: "Auto-ignored" },
  { cve: "CVE-2019-10160", pkg: "python3.5", tier: "unreachable", label: "Auto-ignored" },
  { cve: "CVE-2021-3177", pkg: "python3.5", tier: "unreachable", label: "Auto-ignored" },
];

function FindingsVerdictCard() {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-[#0a0a0a]">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <span className="text-[13px] font-medium text-foreground">Findings</span>
        <span className="font-mono text-[12px] text-foreground-secondary">
          141 → 28 real
        </span>
      </div>
      <div className="divide-y divide-border/60">
        {FINDINGS.map((f) => {
          const confirmed = f.tier === "confirmed";
          return (
            <div
              key={f.cve}
              className={`flex items-center gap-3 px-4 py-2.5 ${
                confirmed
                  ? "border-l-2 border-accent-text/50 bg-accent-text/[0.04]"
                  : "opacity-50"
              }`}
            >
              <span className="flex-1 truncate font-mono text-[12px] text-foreground">
                {f.cve}{" "}
                <span className="text-foreground-secondary">· {f.pkg}</span>
              </span>
              <TierPill tier={f.tier} label={f.label} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function VerifiedSection() {
  return (
    <section id="verified" className="w-full border-t border-white/[0.08]">
      <div className="mx-auto max-w-[1200px] px-6 py-28">
        {/* two-column text header (Linear / Aegis pattern) */}
        <Reveal>
          <div className="grid gap-6 lg:grid-cols-[1.1fr_1fr] lg:gap-12">
            <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-[40px]">
              We don&apos;t guess.
              <span className="block text-foreground-secondary">We trace the path.</span>
            </h2>
            <div className="lg:pt-2">
              <p className="text-[15px] leading-relaxed text-foreground sm:text-base">
                Most scanners match a version number and page you. Deptex traces
                the real data flow — from the request to the vulnerable call —
                and proves whether a CVE is reachable in your code at all. The
                unreachable ones auto-ignore, with the path as the reason.
              </p>
            </div>
          </div>
        </Reveal>

        {/* layered composition: trace (front, right) over findings (back, left) */}
        <Reveal className="relative mt-14 lg:mt-16">
          <div className="relative flex flex-col lg:flex-row lg:items-center">
            {/* front: trace — first in DOM (mobile-first), right on desktop */}
            <div className="relative z-10 order-1 lg:order-2 lg:w-[44%]">
              <ReachabilityTraceCard />
            </div>
            {/* back: findings — left on desktop, slid under the trace */}
            <div className="relative z-0 mt-6 lg:mt-0 order-2 lg:order-1 lg:-mr-[6%] lg:w-[62%]">
              <FindingsVerdictCard />
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

/**
 * Verified — "we don't guess, we trace" (section 2; Linear-layered rebuild
 * 2026-06-18).
 *
 * The page's SECOND section: the WHY behind the product. Reframed as an argument
 * (not "more product"): the headline + the 79.6% / 5× stats (woven into the
 * paragraph) make the case, and the proof is a Linear-style layered composition —
 *   • BACK: the real findings table (VulnerabilityExpandableTable, the hero's
 *     same component) rendered NON-interactive and faded out to the right, so
 *     it's barely-there context/texture (the "wall of findings").
 *   • FRONT: the real reachability flow card (VulnerabilityOrgSidebarExpanded-
 *     Content) — the Source → Step → Sink taint stepper you can click through —
 *     as the focal element. lodash CVE-2021-23337, confirmed-reachable, 3 hops.
 *
 * Both are the actual product components fed mock heroDemo data (no facsimile;
 * every hand-drawn graphic here looked off). See
 * [[feedback_landing_use_real_components]].
 */
import { useState } from "react";
import { ChevronLeft, ChevronRight, CircleDashed } from "lucide-react";
import { Reveal, FocalArtifact } from "./primitives";
import { VulnerabilityExpandedCard } from "../security/VulnerabilityExpandedCard";
import { CodeSnippetBlock } from "../security/VulnerabilityOrgSidebarExpandedContent";
import VulnerabilityExpandableTable from "../security/VulnerabilityExpandableTable";
import { FileTypeIcon } from "../file-type-icon";
import { cn, cleanFilePath } from "../../lib/utils";
import {
  HERO_ORG_ID,
  heroBackgroundFindings,
  heroBackgroundTrackerLinks,
  heroFindingDetail,
  heroTraceVuln,
  heroTraceDetail,
} from "./heroDemo";

/* One-stage-at-a-time reachability stepper — the pre-#100 app look, kept for the
   landing: shows the Source, with a toggle arrow to flip to the Sink (and back).
   The in-app expanded card now stacks all stages; this stepper is landing-only. */
function TraceStepper() {
  const flow = heroTraceDetail.reachable_flows?.[0];
  const hops = flow
    ? [
        { role: "Source", tint: "text-amber-400", file: flow.entry_point_file ?? "", line: flow.entry_point_line ?? null, code: flow.entry_point_code ?? "" },
        { role: "Sink", tint: "text-red-400", file: flow.sink_file ?? "", line: flow.sink_line ?? null, code: flow.sink_code ?? "" },
      ]
    : [];
  const [idx, setIdx] = useState(0);
  if (hops.length === 0) return null;
  const cur = hops[Math.min(idx, hops.length - 1)];
  const go = (d: number) => setIdx((i) => (i + d + hops.length) % hops.length);
  const arrowCls =
    "flex h-5 w-5 items-center justify-center rounded text-zinc-400 transition-colors hover:bg-table-hover hover:text-foreground";
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background-card">
      <div className="flex items-center gap-2 border-b border-zinc-800/50 bg-[#0a0a0b] px-3 py-1.5">
        <button type="button" onClick={() => go(-1)} aria-label="Previous stage" className={arrowCls}>
          <ChevronLeft className="h-3.5 w-3.5" />
        </button>
        <FileTypeIcon file={cur.file} size={13} className="shrink-0" />
        <span className="truncate font-mono text-[11px] text-foreground">
          {cleanFilePath(cur.file)}
          {cur.line != null ? <span className="text-muted-foreground">:{cur.line}</span> : null}
        </span>
        <span className={cn("ml-auto shrink-0 text-[9px] font-semibold uppercase tracking-wide", cur.tint)}>
          {cur.role}
        </span>
        <button type="button" onClick={() => go(1)} aria-label="Next stage" className={arrowCls}>
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
      <CodeSnippetBlock file={cur.file} line={cur.line} code={cur.code} />
    </div>
  );
}

// Plain-text subtitle for the row-style header — a short "where it lives in this
// app" line (the fuller advisory renders in the body Description block).
const TRACE_SUBTITLE =
  "Untrusted template input reaches lodash _.template() on an unauthenticated render route.";

/* The focal card — a trimmed expanded finding, fed mock heroDemo data. The header
   mirrors a real findings-table row: title + description on the left, the Depscore
   pill + status pill on the right. Below it the real VulnerabilityExpandedCard
   (meta row + description + built-in flow all suppressed) renders just the CVSS /
   EPSS badges, and the reachability is the landing-only Source ⇄ Sink stepper. */
function FlowCard() {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-background-card">
      {/* Row-style header — title + description on the left, Depscore + status pill
          on the right, exactly like a row in the real findings table. */}
      <div className="flex items-center gap-3 border-b border-border bg-background-card-header px-4 py-3">
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium text-foreground">
            {heroTraceVuln.summary}
          </div>
          <div className="mt-0.5 line-clamp-1 text-xs text-foreground-secondary">
            {TRACE_SUBTITLE}
          </div>
        </div>
        <span className="inline-flex shrink-0 items-center justify-center rounded-full border border-orange-500/20 bg-orange-500/10 px-2.5 py-1 text-[13px] font-semibold tabular-nums text-orange-400">
          {heroTraceVuln.depscore}
        </span>
        <span className="inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border border-zinc-700/80 bg-background px-2.5 py-1 text-[12px] font-medium text-foreground">
          <CircleDashed className="h-3 w-3 shrink-0 text-foreground-secondary" />
          New
        </span>
      </div>
      <div className="space-y-4 p-4">
        <VulnerabilityExpandedCard
          vuln={heroTraceVuln}
          detail={heroTraceDetail}
          showMeta={false}
          showReachability={false}
        />
        <TraceStepper />
      </div>
    </div>
  );
}

export default function VerifiedSection() {
  return (
    <section id="verified" className="w-full">
      <div className="mx-auto max-w-[1200px] px-6 py-24 sm:py-28">
        {/* two-column text header — the argument; stats woven into the prose */}
        <Reveal>
          <div className="grid gap-6 lg:grid-cols-[1.1fr_1fr] lg:gap-12">
            <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-[40px]">
              We don&apos;t guess.
              <span className="block text-foreground-secondary">We trace the path.</span>
            </h2>
            <div className="lg:pt-2">
              <p className="text-[15px] leading-relaxed text-foreground sm:text-base">
                Most scanners match a version number and page you. Deptex traces
                the path and proves a CVE can actually run —{" "}
                <span
                  className="font-mono text-[28px] font-semibold leading-none tracking-tight text-accent-text align-[-0.15em]"
                  style={{ textShadow: "0 0 22px rgba(52,208,138,0.45)" }}
                >
                  79.6%
                </span>{" "}
                less noise to triage.
              </p>
            </div>
          </div>
        </Reveal>

        {/* Layered: findings table behind, the reachability path card on top. */}
        <Reveal className="mt-14 lg:mt-16">
          <div className="relative">
            {/* BACK — the findings table (trimmed, non-interactive backdrop),
                dimmed a touch overall and fading more toward bottom-right via a
                top-left-anchored radial mask. */}
            <div
              aria-hidden
              className="pointer-events-none select-none opacity-[0.8]"
              style={{
                maskImage:
                  "radial-gradient(135% 135% at 0% 0%, #000 26%, transparent 100%)",
                WebkitMaskImage:
                  "radial-gradient(135% 135% at 0% 0%, #000 26%, transparent 100%)",
              }}
            >
              <VulnerabilityExpandableTable
                organizationId={HERO_ORG_ID}
                rows={heroBackgroundFindings.slice(0, 5)}
                trackerLinks={heroBackgroundTrackerLinks}
                canManageFindings={false}
                fetchDetail={heroFindingDetail}
                hideFilterBar
              />
            </div>

            {/* FRONT — the path card on top, left, vertically centered (desktop) */}
            <FocalArtifact className="z-10 mt-6 w-full max-w-[500px] lg:absolute lg:left-0 lg:top-1/2 lg:mt-0 lg:-translate-y-1/2">
              <FlowCard />
            </FocalArtifact>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

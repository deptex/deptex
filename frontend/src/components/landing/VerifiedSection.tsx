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
import { Reveal, TierPill } from "./primitives";
import { VulnerabilityOrgSidebarExpandedContent } from "../security/VulnerabilityOrgSidebarExpandedContent";
import VulnerabilityExpandableTable from "../security/VulnerabilityExpandableTable";
import {
  HERO_ORG_ID,
  heroFindings,
  heroFindingDetail,
  heroTraceDetail,
} from "./heroDemo";

/* The focal flow card — the real reachability stepper in a titled frame. */
function FlowCard() {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-background">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <span className="truncate font-mono text-[13px] text-foreground">
          CVE-2021-23337 · lodash
        </span>
        <TierPill tier="confirmed" label="Reachable" />
      </div>
      <div className="p-4">
        <VulnerabilityOrgSidebarExpandedContent detail={heroTraceDetail} />
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
                rows={heroFindings.slice(0, 4)}
                canManageFindings={false}
                fetchDetail={heroFindingDetail}
                hideRefineToggle
                hideTypeFilter
              />
            </div>

            {/* FRONT — the path card on top, left, vertically centered (desktop) */}
            <div className="relative z-10 mt-6 w-full max-w-[520px] lg:absolute lg:left-0 lg:top-1/2 lg:mt-0 lg:-translate-y-1/2">
              <FlowCard />
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

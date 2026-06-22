/**
 * Dependency scanning — dedicated product page (founder 2026-06-22).
 *
 * The first of the four full feature pages (replacing the lightweight tabbed
 * PlatformFeaturesPage view). Follows the competitor anatomy (hero → real-
 * component showcases → capability grid → CTA) but, per the house rule, every
 * visual is a REAL product component fed heroDemo mock data — no screenshots,
 * no facsimiles. This page is the template the other three will copy.
 */
import { Link } from "react-router-dom";
import {
  Gauge,
  Route,
  ShieldAlert,
  ArrowUpCircle,
  EyeOff,
  type LucideIcon,
} from "lucide-react";
import { Button } from "../../ui/button";
import { Reveal, TierPill } from "../primitives";
import { VulnerabilityOrgSidebarExpandedContent } from "../../security/VulnerabilityOrgSidebarExpandedContent";
import VulnerabilityExpandableTable from "../../security/VulnerabilityExpandableTable";
import {
  HERO_ORG_ID,
  heroFindings,
  heroFindingDetail,
  heroTraceDetail,
} from "../heroDemo";

/* Hero product film. PLACEHOLDER for now — reuses the original finding-journey
   video (gitignored local asset; prod falls back to the tracked poster). A
   real dependency-scanning walkthrough recording swaps in later. */
function FindingsVideo() {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-[#0a0a0a] shadow-[0_0_0_1px_#262626]">
      <video
        autoPlay
        muted
        loop
        playsInline
        poster="/images/landing/finding-journey-poster.jpg"
        className="block aspect-[8/5] w-full"
      >
        <source src="/videos/landing/finding-journey.webm" type="video/webm" />
      </video>
    </div>
  );
}

/* The real reachability stepper in a titled frame — CVE-2021-23337 lodash,
   confirmed-reachable, 3 hops. Same trace card as the homepage Verified section. */
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

const CTAs = () => (
  <div className="flex flex-col gap-3 sm:flex-row">
    <Button variant="green" asChild>
      <Link to="/login">Try for free</Link>
    </Button>
    <Button
      variant="outline"
      asChild
      className="!h-8 !rounded-lg !px-3 text-foreground"
    >
      <Link to="/get-demo">Book a demo</Link>
    </Button>
  </div>
);

const CAPABILITIES: { Icon: LucideIcon; title: string; body: string }[] = [
  { Icon: Gauge, title: "Depscore", body: "A risk score per dependency and version — severity, EPSS, CISA KEV, and code-level reachability." },
  { Icon: Route, title: "Reachability analysis", body: "Data-flow and usage slices from the taint engine show which CVEs are actually reachable in your code." },
  { Icon: ShieldAlert, title: "Malicious packages", body: "Malicious-package feeds, behavioral heuristics, and a capability fingerprint for every package you install." },
  { Icon: ArrowUpCircle, title: "Version recommendations", body: "Safe upgrade candidates with OSV verification and release notes, respecting banned versions and org policy." },
  { Icon: EyeOff, title: "Suppress & accept risk", body: "Suppress findings or accept risk with a reason and audit trail. Keeps the graph clean while you track exceptions." },
];

export default function DependencyScanningPage() {
  const vulnRows = heroFindings.filter((r) => r.type === "vulnerability");

  return (
    <div className="bg-background text-foreground">
      {/* HERO — centered copy, big product film below (Linear/Endor pattern) */}
      <section className="relative w-full overflow-hidden pb-24 sm:pb-28">
        <div className="mx-auto max-w-[1200px] px-6 pt-28 text-center sm:pt-36">
          <p className="text-sm font-medium text-accent-text">
            Dependency scanning
          </p>
          <h1 className="mx-auto mt-4 max-w-3xl text-4xl font-semibold leading-[1.05] tracking-[-0.02em] text-foreground sm:text-5xl lg:text-[64px]">
            Know which CVEs can actually run.
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-base leading-relaxed text-foreground sm:text-lg">
            Every dependency CVE, scored by whether it&apos;s reachable in your
            code — not raw CVSS. Plus malicious-package detection across 8
            ecosystems.
          </p>
          <div className="mt-8 flex justify-center">
            <CTAs />
          </div>
        </div>

        {/* big product film — near full width, green glow underneath */}
        <Reveal className="mt-16 sm:mt-20">
          <div className="mx-auto max-w-[1180px] px-6">
            <div className="relative">
              <div
                className="glow-green pointer-events-none absolute -inset-12 opacity-50"
                aria-hidden
              />
              <div className="relative">
                <FindingsVideo />
              </div>
            </div>
          </div>
        </Reveal>
      </section>

      {/* SHOWCASE 1 — the real reachability trace (the differentiator) */}
      <section className="w-full border-t border-white/[0.08]">
        <div className="mx-auto max-w-[1200px] px-6 py-20 sm:py-24">
          <div className="grid gap-12 lg:grid-cols-2 lg:items-center">
            <div>
              <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
                We trace the path, not the version.
              </h2>
              <p className="mt-5 max-w-xl text-base leading-relaxed text-foreground">
                Most scanners stop at &ldquo;this version is affected.&rdquo;
                Deptex follows the call graph from your entry points into the
                vulnerable code, and only marks a CVE reachable when a real path
                exists. Step through it yourself — source to sink.
              </p>
            </div>
            <Reveal>
              <FlowCard />
            </Reveal>
          </div>
        </div>
      </section>

      {/* SHOWCASE 2 — the real findings table, ranked by reachability (table left) */}
      <section className="w-full border-t border-white/[0.08]">
        <div className="mx-auto max-w-[1200px] px-6 py-20 sm:py-24">
          <div className="grid gap-12 lg:grid-cols-2 lg:items-center">
            <div className="lg:order-2">
              <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
                Every finding, scored by your code.
              </h2>
              <p className="mt-5 max-w-xl text-base leading-relaxed text-foreground">
                Confirmed, data-flow, function, or module — each CVE is ranked by
                how reachable it is and weighted by your project, not a generic
                CVSS number. The top of the list is the work that matters.
              </p>
            </div>
            <Reveal className="lg:order-1">
              <VulnerabilityExpandableTable
                organizationId={HERO_ORG_ID}
                rows={vulnRows}
                canManageFindings={false}
                fetchDetail={heroFindingDetail}
                hideRefineToggle
                hideTypeFilter
              />
            </Reveal>
          </div>
        </div>
      </section>

      {/* CAPABILITIES grid */}
      <section className="w-full border-t border-white/[0.08]">
        <div className="mx-auto max-w-[1200px] px-6 py-20 sm:py-24">
          <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
            Everything in dependency scanning.
          </h2>
          <div className="mt-12 grid grid-cols-1 gap-x-10 gap-y-12 sm:grid-cols-2 lg:grid-cols-3">
            {CAPABILITIES.map(({ Icon, title, body }) => (
              <div key={title} className="flex flex-col">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.03]">
                  <Icon className="h-[18px] w-[18px] text-foreground-secondary" aria-hidden />
                </div>
                <h3 className="mt-4 text-[15px] font-medium text-foreground">{title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-foreground-secondary">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FINAL CTA */}
      <section className="w-full border-t border-white/[0.08]">
        <div className="mx-auto flex max-w-[1200px] flex-col items-center px-6 py-24 text-center md:py-28">
          <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-4xl">
            Scan your dependencies for what&apos;s reachable.
          </h2>
          <p className="mt-5 text-base leading-relaxed text-foreground">
            Connect a repo and read the first trace yourself.
          </p>
          <div className="mt-8">
            <CTAs />
          </div>
        </div>
      </section>
    </div>
  );
}

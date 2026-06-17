/**
 * HeroShowcase — the hero's big visual (founder 2026-06-16, Aikido reference).
 *
 * Replaces the product film with a TABBED, INTERACTIVE product showcase: an
 * app-window frame whose contents switch between Overview / Findings / Aegis —
 * the real org-sidebar surfaces (OrgSidebar.tsx) — each a mini, real, scrollable
 * slice of the actual product (not a recording). This shows off the key surfaces
 * as live DOM, kills the dummy-video problem, and needs no asset pipeline.
 * Visuals/data mirror the real app (org graph + multiplayer cursors, the
 * findings table + reachability verdicts, the Aegis chat) on the real
 * dogfood-express scan (lodash CVE-2021-23337 reachable; 141 → 28 after triage).
 */
import { useState } from "react";
import {
  ArrowUp,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ClipboardList,
  Lock,
  MoreVertical,
  Plus,
  RotateCw,
} from "lucide-react";
import HeroOverviewGraph from "./HeroOverviewGraph";
import HeroFindingsTable from "./HeroFindingsTable";

// Findings leads — it proves the headline ("cut the noise") at first glance.
// (Deviates from the real sidebar order Overview/Findings/Aegis on purpose.)
const TABS: { id: string; label: string }[] = [
  { id: "findings", label: "Findings" },
  { id: "overview", label: "Overview" },
  { id: "aegis", label: "Aegis" },
];

/* ---------------- Aegis: the chat (scrollable) ---------------- */
function AegisView() {
  return (
    <div className="flex h-full flex-col">
      <div className="flex-1 space-y-4 overflow-y-auto px-4 py-4 sm:px-5">
        {/* user */}
        <div className="flex justify-end">
          <div className="max-w-[80%] rounded-2xl border border-border bg-background-card px-4 py-2.5 text-sm leading-relaxed text-foreground/90">
            lodash in storefront-api is flagged critical — is it actually exploitable here?
          </div>
        </div>

        {/* aegis */}
        <div className="text-sm leading-relaxed text-foreground/90">
          Yes —{" "}
          <span className="font-mono text-[13px] text-accent-text">CVE-2021-23337</span>{" "}
          is reachable. Request body flows into{" "}
          <code className="rounded bg-background-subtle px-1 py-0.5 font-mono text-[12px] text-foreground">
            _.template()
          </code>{" "}
          in{" "}
          <code className="rounded bg-background-subtle px-1 py-0.5 font-mono text-[12px] text-foreground">
            routes/render.js
          </code>
          , so the injection path is live. A patch bump to 4.17.21 fixes it — your
          usage doesn&apos;t touch the changed API.
        </div>

        {/* plan pill */}
        <div className="flex w-full items-center gap-3 rounded-md border border-border bg-background-subtle/30 px-4 py-3">
          <ClipboardList className="h-4 w-4 shrink-0 text-foreground-secondary" />
          <span className="flex-1 truncate text-sm text-foreground">
            Bump lodash to 4.17.21 and open a draft PR
          </span>
          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-foreground-secondary" />
        </div>

        {/* user */}
        <div className="flex justify-end">
          <div className="max-w-[80%] rounded-2xl border border-border bg-background-card px-4 py-2.5 text-sm leading-relaxed text-foreground/90">
            go ahead
          </div>
        </div>

        {/* aegis */}
        <div className="text-sm leading-relaxed text-foreground/90">
          Done — opened draft PR{" "}
          <span className="font-mono text-[13px] text-accent-text">#1287</span>. Your
          test suite passed (142 tests) and the lodash path is no longer reachable.
          Review and merge when you&apos;re ready.
        </div>
      </div>

      {/* composer */}
      <div className="border-t border-[#1c1c1c] px-3 py-3">
        <div className="rounded-2xl border border-border bg-background-card">
          <div className="px-4 pt-3 pb-1 text-[0.9375rem] leading-relaxed text-foreground/50">
            Ask anything
          </div>
          <div className="flex items-center justify-between px-2 pb-2">
            <span className="inline-flex h-8 items-center gap-2 rounded-md px-2 text-sm text-foreground/70">
              <span className="h-3.5 w-3.5 rounded-full bg-gradient-to-br from-[#2dd4bf] to-[#1f7a55]" />
              Claude Opus 4.8
              <ChevronDown className="h-3 w-3 text-foreground/50" />
            </span>
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-foreground text-background ring-1 ring-inset ring-foreground/10">
              <ArrowUp className="h-4 w-4" />
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function HeroShowcase() {
  // Default to Findings — it proves the headline ("cut the noise") at first
  // glance: CVEs scored by reachability, noise auto-ignored. Overview leads
  // with an org map that reads less obviously as "security".
  const [active, setActive] = useState("findings");

  return (
    <div className="relative">
      <div
        className="glow-green pointer-events-none absolute -inset-x-8 -top-8 bottom-0 opacity-25"
        aria-hidden
      />

      {/* app window — styled as a real (dark) Chrome browser: mac traffic
          lights + Chrome tabs in the title bar, then a toolbar with the address
          bar (founder 2026-06-16). Overview / Findings / Aegis ARE the browser
          tabs; the active tab merges into the toolbar exactly like Chrome. */}
      <div className="relative overflow-hidden rounded-xl border border-[#262626] bg-[#0a0a0a] shadow-[0_30px_80px_rgba(0,0,0,0.6)]">
        {/* title bar — traffic lights + Chrome tabs */}
        <div className="flex h-11 items-end gap-1.5 bg-[#0a0a0a] px-3">
          <div className="flex shrink-0 items-center gap-2 self-center pr-3">
            <span className="h-3 w-3 rounded-full bg-[#ff5f57]" />
            <span className="h-3 w-3 rounded-full bg-[#febc2e]" />
            <span className="h-3 w-3 rounded-full bg-[#28c840]" />
          </div>
          {TABS.map((t) => {
            const isActive = t.id === active;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setActive(t.id)}
                aria-pressed={isActive}
                className={`flex items-center gap-2 pl-2.5 pr-3.5 pt-1.5 text-[13px] font-medium transition-colors ${
                  isActive
                    ? "chrome-tab-active rounded-t-lg bg-[#141414] pb-3 text-foreground"
                    : "mb-1.5 rounded-lg pb-1.5 text-foreground-secondary hover:bg-white/[0.05] hover:text-foreground"
                }`}
              >
                <img
                  src="/images/website_icon.png"
                  alt=""
                  aria-hidden
                  className="h-4 w-4 shrink-0 rounded-full object-contain"
                />
                {t.label}
              </button>
            );
          })}
          <span className="flex h-6 w-6 items-center justify-center self-center rounded-full text-foreground-secondary/60 hover:bg-white/[0.04]">
            <Plus className="h-4 w-4" aria-hidden />
          </span>
        </div>

        {/* toolbar — nav buttons + address bar (active tab merges into this) */}
        <div className="flex items-center gap-2 bg-[#141414] px-3 py-2">
          <div className="flex items-center gap-1 text-foreground-secondary/50">
            <ChevronLeft className="h-4 w-4" aria-hidden />
            <ChevronRight className="h-4 w-4" aria-hidden />
            <RotateCw className="ml-0.5 h-3.5 w-3.5" aria-hidden />
          </div>
          <div className="ml-1 flex h-7 flex-1 items-center gap-2 rounded-full border border-white/[0.06] bg-[#0a0a0a] px-3">
            <Lock className="h-3 w-3 text-foreground-secondary" aria-hidden />
            <span className="font-mono text-[12px] text-foreground">deptex.dev</span>
          </div>
          <MoreVertical
            className="h-4 w-4 shrink-0 text-foreground-secondary/50"
            aria-hidden
          />
        </div>

        {/* content — fixed height so tab switches don't jump; views scroll */}
        <div key={active} className="tab-fade h-[560px] border-t border-[#1c1c1c]">
          {active === "overview" && <HeroOverviewGraph />}
          {active === "findings" && <HeroFindingsTable />}
          {active === "aegis" && <AegisView />}
        </div>
      </div>
    </div>
  );
}

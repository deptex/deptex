/**
 * §3.9 Aegis — proof becomes a pull request.
 *
 * Reworked 2026-06-16 (founder, Linear "self-driving" reference): two-column
 * text header, then a LAYERED composition — a floating Aegis chat card in the
 * foreground over a draft-PR card behind it (Linear's Slack-thread-over-board
 * pattern), vertically centered against each other. No video: the film above
 * carries the motion of the fix flow; this is the still you can READ.
 *
 * Fidelity note: the chat card mirrors the REAL Aegis chat surface 1:1 —
 * user turn = rounded-2xl bg-background-card bubble (right); assistant turn =
 * plain text, no bubble, no avatar (src/components/aegis/MessageBubble.tsx);
 * the plan renders as the neutral ClipboardList pill from PlanCard.tsx;
 * composer = ChatInput's model-picker + circular bg-foreground send button.
 * Same semantic tokens as the app so it reads as the product, not a facsimile.
 *
 * The right card is a GitHub-PR facsimile (its own GitHub-dark palette) — a
 * real screenshot swaps in once a real Aegis fix run opens a PR (today every
 * project_security_fixes.pr_url is NULL, so there is nothing real to capture).
 *
 * Do NOT claim: autopilot, sprints, PR review, Slack parity, "50+ tools".
 */
import {
  ArrowUp,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardList,
  FileCode2,
  GitPullRequest,
} from "lucide-react";
import { Reveal } from "./primitives";

/* ---------------- foreground: the Aegis conversation ----------------
   Mirrors src/components/aegis/{MessageBubble,ChatInput,PlanCard}.tsx. */
function AegisChatCard() {
  return (
    <div className="flex flex-col overflow-hidden rounded-xl border border-border bg-background shadow-[0_28px_80px_rgba(0,0,0,0.78)]">
      {/* transcript */}
      <div className="flex flex-col py-3">
        {/* user turn — right-aligned bubble */}
        <div className="flex flex-col items-end px-4 py-1">
          <div className="max-w-[80%] rounded-2xl border border-border bg-background-card px-4 py-2.5 text-sm leading-relaxed text-foreground/90">
            lodash is flagged critical — is it actually exploitable here?
          </div>
        </div>

        {/* assistant turn — plain text, no bubble, no avatar */}
        <div className="px-4 py-2 text-sm leading-relaxed text-foreground/90">
          Yes —{" "}
          <span className="font-mono text-[13px] text-accent-text">
            CVE-2021-23337
          </span>{" "}
          is reachable. Request body flows into{" "}
          <code className="rounded bg-background-subtle px-1 py-0.5 font-mono text-[12px] text-foreground">
            _.template()
          </code>{" "}
          in{" "}
          <code className="rounded bg-background-subtle px-1 py-0.5 font-mono text-[12px] text-foreground">
            routes/render.js
          </code>
          , so the injection path is live. A patch bump to 4.17.21 fixes it —
          your usage doesn&apos;t touch the changed API.
        </div>

        {/* plan pill — the real PlanCard chrome */}
        <div className="px-4">
          <div className="my-2 flex w-full items-center gap-3 rounded-md border border-border bg-background-subtle/30 px-4 py-3">
            <ClipboardList className="h-4 w-4 shrink-0 text-foreground-secondary" />
            <span className="flex-1 truncate text-sm text-foreground">
              Bump lodash to 4.17.21 and open a draft PR
            </span>
            <ChevronRight className="h-3.5 w-3.5 shrink-0 text-foreground-secondary" />
          </div>
        </div>
      </div>

      {/* composer — ChatInput's chrome */}
      <div className="px-3 pb-3">
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

/* ---------------- background: the draft PR it opened ----------------
   GitHub-dark facsimile; swaps for a real screenshot when one exists. */
function DraftPrCard() {
  return (
    <div className="overflow-hidden rounded-xl border border-[#30363d] bg-[#0d1117] text-[#c9d1d9] shadow-2xl">
      {/* title block */}
      <div className="border-b border-[#21262d] px-5 py-4">
        <h4 className="text-[17px] font-semibold leading-snug text-[#e6edf3]">
          Fix command injection in lodash (CVE-2021-23337){" "}
          <span className="font-normal text-[#8b949e]">#1287</span>
        </h4>
        <div className="mt-2.5 flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full bg-[#6e7681] px-2.5 py-1 text-[12px] font-medium text-white">
            <GitPullRequest className="h-3.5 w-3.5" /> Draft
          </span>
          <span className="text-[12px] text-[#8b949e]">
            <span className="font-medium text-[#c9d1d9]">aegis</span> wants to
            merge 1 commit into{" "}
            <code className="rounded bg-[#21262d] px-1 py-0.5 font-mono text-[11px] text-[#c9d1d9]">
              main
            </code>{" "}
            from{" "}
            <code className="rounded bg-[#21262d] px-1 py-0.5 font-mono text-[11px] text-[#c9d1d9]">
              aegis/fix-lodash-cve-2021-23337
            </code>
          </span>
        </div>
      </div>

      <div className="px-5 py-4">
        {/* diff */}
        <div className="overflow-hidden rounded-md border border-[#30363d] font-mono text-[12px] leading-relaxed">
          <div className="flex items-center gap-2 border-b border-[#30363d] bg-[#161b22] px-3 py-2 text-[#8b949e]">
            <FileCode2 className="h-3.5 w-3.5" /> package.json
          </div>
          <div className="bg-[#341a1d] px-3 py-0.5 text-[#ffa198]">
            <span className="select-none text-[#86393b]">- </span>
            &quot;lodash&quot;: &quot;^4.17.20&quot;,
          </div>
          <div className="bg-[#12261e] px-3 py-0.5 text-[#7ee2b8]">
            <span className="select-none text-[#3a7a55]">+ </span>
            &quot;lodash&quot;: &quot;^4.17.21&quot;,
          </div>
        </div>

        {/* checks box */}
        <div className="mt-4 overflow-hidden rounded-md border border-[#30363d]">
          <div className="flex items-center gap-2 border-b border-[#30363d] bg-[#161b22] px-3 py-2.5">
            <CheckCircle2 className="h-4 w-4 text-[#3fb950]" />
            <span className="text-[13px] font-semibold text-[#3fb950]">
              All checks have passed
            </span>
            <span className="text-[12px] text-[#8b949e]">2 successful checks</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-2 text-[12px] text-[#8b949e]">
            <Check className="h-3.5 w-3.5 text-[#3fb950]" /> CI / tests — 142
            passed
          </div>
          <div className="flex items-center gap-2 border-t border-[#21262d] px-3 py-2 text-[12px] text-[#8b949e]">
            <Check className="h-3.5 w-3.5 text-[#3fb950]" /> Deptex / reachability
            re-verified
          </div>
        </div>
      </div>
    </div>
  );
}

export default function AegisSection() {
  return (
    <section id="aegis" className="w-full border-y border-white/[0.08]">
      <div className="mx-auto max-w-[1200px] px-6 py-28">
        {/* two-column text header (Linear pattern) */}
        <Reveal>
          <div className="grid gap-6 lg:grid-cols-[1.1fr_1fr] lg:gap-12">
            <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-[40px]">
              Aegis doesn&apos;t stop at the finding.
              <span className="block text-foreground-secondary">It ships the fix.</span>
            </h2>
            <div className="lg:pt-2">
              <p className="text-[15px] leading-relaxed text-foreground sm:text-base">
                Ask Aegis about any finding. It investigates in your repo&apos;s
                context, plans the fix, and — once you approve — a sandboxed
                worker writes the patch and runs your own test suite. Then it
                opens a PR; nothing merges without you.
              </p>
            </div>
          </div>
        </Reveal>

        {/* layered composition: chat (front) over draft PR (back), centered */}
        <Reveal className="relative mt-14 lg:mt-16">
          <div
            className="glow-green pointer-events-none absolute -inset-12 opacity-30"
            aria-hidden
          />
          <div className="relative flex flex-col lg:flex-row lg:items-center">
            {/* front: chat, left, floating above */}
            <div className="relative z-10 lg:w-[44%]">
              <AegisChatCard />
            </div>
            {/* back: draft PR, right, slid under the chat */}
            <div className="relative z-0 mt-6 lg:mt-0 lg:-ml-[6%] lg:w-[62%]">
              <DraftPrCard />
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

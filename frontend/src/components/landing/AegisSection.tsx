/**
 * §3.9 Aegis — proof becomes a pull request (real-component rebuild 2026-06-18).
 *
 * Mirrors the Verified section's final shape: a real, app-styled card floating
 * over a faded, full-width backdrop.
 *   • FRONT: the Aegis chat — the REAL chat components (ChatInput + ModelPicker
 *     → the actual Claude Opus 4.8 / Anthropic logo, ToolCallGroup) fed mock
 *     data, the same way the hero's Aegis tab is built. Taller than before, with
 *     a two-turn transcript (investigate → fix) and a typeable composer that
 *     funnels to a sign-up gate.
 *   • BACK: the draft PR it opens — recoloured to OUR app palette (not GitHub
 *     dark), rendered full-width and dimmed with the SAME top-left radial fade
 *     as the Verified findings backdrop. Non-interactive texture.
 *
 * Real screenshot swaps in once a real Aegis fix run opens a PR (today every
 * project_security_fixes.pr_url is NULL). Do NOT claim: autopilot, sprints, PR
 * review, Slack parity, "50+ tools".
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Check, CheckCircle2, FileCode2, GitPullRequest } from "lucide-react";
import { Link } from "react-router-dom";
import { Reveal } from "./primitives";
import { Button } from "../ui/button";
import { ChatInput } from "../aegis/ChatInput";
import { ToolCallGroup, type ToolCallEntry } from "../aegis/ToolCallCard";
import type { AIModelMetadata } from "../../lib/api";

// Same top-left-anchored radial fade as the Verified findings backdrop.
const FADE =
  "radial-gradient(135% 135% at 0% 0%, #000 26%, transparent 100%)";

// Mock model catalog (real AIModelMetadata shape) — feeds the real ModelPicker
// inside ChatInput (Claude Opus 4.8 + the real Anthropic logo).
const MODELS: AIModelMetadata[] = [
  { id: "claude-opus-4-8", provider: "anthropic", label: "Claude Opus 4.8", description: "Anthropic's most capable model — best for security reasoning.", contextWindow: 1_000_000, inputPricePer1M: 5, outputPricePer1M: 25, releasedAt: "2026-01-01" },
  { id: "gpt-5.1", provider: "openai", label: "GPT-5.1", description: "OpenAI's flagship reasoning model.", contextWindow: 400_000, inputPricePer1M: 4, outputPricePer1M: 16, releasedAt: "2025-11-01" },
  { id: "gemini-2.5-pro", provider: "google", label: "Gemini 2.5 Pro", description: "Google's long-context reasoning model.", contextWindow: 1_000_000, inputPricePer1M: 2, outputPricePer1M: 10, releasedAt: "2025-09-01" },
];

const TOOLS_INVESTIGATE: ToolCallEntry[] = [
  { toolName: "list_project_findings", state: "done" },
  { toolName: "get_finding_detail", state: "done" },
  { toolName: "analyze_reachability", state: "done" },
];
const TOOLS_FIX: ToolCallEntry[] = [
  { toolName: "request_fix", state: "done" },
  { toolName: "write_patch", state: "done" },
  { toolName: "run_tests", state: "done" },
  { toolName: "open_pull_request", state: "done" },
];

// User bubble — copied verbatim from aegis/MessageBubble.
function UserBubble({ children }: { children: ReactNode }) {
  return (
    <div className="px-4 py-1">
      <div className="mx-auto max-w-3xl flex flex-col items-end">
        <div className="max-w-[80%] rounded-2xl bg-background-card border border-border px-4 py-2.5 text-sm text-foreground/90 whitespace-pre-wrap leading-relaxed">
          {children}
        </div>
      </div>
    </div>
  );
}

// Assistant block — copied verbatim from aegis/MessageBubble (space-y-2 stack).
function AssistantBlock({ children }: { children: ReactNode }) {
  return (
    <div className="px-4 py-2">
      <div className="mx-auto max-w-3xl">
        <div className="space-y-2">{children}</div>
      </div>
    </div>
  );
}

function Mono({ children }: { children: ReactNode }) {
  return (
    <code className="rounded bg-background-subtle px-1 py-0.5 font-mono text-[12px] text-foreground">
      {children}
    </code>
  );
}

function GateMessage() {
  return (
    <div className="space-y-3 text-sm leading-relaxed text-foreground/90">
      <p>
        Aegis runs for real once it&apos;s connected to your code. Create a free
        account to point it at your own repos and let it open the fix PR.
      </p>
      <Button variant="green" asChild className="!h-8 !rounded-lg !px-3">
        <Link to="/login">Try Aegis for free</Link>
      </Button>
    </div>
  );
}

/* ---------------- front: the Aegis chat (real components) ---------------- */
function AegisChatCard() {
  const [modelId, setModelId] = useState(MODELS[0].id);
  const [extra, setExtra] = useState<{ id: number; role: "user" | "aegis"; text?: string }[]>([]);
  const idRef = useRef(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const timers = useRef<number[]>([]);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [extra]);
  useEffect(() => () => timers.current.forEach((t) => clearTimeout(t)), []);

  const sendGate = (userText?: string) => {
    if (userText !== undefined) {
      setExtra((prev) => [...prev, { id: ++idRef.current, role: "user", text: userText }]);
    }
    const t = window.setTimeout(
      () => setExtra((prev) => [...prev, { id: ++idRef.current, role: "aegis" }]),
      480,
    );
    timers.current.push(t);
  };

  return (
    <div className="flex h-[560px] flex-col overflow-hidden rounded-xl border border-border bg-background">
      <div ref={scrollRef} className="flex-1 overflow-y-auto custom-scrollbar py-4">
        <UserBubble>lodash is flagged critical — is it actually exploitable here?</UserBubble>

        <AssistantBlock>
          <div className="text-sm leading-relaxed text-foreground/90">
            Let me trace it in <span className="font-medium text-foreground">storefront-api</span>.
          </div>
          <ToolCallGroup tools={TOOLS_INVESTIGATE} />
          <div className="text-sm leading-relaxed text-foreground/90">
            Yes —{" "}
            <span className="font-mono text-[13px] text-accent-text">CVE-2021-23337</span>{" "}
            is reachable. Request body flows into <Mono>_.template()</Mono> in{" "}
            <Mono>routes/render.js</Mono>, so the injection path is live. A patch
            bump to 4.17.21 fixes it — your usage doesn&apos;t touch the changed API.
          </div>
        </AssistantBlock>

        <UserBubble>Great — open a PR for it.</UserBubble>

        <AssistantBlock>
          <div className="text-sm leading-relaxed text-foreground/90">On it.</div>
          <ToolCallGroup tools={TOOLS_FIX} />
          <div className="text-sm leading-relaxed text-foreground/90">
            Patched <Mono>lodash</Mono> → 4.17.21, ran your suite (142 passing),
            and opened draft PR <span className="font-mono text-foreground">#1287</span>.
            Reachability re-verified — nothing merges without your review.
          </div>
        </AssistantBlock>

        {extra.map((m) =>
          m.role === "user" ? (
            <UserBubble key={m.id}>{m.text}</UserBubble>
          ) : (
            <AssistantBlock key={m.id}>
              <GateMessage />
            </AssistantBlock>
          ),
        )}
      </div>

      {/* composer — the REAL ChatInput (textarea + ModelPicker pill + send) */}
      <div className="px-3 pb-3">
        <div className="rounded-2xl border border-border bg-background-card">
          <ChatInput
            onSubmit={(text) => sendGate(text)}
            placeholder="Ask Aegis anything"
            models={MODELS}
            selectedModelId={modelId}
            onSelectModel={setModelId}
          />
        </div>
      </div>
    </div>
  );
}

/* ---------------- back: the draft PR it opened (app palette) ---------------- */
function DraftPrCard() {
  return (
    <div className="w-full overflow-hidden rounded-xl border border-border bg-[#0a0a0a] text-foreground">
      {/* title block */}
      <div className="border-b border-border px-5 py-4">
        <h4 className="text-[17px] font-semibold leading-snug text-foreground">
          Fix command injection in lodash (CVE-2021-23337){" "}
          <span className="font-normal text-foreground-secondary">#1287</span>
        </h4>
        <div className="mt-2.5 flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-background-subtle px-2.5 py-1 text-[12px] font-medium text-foreground-secondary">
            <GitPullRequest className="h-3.5 w-3.5" /> Draft
          </span>
          <span className="text-[12px] text-foreground-secondary">
            <span className="font-medium text-foreground">aegis</span> wants to
            merge 1 commit into <Mono>main</Mono> from{" "}
            <Mono>aegis/fix-lodash-cve-2021-23337</Mono>
          </span>
        </div>
      </div>

      <div className="px-5 py-4">
        {/* diff */}
        <div className="overflow-hidden rounded-md border border-border font-mono text-[12px] leading-relaxed">
          <div className="flex items-center gap-2 border-b border-border bg-background-subtle px-3 py-2 text-foreground-secondary">
            <FileCode2 className="h-3.5 w-3.5" /> package.json
          </div>
          <div className="bg-red-500/10 px-3 py-0.5 text-red-300">
            <span className="select-none text-red-500/50">- </span>
            &quot;lodash&quot;: &quot;^4.17.20&quot;,
          </div>
          <div className="bg-accent-text/10 px-3 py-0.5 text-accent-text">
            <span className="select-none text-accent-text/60">+ </span>
            &quot;lodash&quot;: &quot;^4.17.21&quot;,
          </div>
        </div>

        {/* checks box */}
        <div className="mt-4 overflow-hidden rounded-md border border-border">
          <div className="flex items-center gap-2 border-b border-border bg-background-subtle px-3 py-2.5">
            <CheckCircle2 className="h-4 w-4 text-accent-text" />
            <span className="text-[13px] font-semibold text-accent-text">
              All checks have passed
            </span>
            <span className="text-[12px] text-foreground-secondary">2 successful checks</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-2 text-[12px] text-foreground-secondary">
            <Check className="h-3.5 w-3.5 text-accent-text" /> CI / tests — 142 passed
          </div>
          <div className="flex items-center gap-2 border-t border-border px-3 py-2 text-[12px] text-foreground-secondary">
            <Check className="h-3.5 w-3.5 text-accent-text" /> Deptex / reachability re-verified
          </div>
        </div>
      </div>
    </div>
  );
}

export default function AegisSection() {
  return (
    <section id="aegis" className="w-full border-t border-white/[0.08]">
      <div className="mx-auto max-w-[1200px] px-6 py-24 sm:py-28">
        {/* two-column text header (Linear pattern) */}
        <Reveal>
          <div className="grid gap-6 lg:grid-cols-[1.1fr_1fr] lg:gap-12">
            <h2 className="text-3xl font-semibold leading-[1.1] tracking-[-0.02em] text-foreground md:text-[40px]">
              Aegis doesn&apos;t stop at the finding.
              <span className="block text-foreground-secondary">It ships the fix.</span>
            </h2>
            <div className="lg:pt-2">
              <p className="text-[15px] leading-relaxed text-foreground sm:text-base">
                Ask Aegis about any finding. It investigates your repo, plans the
                fix, then writes the patch, runs your tests, and opens a PR —{" "}
                <span
                  className="font-mono text-[28px] font-semibold leading-none tracking-tight text-accent-text align-[-0.15em]"
                  style={{ textShadow: "0 0 22px rgba(52,208,138,0.45)" }}
                >
                  5×
                </span>{" "}
                faster fixes, and nothing merges without you.
              </p>
            </div>
          </div>
        </Reveal>

        {/* Layered: the real Aegis chat in front, the draft PR faded behind. */}
        <Reveal className="mt-14 lg:mt-16">
          <div className="relative">
            {/* BACK — draft PR, full width, app palette, dimmed + faded,
                vertically centered against the chat (desktop) */}
            <div
              aria-hidden
              className="pointer-events-none absolute inset-0 z-0 hidden items-center opacity-[0.8] lg:flex"
              style={{ maskImage: FADE, WebkitMaskImage: FADE }}
            >
              <DraftPrCard />
            </div>

            {/* FRONT — the chat card (defines height) */}
            <div className="relative z-10 w-full max-w-[520px]">
              <AegisChatCard />
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
